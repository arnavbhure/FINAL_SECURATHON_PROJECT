import crypto from 'node:crypto';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import type { Pool } from 'pg';
import type { ApiEnvironment } from '../env.js';
import { UserRepository, type UserRecord, type UserRole, type UserStatus } from '../repositories/user.repository.js';
import { SessionRepository } from '../repositories/session.repository.js';
import { AuthAuditRepository, type AuthAuditEventRecord } from '../repositories/auth-audit.repository.js';
import { getApiJwtKeyPair } from '../crypto/jwt-keys.js';

export interface AuthTokenPayload {
  sub: string;
  sid?: string | undefined;
  email: string;
  role: UserRole;
  fullName: string;
  sites: string[];
}

export interface AuthenticatedUserView {
  id: string;
  email: string;
  fullName: string;
  role: UserRole;
  sites: string[];
}

export interface LoginResult {
  accessToken: string;
  refreshToken: string;
  csrfToken: string;
  user: AuthenticatedUserView;
}

export interface RefreshResult {
  accessToken: string;
  refreshToken: string;
  csrfToken: string;
  user: AuthenticatedUserView;
}

interface RateLimitEntry {
  attempts: number;
  lockedUntil: number;
}

export class AuthService {
  private readonly userRepo: UserRepository;
  private readonly sessionRepo: SessionRepository;
  private readonly auditRepo: AuthAuditRepository;
  private readonly rateLimits = new Map<string, RateLimitEntry>();

  constructor(
    private readonly pool: Pool,
    private readonly env: ApiEnvironment
  ) {
    this.userRepo = new UserRepository(pool);
    this.sessionRepo = new SessionRepository(pool);
    this.auditRepo = new AuthAuditRepository(pool);
  }

  getUserRepository(): UserRepository {
    return this.userRepo;
  }

  getSessionRepository(): SessionRepository {
    return this.sessionRepo;
  }

  getAuditRepository(): AuthAuditRepository {
    return this.auditRepo;
  }

  // --- Password Utilities ---

  async hashPassword(password: string): Promise<string> {
    return bcrypt.hash(password, 10);
  }

  async verifyPassword(password: string, hash: string): Promise<boolean> {
    return bcrypt.compare(password, hash);
  }

  // --- Token Utilities ---

  hashToken(token: string): string {
    return crypto.createHash('sha256').update(token, 'utf-8').digest('hex');
  }

  generateRefreshToken(): string {
    return crypto.randomBytes(40).toString('hex');
  }

  generateCsrfToken(): string {
    return crypto.randomBytes(24).toString('hex');
  }

  generateAccessToken(user: UserRecord, siteCodes: string[], sessionId?: string): string {
    const payload: AuthTokenPayload = {
      sub: user.id,
      sid: sessionId,
      email: user.email,
      role: user.role,
      fullName: user.fullName,
      sites: siteCodes,
    };

    const keys = getApiJwtKeyPair();
    return jwt.sign(payload, keys.privateKeyPem, {
      expiresIn: `${this.env.JWT_ACCESS_TTL_MINUTES}m`,
      algorithm: 'ES256',
      issuer: 'envirotrust-api',
      audience: 'envirotrust-web',
    });
  }

  verifyAccessToken(token: string): AuthTokenPayload {
    const keys = getApiJwtKeyPair();
    return jwt.verify(token, keys.publicKeyPem, {
      algorithms: ['ES256'],
      issuer: 'envirotrust-api',
      audience: 'envirotrust-web',
    }) as AuthTokenPayload;
  }

  /**
   * Revalidates an active session and fetches current user status/permissions from DB.
   * If the refresh session was revoked (via logout, token reuse, admin disabling, or role change),
   * this immediately rejects the access token even if cryptographically unexpired.
   */
  async validateSession(sid: string, userId: string): Promise<AuthTokenPayload> {
    const session = await this.sessionRepo.findById(sid);
    if (!session || session.userId !== userId || session.revokedAt !== null) {
      const err = new Error('Session has been revoked or is invalid.');
      (err as any).statusCode = 401;
      (err as any).code = 'SESSION_REVOKED';
      throw err;
    }

    if (new Date() > session.expiresAt) {
      const err = new Error('Session has expired.');
      (err as any).statusCode = 401;
      (err as any).code = 'SESSION_EXPIRED';
      throw err;
    }

    const user = await this.userRepo.findById(userId);
    if (!user) {
      const err = new Error('User not found.');
      (err as any).statusCode = 401;
      (err as any).code = 'USER_NOT_FOUND';
      throw err;
    }

    if (user.status === 'DISABLED') {
      const err = new Error('Account has been deactivated. Please contact an administrator.');
      (err as any).statusCode = 403;
      (err as any).code = 'ACCOUNT_DISABLED';
      throw err;
    }

    const sites = await this.userRepo.getUserSiteCodes(user.id);
    return {
      sub: user.id,
      sid: session.id,
      email: user.email,
      role: user.role,
      fullName: user.fullName,
      sites,
    };
  }

  // --- Rate Limiting for Login ---

  private checkRateLimit(key: string): boolean {
    const entry = this.rateLimits.get(key);
    if (!entry) return true;
    if (Date.now() < entry.lockedUntil) return false;
    if (Date.now() >= entry.lockedUntil && entry.attempts >= 5) {
      this.rateLimits.delete(key);
    }
    return true;
  }

  private recordFailedAttempt(key: string): void {
    const entry = this.rateLimits.get(key) || { attempts: 0, lockedUntil: 0 };
    entry.attempts += 1;
    if (entry.attempts >= 5) {
      entry.lockedUntil = Date.now() + 15 * 60 * 1000; // 15-minute lockout
    }
    this.rateLimits.set(key, entry);
  }

  private clearFailedAttempts(key: string): void {
    this.rateLimits.delete(key);
  }

  // --- Authentication Workflows ---

  /**
   * Logs in a user with email and password.
   * Generic error message prevents account enumeration.
   */
  async login(
    email: string,
    password: string,
    context: { ip?: string | undefined; userAgent?: string | undefined } = {}
  ): Promise<LoginResult> {
    const normalizedEmail = (email || '').trim().toLowerCase();
    const rateLimitKey = `${normalizedEmail}:${context.ip || 'local'}`;

    if (!this.checkRateLimit(rateLimitKey)) {
      await this.auditRepo.recordAuthEvent({
        action: 'LOGIN_RATE_LIMITED',
        actorEmail: normalizedEmail,
        ipAddress: context.ip,
        userAgent: context.userAgent,
        details: { reason: 'TOO_MANY_ATTEMPTS' },
      });
      const err = new Error('Too many failed login attempts. Please try again in 15 minutes.');
      (err as any).statusCode = 429;
      (err as any).code = 'RATE_LIMITED';
      throw err;
    }

    const user = await this.userRepo.findByEmail(normalizedEmail);
    if (!user) {
      this.recordFailedAttempt(rateLimitKey);
      await this.auditRepo.recordAuthEvent({
        action: 'LOGIN_FAILED',
        actorEmail: normalizedEmail,
        ipAddress: context.ip,
        userAgent: context.userAgent,
        details: { reason: 'UNKNOWN_USER' },
      });
      const err = new Error('Invalid email or password.');
      (err as any).statusCode = 401;
      (err as any).code = 'INVALID_CREDENTIALS';
      throw err;
    }

    if (user.status === 'DISABLED') {
      await this.auditRepo.recordAuthEvent({
        userId: user.id,
        action: 'LOGIN_FAILED',
        actorEmail: normalizedEmail,
        ipAddress: context.ip,
        userAgent: context.userAgent,
        details: { reason: 'ACCOUNT_DISABLED' },
      });
      const err = new Error('Account has been deactivated. Please contact an administrator.');
      (err as any).statusCode = 403;
      (err as any).code = 'ACCOUNT_DISABLED';
      throw err;
    }

    const passwordMatch = await this.verifyPassword(password, user.passwordHash);
    if (!passwordMatch) {
      this.recordFailedAttempt(rateLimitKey);
      await this.auditRepo.recordAuthEvent({
        userId: user.id,
        action: 'LOGIN_FAILED',
        actorEmail: normalizedEmail,
        ipAddress: context.ip,
        userAgent: context.userAgent,
        details: { reason: 'INVALID_PASSWORD' },
      });
      const err = new Error('Invalid email or password.');
      (err as any).statusCode = 401;
      (err as any).code = 'INVALID_CREDENTIALS';
      throw err;
    }

    // Login successful
    this.clearFailedAttempts(rateLimitKey);
    await this.userRepo.updateLastLogin(user.id);

    const siteMemberships = await this.userRepo.getUserSiteMemberships(user.id);
    const siteCodes = siteMemberships.map((s) => s.siteCode);

    const rawRefreshToken = this.generateRefreshToken();
    const tokenHash = this.hashToken(rawRefreshToken);

    const expiresAt = new Date();
    expiresAt.setDate(expiresAt.getDate() + this.env.JWT_REFRESH_TTL_DAYS);

    const session = await this.sessionRepo.createSession(user.id, tokenHash, expiresAt);
    const accessToken = this.generateAccessToken(user, siteCodes, session.id);

    await this.auditRepo.recordAuthEvent({
      userId: user.id,
      action: 'LOGIN_SUCCESS',
      actorEmail: normalizedEmail,
      ipAddress: context.ip,
      userAgent: context.userAgent,
      details: { role: user.role, sites: siteCodes },
    });

    const csrfToken = this.generateCsrfToken();

    return {
      accessToken,
      refreshToken: rawRefreshToken,
      csrfToken,
      user: {
        id: user.id,
        email: user.email,
        fullName: user.fullName,
        role: user.role,
        sites: siteCodes,
      },
    };
  }

  /**
   * Refreshes access token and rotates refresh token with reuse detection.
   */
  async refresh(
    rawRefreshToken: string,
    context: { ip?: string | undefined; userAgent?: string | undefined } = {}
  ): Promise<RefreshResult> {
    if (!rawRefreshToken || typeof rawRefreshToken !== 'string') {
      const err = new Error('Refresh token is required.');
      (err as any).statusCode = 401;
      (err as any).code = 'INVALID_REFRESH_TOKEN';
      throw err;
    }

    const tokenHash = this.hashToken(rawRefreshToken);

    // Look up any session by hash to detect replay/reuse
    const existingSession = await this.sessionRepo.findSessionByTokenHash(tokenHash);

    if (!existingSession) {
      const err = new Error('Invalid refresh token.');
      (err as any).statusCode = 401;
      (err as any).code = 'INVALID_REFRESH_TOKEN';
      throw err;
    }

    // Refresh Token Reuse Detection
    if (existingSession.revokedAt !== null) {
      // Token was already revoked or rotated! Replay attack detected.
      // Revoke all sessions for this user to protect account.
      await this.sessionRepo.revokeAllUserSessions(existingSession.userId);

      const user = await this.userRepo.findById(existingSession.userId);
      await this.auditRepo.recordAuthEvent({
        userId: existingSession.userId,
        action: 'REFRESH_TOKEN_REUSE_DETECTED',
        actorEmail: user ? user.email : 'unknown',
        ipAddress: context.ip,
        userAgent: context.userAgent,
        details: { sessionId: existingSession.id, revokedAt: existingSession.revokedAt },
      });

      const err = new Error('Refresh token reuse detected. All active sessions have been invalidated.');
      (err as any).statusCode = 401;
      (err as any).code = 'TOKEN_REUSE_DETECTED';
      throw err;
    }

    // Check expiration
    if (new Date() >= existingSession.expiresAt) {
      await this.sessionRepo.revokeSession(existingSession.id);
      const err = new Error('Refresh token has expired. Please log in again.');
      (err as any).statusCode = 401;
      (err as any).code = 'REFRESH_TOKEN_EXPIRED';
      throw err;
    }

    // Check user account status
    const user = await this.userRepo.findById(existingSession.userId);
    if (!user || user.status === 'DISABLED') {
      await this.sessionRepo.revokeSession(existingSession.id);
      const err = new Error('User account is deactivated.');
      (err as any).statusCode = 403;
      (err as any).code = 'ACCOUNT_DISABLED';
      throw err;
    }

    // Rotate refresh token
    const newRawRefreshToken = this.generateRefreshToken();
    const newTokenHash = this.hashToken(newRawRefreshToken);

    const newExpiresAt = new Date();
    newExpiresAt.setDate(newExpiresAt.getDate() + this.env.JWT_REFRESH_TTL_DAYS);

    const rotatedSession = await this.sessionRepo.rotateSessionToken(
      existingSession.id,
      tokenHash,
      newTokenHash,
      newExpiresAt,
      existingSession.userId
    );

    if (!rotatedSession) {
      const err = new Error('Failed to rotate refresh token session.');
      (err as any).statusCode = 401;
      (err as any).code = 'TOKEN_ROTATION_FAILED';
      throw err;
    }

    const siteMemberships = await this.userRepo.getUserSiteMemberships(user.id);
    const siteCodes = siteMemberships.map((s) => s.siteCode);
    const accessToken = this.generateAccessToken(user, siteCodes, rotatedSession.id);

    await this.auditRepo.recordAuthEvent({
      userId: user.id,
      action: 'TOKEN_REFRESH_SUCCESS',
      actorEmail: user.email,
      ipAddress: context.ip,
      userAgent: context.userAgent,
    });

    const csrfToken = this.generateCsrfToken();

    return {
      accessToken,
      refreshToken: newRawRefreshToken,
      csrfToken,
      user: {
        id: user.id,
        email: user.email,
        fullName: user.fullName,
        role: user.role,
        sites: siteCodes,
      },
    };
  }

  /**
   * Logs out a session by revoking its refresh token.
   */
  async logout(
    rawRefreshToken: string | undefined,
    context: { ip?: string | undefined; userAgent?: string | undefined } = {}
  ): Promise<void> {
    if (!rawRefreshToken) return;

    const tokenHash = this.hashToken(rawRefreshToken);
    const session = await this.sessionRepo.findSessionByTokenHash(tokenHash);

    if (session) {
      await this.sessionRepo.revokeSession(session.id);
      const user = await this.userRepo.findById(session.userId);
      await this.auditRepo.recordAuthEvent({
        userId: session.userId,
        action: 'LOGOUT_SUCCESS',
        actorEmail: user ? user.email : 'unknown',
        ipAddress: context.ip,
        userAgent: context.userAgent,
      });
    }
  }

  // --- Administrative User Management ---

  async listUsers(): Promise<Array<{
    id: string;
    fullName: string;
    email: string;
    role: UserRole;
    status: UserStatus;
    sites: string[];
    createdAt: Date;
    updatedAt: Date;
    lastLoginAt: Date | null;
  }>> {
    return this.userRepo.listUsers();
  }

  async createUser(
    adminUser: AuthTokenPayload,
    params: {
      fullName: string;
      email: string;
      password: string;
      role: UserRole;
      sites?: string[];
    },
    context: { ip?: string | undefined; userAgent?: string | undefined } = {}
  ): Promise<AuthenticatedUserView> {
    const normalizedEmail = (params.email || '').trim().toLowerCase();
    if (!normalizedEmail || !normalizedEmail.includes('@')) {
      const err = new Error('A valid email address is required.');
      (err as any).statusCode = 400;
      (err as any).code = 'INVALID_EMAIL';
      throw err;
    }

    if (!params.password || params.password.length < 8) {
      const err = new Error('Password must be at least 8 characters long.');
      (err as any).statusCode = 400;
      (err as any).code = 'INVALID_PASSWORD_COMPLEXITY';
      throw err;
    }

    const validRoles: UserRole[] = ['PLATFORM_ADMIN', 'FACTORY_OPERATOR', 'REGULATOR_AUDITOR'];
    if (!validRoles.includes(params.role)) {
      const err = new Error(`Invalid role. Must be one of: ${validRoles.join(', ')}`);
      (err as any).statusCode = 400;
      (err as any).code = 'INVALID_ROLE';
      throw err;
    }

    const existing = await this.userRepo.findByEmail(normalizedEmail);
    if (existing) {
      const err = new Error('A user with this email address already exists.');
      (err as any).statusCode = 409;
      (err as any).code = 'USER_ALREADY_EXISTS';
      throw err;
    }

    const passwordHash = await this.hashPassword(params.password);
    const created = await this.userRepo.createUser({
      fullName: (params.fullName || '').trim(),
      email: normalizedEmail,
      passwordHash,
      role: params.role,
      status: 'ACTIVE',
    });

    const assignedSites: string[] = [];
    if (Array.isArray(params.sites)) {
      for (const siteCode of params.sites) {
        const site = await this.userRepo.findSiteByCode(siteCode);
        if (site) {
          await this.userRepo.assignSiteMembership(created.id, site.id);
          assignedSites.push(site.siteCode);
        }
      }
    }

    await this.auditRepo.recordAuthEvent({
      userId: created.id,
      action: 'USER_CREATED',
      actorEmail: adminUser.email,
      ipAddress: context.ip,
      userAgent: context.userAgent,
      details: {
        createdUserId: created.id,
        createdUserEmail: created.email,
        role: created.role,
        assignedSites,
      },
    });

    return {
      id: created.id,
      email: created.email,
      fullName: created.fullName,
      role: created.role,
      sites: assignedSites,
    };
  }

  async setUserStatus(
    adminUser: AuthTokenPayload,
    targetUserId: string,
    status: UserStatus,
    context: { ip?: string | undefined; userAgent?: string | undefined } = {}
  ): Promise<{ id: string; status: UserStatus }> {
    const client = await this.pool.connect();
    try {
      await client.query('BEGIN');

      const user = await this.userRepo.findById(targetUserId, client);
      if (!user) {
        const err = new Error('User not found.');
        (err as any).statusCode = 404;
        (err as any).code = 'USER_NOT_FOUND';
        throw err;
      }

      if (status === 'DISABLED') {
        if (user.role === 'PLATFORM_ADMIN') {
          const remainingAdmins = await this.userRepo.countActiveAdmins(user.id, client);
          if (remainingAdmins === 0) {
            const err = new Error('Cannot disable the last active PLATFORM_ADMIN account.');
            (err as any).statusCode = 400;
            (err as any).code = 'CANNOT_DISABLE_LAST_ADMIN';
            throw err;
          }
        }
        await this.userRepo.setUserStatus(user.id, 'DISABLED', client);
        // Revoke all active sessions immediately
        await this.sessionRepo.revokeAllUserSessions(user.id, client);

        await this.auditRepo.recordAuthEvent(
          {
            userId: user.id,
            action: 'ACCOUNT_DISABLED',
            actorEmail: adminUser.email,
            ipAddress: context.ip,
            userAgent: context.userAgent,
            details: { targetUserId: user.id, targetEmail: user.email },
          },
          client
        );
      } else {
        await this.userRepo.setUserStatus(user.id, 'ACTIVE', client);
        await this.auditRepo.recordAuthEvent(
          {
            userId: user.id,
            action: 'ACCOUNT_REACTIVATED',
            actorEmail: adminUser.email,
            ipAddress: context.ip,
            userAgent: context.userAgent,
            details: { targetUserId: user.id, targetEmail: user.email },
          },
          client
        );
      }

      await client.query('COMMIT');
      return { id: user.id, status };
    } catch (err) {
      await client.query('ROLLBACK');
      throw err;
    } finally {
      client.release();
    }
  }

  async setUserRole(
    adminUser: AuthTokenPayload,
    targetUserId: string,
    newRole: UserRole,
    context: { ip?: string | undefined; userAgent?: string | undefined } = {}
  ): Promise<{ id: string; role: UserRole }> {
    const client = await this.pool.connect();
    try {
      await client.query('BEGIN');

      const user = await this.userRepo.findById(targetUserId, client);
      if (!user) {
        const err = new Error('User not found.');
        (err as any).statusCode = 404;
        (err as any).code = 'USER_NOT_FOUND';
        throw err;
      }

      const validRoles: UserRole[] = ['PLATFORM_ADMIN', 'FACTORY_OPERATOR', 'REGULATOR_AUDITOR'];
      if (!validRoles.includes(newRole)) {
        const err = new Error(`Invalid role. Must be one of: ${validRoles.join(', ')}`);
        (err as any).statusCode = 400;
        (err as any).code = 'INVALID_ROLE';
        throw err;
      }

      if (user.role === 'PLATFORM_ADMIN' && newRole !== 'PLATFORM_ADMIN') {
        const remainingAdmins = await this.userRepo.countActiveAdmins(user.id, client);
        if (remainingAdmins === 0) {
          const err = new Error('Cannot change role: user is the last active PLATFORM_ADMIN.');
          (err as any).statusCode = 400;
          (err as any).code = 'CANNOT_DEMOTE_LAST_ADMIN';
          throw err;
        }
      }

      const previousRole = user.role;
      await this.userRepo.updateUserRole(user.id, newRole, client);
      // Revoke all existing sessions so obsolete role tokens are rejected
      await this.sessionRepo.revokeAllUserSessions(user.id, client);

      await this.auditRepo.recordAuthEvent(
        {
          userId: user.id,
          action: 'ROLE_CHANGED',
          actorEmail: adminUser.email,
          ipAddress: context.ip,
          userAgent: context.userAgent,
          details: {
            targetUserId: user.id,
            targetEmail: user.email,
            previousRole,
            newRole,
          },
        },
        client
      );

      await client.query('COMMIT');
      return { id: user.id, role: newRole };
    } catch (err) {
      await client.query('ROLLBACK');
      throw err;
    } finally {
      client.release();
    }
  }

  async addUserSite(
    adminUser: AuthTokenPayload,
    targetUserId: string,
    siteCode: string,
    context: { ip?: string | undefined; userAgent?: string | undefined } = {}
  ): Promise<{ id: string; sites: string[] }> {
    const client = await this.pool.connect();
    try {
      await client.query('BEGIN');

      const user = await this.userRepo.findById(targetUserId, client);
      if (!user) {
        const err = new Error('User not found.');
        (err as any).statusCode = 404;
        (err as any).code = 'USER_NOT_FOUND';
        throw err;
      }

      const site = await this.userRepo.findSiteByCode(siteCode, client);
      if (!site) {
        const err = new Error(`Site code '${siteCode}' does not exist.`);
        (err as any).statusCode = 404;
        (err as any).code = 'SITE_NOT_FOUND';
        throw err;
      }

      await this.userRepo.assignSiteMembership(user.id, site.id, client);
      // Invalidate sessions so permissions update cleanly
      await this.sessionRepo.revokeAllUserSessions(user.id, client);

      const updatedSites = await this.userRepo.getUserSiteCodes(user.id, client);
      await this.auditRepo.recordAuthEvent(
        {
          userId: user.id,
          action: 'SITE_MEMBERSHIP_CHANGED',
          actorEmail: adminUser.email,
          ipAddress: context.ip,
          userAgent: context.userAgent,
          details: {
            targetUserId: user.id,
            targetEmail: user.email,
            modification: 'ADDED',
            siteCode,
          },
        },
        client
      );

      await client.query('COMMIT');
      return { id: user.id, sites: updatedSites };
    } catch (err) {
      await client.query('ROLLBACK');
      throw err;
    } finally {
      client.release();
    }
  }

  async removeUserSite(
    adminUser: AuthTokenPayload,
    targetUserId: string,
    siteCode: string,
    context: { ip?: string | undefined; userAgent?: string | undefined } = {}
  ): Promise<{ id: string; sites: string[] }> {
    const client = await this.pool.connect();
    try {
      await client.query('BEGIN');

      const user = await this.userRepo.findById(targetUserId, client);
      if (!user) {
        const err = new Error('User not found.');
        (err as any).statusCode = 404;
        (err as any).code = 'USER_NOT_FOUND';
        throw err;
      }

      const site = await this.userRepo.findSiteByCode(siteCode, client);
      if (!site) {
        const err = new Error(`Site code '${siteCode}' does not exist.`);
        (err as any).statusCode = 404;
        (err as any).code = 'SITE_NOT_FOUND';
        throw err;
      }

      await this.userRepo.removeSiteMembership(user.id, site.id, client);
      // Invalidate sessions so old access tokens cannot access removed site
      await this.sessionRepo.revokeAllUserSessions(user.id, client);

      const updatedSites = await this.userRepo.getUserSiteCodes(user.id, client);
      await this.auditRepo.recordAuthEvent(
        {
          userId: user.id,
          action: 'SITE_MEMBERSHIP_CHANGED',
          actorEmail: adminUser.email,
          ipAddress: context.ip,
          userAgent: context.userAgent,
          details: {
            targetUserId: user.id,
            targetEmail: user.email,
            modification: 'REMOVED',
            siteCode,
          },
        },
        client
      );

      await client.query('COMMIT');
      return { id: user.id, sites: updatedSites };
    } catch (err) {
      await client.query('ROLLBACK');
      throw err;
    } finally {
      client.release();
    }
  }

  async queryAuditEvents(filters: {
    limit?: number | undefined;
    offset?: number | undefined;
    action?: string | undefined;
    userId?: string | undefined;
  } = {}): Promise<AuthAuditEventRecord[]> {
    return this.auditRepo.queryEvents(filters);
  }

  /**
   * Retrieves user profile and permitted sites for /me endpoint.
   */
  async getMe(userId: string): Promise<AuthenticatedUserView> {
    const user = await this.userRepo.findById(userId);
    if (!user || user.status === 'DISABLED') {
      const err = new Error('User account not found or disabled.');
      (err as any).statusCode = 401;
      (err as any).code = 'UNAUTHORIZED';
      throw err;
    }

    const memberships = await this.userRepo.getUserSiteMemberships(user.id);
    return {
      id: user.id,
      email: user.email,
      fullName: user.fullName,
      role: user.role,
      sites: memberships.map((m) => m.siteCode),
    };
  }
}
