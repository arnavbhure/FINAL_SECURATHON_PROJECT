import type { Pool, PoolClient } from 'pg';

export type UserRole = 'PLATFORM_ADMIN' | 'FACTORY_OPERATOR' | 'REGULATOR_AUDITOR';
export type UserStatus = 'ACTIVE' | 'DISABLED';

export interface UserRecord {
  id: string;
  fullName: string;
  email: string;
  passwordHash: string;
  role: UserRole;
  status: UserStatus;
  createdAt: Date;
  updatedAt: Date;
  lastLoginAt: Date | null;
}

export interface UserSiteMembershipRecord {
  siteId: string;
  siteCode: string;
  siteName: string;
}

export class UserRepository {
  constructor(private readonly pool: Pool) {}

  /**
   * Finds a user by normalized email (case-insensitive).
   */
  async findByEmail(email: string, client?: PoolClient): Promise<UserRecord | null> {
    const q = client || this.pool;
    const normalized = email.trim().toLowerCase();
    const res = await q.query<{
      id: string;
      full_name: string;
      email: string;
      password_hash: string;
      role: UserRole;
      status: UserStatus;
      created_at: Date;
      updated_at: Date;
      last_login_at: Date | null;
    }>(
      `SELECT id, full_name, email, password_hash, role, status, created_at, updated_at, last_login_at
       FROM users
       WHERE LOWER(email) = $1`,
      [normalized]
    );

    if (res.rows.length === 0 || !res.rows[0]) return null;
    const row = res.rows[0];
    return {
      id: row.id,
      fullName: row.full_name,
      email: row.email,
      passwordHash: row.password_hash,
      role: row.role,
      status: row.status,
      createdAt: row.created_at,
      updatedAt: row.updated_at,
      lastLoginAt: row.last_login_at,
    };
  }

  /**
   * Finds a user by ID.
   */
  async findById(id: string, client?: PoolClient): Promise<UserRecord | null> {
    const q = client || this.pool;
    const res = await q.query<{
      id: string;
      full_name: string;
      email: string;
      password_hash: string;
      role: UserRole;
      status: UserStatus;
      created_at: Date;
      updated_at: Date;
      last_login_at: Date | null;
    }>(
      `SELECT id, full_name, email, password_hash, role, status, created_at, updated_at, last_login_at
       FROM users
       WHERE id = $1`,
      [id]
    );

    if (res.rows.length === 0 || !res.rows[0]) return null;
    const row = res.rows[0];
    return {
      id: row.id,
      fullName: row.full_name,
      email: row.email,
      passwordHash: row.password_hash,
      role: row.role,
      status: row.status,
      createdAt: row.created_at,
      updatedAt: row.updated_at,
      lastLoginAt: row.last_login_at,
    };
  }

  /**
   * Retrieves all sites a user is permitted to access.
   */
  async getUserSiteMemberships(userId: string, client?: PoolClient): Promise<UserSiteMembershipRecord[]> {
    const q = client || this.pool;
    const res = await q.query<{
      site_id: string;
      site_code: string;
      name: string;
    }>(
      `SELECT s.id as site_id, s.site_code, s.name
       FROM user_site_memberships m
       JOIN sites s ON s.id = m.site_id
       WHERE m.user_id = $1 AND s.status = 'ACTIVE'`,
      [userId]
    );

    return res.rows.map((r) => ({
      siteId: r.site_id,
      siteCode: r.site_code,
      siteName: r.name,
    }));
  }

  /**
   * Retrieves just the array of site codes for a user.
   */
  async getUserSiteCodes(userId: string, client?: PoolClient): Promise<string[]> {
    const memberships = await this.getUserSiteMemberships(userId, client);
    return memberships.map((m) => m.siteCode);
  }

  /**
   * Lists all human users with their assigned site codes (passwords excluded).
   */
  async listUsers(client?: PoolClient): Promise<Array<{
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
    const q = client || this.pool;
    const res = await q.query<{
      id: string;
      full_name: string;
      email: string;
      role: UserRole;
      status: UserStatus;
      sites: string[];
      created_at: Date;
      updated_at: Date;
      last_login_at: Date | null;
    }>(
      `SELECT u.id, u.full_name, u.email, u.role, u.status,
              COALESCE(ARRAY_AGG(s.site_code ORDER BY s.site_code) FILTER (WHERE s.site_code IS NOT NULL), '{}') as sites,
              u.created_at, u.updated_at, u.last_login_at
       FROM users u
       LEFT JOIN user_site_memberships m ON m.user_id = u.id
       LEFT JOIN sites s ON s.id = m.site_id
       GROUP BY u.id
       ORDER BY u.created_at ASC`
    );

    return res.rows.map((r) => ({
      id: r.id,
      fullName: r.full_name,
      email: r.email,
      role: r.role,
      status: r.status,
      sites: r.sites || [],
      createdAt: r.created_at,
      updatedAt: r.updated_at,
      lastLoginAt: r.last_login_at,
    }));
  }

  /**
   * Counts active PLATFORM_ADMIN users, optionally excluding a specific user ID.
   * Used to prevent accidental deletion or demotion of the last active administrator.
   */
  async countActiveAdmins(excludeUserId?: string, client?: PoolClient): Promise<number> {
    const q = client || this.pool;
    // When executing inside a transaction client, lock active PLATFORM_ADMIN rows
    // to prevent race conditions during concurrent admin demotion or disablement.
    const sql = client
      ? `WITH locked_admins AS (
           SELECT id
           FROM users
           WHERE role = 'PLATFORM_ADMIN' AND status = 'ACTIVE'
           FOR UPDATE
         )
         SELECT count(*) as count
         FROM locked_admins
         WHERE ($1::uuid IS NULL OR id != $1::uuid)`
      : `SELECT count(*) as count
         FROM users
         WHERE role = 'PLATFORM_ADMIN' AND status = 'ACTIVE'
           AND ($1::uuid IS NULL OR id != $1::uuid)`;

    const res = await q.query<{ count: string }>(sql, [excludeUserId || null]);

    return parseInt(res.rows[0]?.count || '0', 10);
  }

  /**
   * Updates a user's role.
   */
  async updateUserRole(userId: string, role: UserRole, client?: PoolClient): Promise<void> {
    const q = client || this.pool;
    await q.query(
      `UPDATE users
       SET role = $1, updated_at = now()
       WHERE id = $2`,
      [role, userId]
    );
  }

  /**
   * Removes a site membership from a user.
   */
  async removeSiteMembership(userId: string, siteId: string, client?: PoolClient): Promise<void> {
    const q = client || this.pool;
    await q.query(
      `DELETE FROM user_site_memberships
       WHERE user_id = $1 AND site_id = $2`,
      [userId, siteId]
    );
  }

  /**
   * Finds a site by its site_code.
   */
  async findSiteByCode(siteCode: string, client?: PoolClient): Promise<{ id: string; siteCode: string; name: string } | null> {
    const q = client || this.pool;
    const res = await q.query<{ id: string; site_code: string; name: string }>(
      `SELECT id, site_code, name FROM sites WHERE site_code = $1`,
      [siteCode]
    );
    if (res.rows.length === 0 || !res.rows[0]) return null;
    return {
      id: res.rows[0].id,
      siteCode: res.rows[0].site_code,
      name: res.rows[0].name,
    };
  }

  /**
   * Creates a new user record.
   */
  async createUser(
    params: {
      fullName: string;
      email: string;
      passwordHash: string;
      role: UserRole;
      status?: UserStatus;
    },
    client?: PoolClient
  ): Promise<UserRecord> {
    const q = client || this.pool;
    const normalized = params.email.trim().toLowerCase();
    const res = await q.query<{
      id: string;
      full_name: string;
      email: string;
      password_hash: string;
      role: UserRole;
      status: UserStatus;
      created_at: Date;
      updated_at: Date;
      last_login_at: Date | null;
    }>(
      `INSERT INTO users (full_name, email, password_hash, role, status, updated_at)
       VALUES ($1, $2, $3, $4, $5, now())
       RETURNING id, full_name, email, password_hash, role, status, created_at, updated_at, last_login_at`,
      [params.fullName, normalized, params.passwordHash, params.role, params.status || 'ACTIVE']
    );

    const row = res.rows[0];
    if (!row) throw new Error('Failed to create user');
    return {
      id: row.id,
      fullName: row.full_name,
      email: row.email,
      passwordHash: row.password_hash,
      role: row.role,
      status: row.status,
      createdAt: row.created_at,
      updatedAt: row.updated_at,
      lastLoginAt: row.last_login_at,
    };
  }

  /**
   * Assigns a site membership to a user.
   */
  async assignSiteMembership(userId: string, siteId: string, client?: PoolClient): Promise<void> {
    const q = client || this.pool;
    await q.query(
      `INSERT INTO user_site_memberships (user_id, site_id)
       VALUES ($1, $2)
       ON CONFLICT (user_id, site_id) DO NOTHING`,
      [userId, siteId]
    );
  }

  /**
   * Sets a user account status (ACTIVE or DISABLED).
   */
  async setUserStatus(userId: string, status: UserStatus, client?: PoolClient): Promise<void> {
    const q = client || this.pool;
    await q.query(
      `UPDATE users
       SET status = $1, updated_at = now()
       WHERE id = $2`,
      [status, userId]
    );
  }

  /**
   * Updates the last_login_at timestamp.
   */
  async updateLastLogin(userId: string, client?: PoolClient): Promise<void> {
    const q = client || this.pool;
    await q.query(
      `UPDATE users
       SET last_login_at = now()
       WHERE id = $1`,
      [userId]
    );
  }
}

