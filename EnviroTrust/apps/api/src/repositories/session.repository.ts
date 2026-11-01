import type { Pool, PoolClient } from 'pg';

export interface SessionRecord {
  id: string;
  userId: string;
  tokenHash: string;
  expiresAt: Date;
  revokedAt: Date | null;
  createdAt: Date;
  lastUsedAt: Date;
}

export class SessionRepository {
  constructor(private readonly pool: Pool) {}

  /**
   * Persists a newly created authentication session with a SHA-256 token hash.
   */
  async createSession(
    userId: string,
    tokenHash: string,
    expiresAt: Date,
    client?: PoolClient
  ): Promise<SessionRecord> {
    const q = client || this.pool;
    const res = await q.query<{
      id: string;
      user_id: string;
      token_hash: string;
      expires_at: Date;
      revoked_at: Date | null;
      created_at: Date;
      last_used_at: Date;
    }>(
      `INSERT INTO authentication_sessions (user_id, token_hash, expires_at, created_at, last_used_at)
       VALUES ($1, $2, $3, now(), now())
       RETURNING id, user_id, token_hash, expires_at, revoked_at, created_at, last_used_at`,
      [userId, tokenHash, expiresAt.toISOString()]
    );

    const row = res.rows[0];
    if (!row) throw new Error('Failed to create authentication session');
    return {
      id: row.id,
      userId: row.user_id,
      tokenHash: row.token_hash,
      expiresAt: row.expires_at,
      revokedAt: row.revoked_at,
      createdAt: row.created_at,
      lastUsedAt: row.last_used_at,
    };
  }

  /**
   * Finds an active (unrevoked and unexpired) session by token hash.
   */
  async findActiveSession(tokenHash: string, client?: PoolClient): Promise<SessionRecord | null> {
    const q = client || this.pool;
    const res = await q.query<{
      id: string;
      user_id: string;
      token_hash: string;
      expires_at: Date;
      revoked_at: Date | null;
      created_at: Date;
      last_used_at: Date;
    }>(
      `SELECT id, user_id, token_hash, expires_at, revoked_at, created_at, last_used_at
       FROM authentication_sessions
       WHERE token_hash = $1 AND revoked_at IS NULL AND expires_at > now()`,
      [tokenHash]
    );

    if (res.rows.length === 0 || !res.rows[0]) return null;
    const row = res.rows[0];
    return {
      id: row.id,
      userId: row.user_id,
      tokenHash: row.token_hash,
      expiresAt: row.expires_at,
      revokedAt: row.revoked_at,
      createdAt: row.created_at,
      lastUsedAt: row.last_used_at,
    };
  }

  /**
   * Finds any session (active or revoked) by token hash. Used for reuse detection.
   */
  async findSessionByTokenHash(tokenHash: string, client?: PoolClient): Promise<SessionRecord | null> {
    const q = client || this.pool;
    const res = await q.query<{
      id: string;
      user_id: string;
      token_hash: string;
      expires_at: Date;
      revoked_at: Date | null;
      created_at: Date;
      last_used_at: Date;
    }>(
      `SELECT id, user_id, token_hash, expires_at, revoked_at, created_at, last_used_at
       FROM authentication_sessions
       WHERE token_hash = $1`,
      [tokenHash]
    );

    if (res.rows.length === 0 || !res.rows[0]) return null;
    const row = res.rows[0];
    return {
      id: row.id,
      userId: row.user_id,
      tokenHash: row.token_hash,
      expiresAt: row.expires_at,
      revokedAt: row.revoked_at,
      createdAt: row.created_at,
      lastUsedAt: row.last_used_at,
    };
  }

  /**
    * Finds a session by its ID.
    */
  async findById(sessionId: string, client?: PoolClient): Promise<SessionRecord | null> {
    const q = client || this.pool;
    const res = await q.query<{
      id: string;
      user_id: string;
      token_hash: string;
      expires_at: Date;
      revoked_at: Date | null;
      created_at: Date;
      last_used_at: Date;
    }>(
      `SELECT id, user_id, token_hash, expires_at, revoked_at, created_at, last_used_at
       FROM authentication_sessions
       WHERE id = $1`,
      [sessionId]
    );

    if (res.rows.length === 0 || !res.rows[0]) return null;
    const row = res.rows[0];
    return {
      id: row.id,
      userId: row.user_id,
      tokenHash: row.token_hash,
      expiresAt: row.expires_at,
      revokedAt: row.revoked_at,
      createdAt: row.created_at,
      lastUsedAt: row.last_used_at,
    };
  }

  /**
   * Atomically rotates the refresh token session on successful refresh.
   * Marks old token revoked and inserts new active token to enable reuse detection.
   */
  async rotateSessionToken(
    sessionId: string,
    oldTokenHash: string,
    newTokenHash: string,
    newExpiresAt: Date,
    userId: string,
    client?: PoolClient
  ): Promise<SessionRecord | null> {
    const q = client || this.pool;

    // 1. Mark existing session as revoked
    const revokeRes = await q.query(
      `UPDATE authentication_sessions
       SET revoked_at = now()
       WHERE id = $1 AND token_hash = $2 AND revoked_at IS NULL`,
      [sessionId, oldTokenHash]
    );

    if ((revokeRes.rowCount ?? 0) === 0) {
      return null;
    }

    // 2. Insert new session
    const insertRes = await q.query<{
      id: string;
      user_id: string;
      token_hash: string;
      expires_at: Date;
      revoked_at: Date | null;
      created_at: Date;
      last_used_at: Date;
    }>(
      `INSERT INTO authentication_sessions (user_id, token_hash, expires_at, created_at, last_used_at)
       VALUES ($1, $2, $3, now(), now())
       RETURNING id, user_id, token_hash, expires_at, revoked_at, created_at, last_used_at`,
      [userId, newTokenHash, newExpiresAt.toISOString()]
    );

    const row = insertRes.rows[0];
    if (!row) return null;
    return {
      id: row.id,
      userId: row.user_id,
      tokenHash: row.token_hash,
      expiresAt: row.expires_at,
      revokedAt: row.revoked_at,
      createdAt: row.created_at,
      lastUsedAt: row.last_used_at,
    };
  }

  /**
   * Revokes a session by ID.
   */
  async revokeSession(sessionId: string, client?: PoolClient): Promise<void> {
    const q = client || this.pool;
    await q.query(
      `UPDATE authentication_sessions
       SET revoked_at = now()
       WHERE id = $1 AND revoked_at IS NULL`,
      [sessionId]
    );
  }

  /**
   * Revokes a session by token hash.
   */
  async revokeSessionByTokenHash(tokenHash: string, client?: PoolClient): Promise<void> {
    const q = client || this.pool;
    await q.query(
      `UPDATE authentication_sessions
       SET revoked_at = now()
       WHERE token_hash = $1 AND revoked_at IS NULL`,
      [tokenHash]
    );
  }

  /**
   * Revokes all active sessions for a user (used on token reuse detection or account status changes).
   */
  async revokeAllUserSessions(userId: string, client?: PoolClient): Promise<void> {
    const q = client || this.pool;
    await q.query(
      `UPDATE authentication_sessions
       SET revoked_at = now()
       WHERE user_id = $1 AND revoked_at IS NULL`,
      [userId]
    );
  }
}
