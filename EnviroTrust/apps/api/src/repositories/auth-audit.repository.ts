import type { Pool, PoolClient } from 'pg';

export type AuthAuditAction =
  | 'LOGIN_SUCCESS'
  | 'LOGIN_FAILED'
  | 'LOGIN_RATE_LIMITED'
  | 'LOGOUT_SUCCESS'
  | 'TOKEN_REFRESH_SUCCESS'
  | 'REFRESH_TOKEN_REUSE_DETECTED'
  | 'ACCOUNT_DISABLED'
  | 'ACCOUNT_REACTIVATED'
  | 'USER_CREATED'
  | 'ROLE_CHANGED'
  | 'SITE_MEMBERSHIP_CHANGED';

export interface AuthAuditEventRecord {
  id: string;
  userId: string | null;
  action: AuthAuditAction | string;
  actorEmail: string;
  ipAddress: string | null;
  userAgent: string | null;
  details: Record<string, unknown>;
  occurredAt: Date;
}

export class AuthAuditRepository {
  constructor(private readonly pool: Pool) {}

  /**
   * Persists an authentication or administrative audit event.
   * Ensures no passwords, secrets, or raw tokens are stored.
   */
  async recordAuthEvent(
    params: {
      userId?: string | null | undefined;
      action: AuthAuditAction | string;
      actorEmail: string;
      ipAddress?: string | null | undefined;
      userAgent?: string | null | undefined;
      details?: Record<string, unknown> | undefined;
    },
    client?: PoolClient
  ): Promise<void> {
    const q = client || this.pool;
    const sanitizedDetails = { ...(params.details || {}) };
    // Remove any accidental secret keys
    delete sanitizedDetails['password'];
    delete sanitizedDetails['token'];
    delete sanitizedDetails['refreshToken'];
    delete sanitizedDetails['accessToken'];
    delete sanitizedDetails['cookie'];

    await q.query(
      `INSERT INTO auth_audit_events (user_id, action, actor_email, ip_address, user_agent, details, occurred_at)
       VALUES ($1, $2, $3, $4, $5, $6, now())`,
      [
        params.userId || null,
        params.action,
        params.actorEmail.toLowerCase().trim(),
        params.ipAddress || null,
        params.userAgent || null,
        JSON.stringify(sanitizedDetails),
      ]
    );
  }

  /**
   * Queries audit events with filtering and pagination for administrative review.
   */
  async queryEvents(filters: {
    limit?: number | undefined;
    offset?: number | undefined;
    action?: string | undefined;
    userId?: string | undefined;
  } = {}): Promise<AuthAuditEventRecord[]> {
    const conditions: string[] = [];
    const values: any[] = [];
    let pIdx = 1;

    if (filters.action) {
      conditions.push(`action = $${pIdx++}`);
      values.push(filters.action);
    }

    if (filters.userId) {
      conditions.push(`user_id = $${pIdx++}`);
      values.push(filters.userId);
    }

    const whereClause = conditions.length > 0 ? `WHERE ${conditions.join(' AND ')}` : '';
    const limit = Math.min(filters.limit || 50, 200);
    const offset = Math.max(filters.offset || 0, 0);

    values.push(limit, offset);
    const sql = `
      SELECT id, user_id, action, actor_email, ip_address, user_agent, details, occurred_at
      FROM auth_audit_events
      ${whereClause}
      ORDER BY occurred_at DESC
      LIMIT $${pIdx++} OFFSET $${pIdx++}
    `;

    const res = await this.pool.query<{
      id: string;
      user_id: string | null;
      action: string;
      actor_email: string;
      ip_address: string | null;
      user_agent: string | null;
      details: Record<string, unknown>;
      occurred_at: Date;
    }>(sql, values);

    return res.rows.map((r) => ({
      id: r.id,
      userId: r.user_id,
      action: r.action,
      actorEmail: r.actor_email,
      ipAddress: r.ip_address,
      userAgent: r.user_agent,
      details: r.details,
      occurredAt: r.occurred_at,
    }));
  }

  /**
   * Retrieves recent audit events for admin inspection.
   */
  async getRecentEvents(limit = 50): Promise<AuthAuditEventRecord[]> {
    return this.queryEvents({ limit });
  }
}
