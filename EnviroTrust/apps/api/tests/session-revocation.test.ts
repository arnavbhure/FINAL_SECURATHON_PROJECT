import { describe, it, before, after } from 'node:test';
import assert from 'node:assert/strict';
import type { Server } from 'node:http';
import type { AddressInfo } from 'node:net';
import { createApiApp } from '../src/app.js';
import { getDbPool, closeDbPool } from '../src/db/connection.js';
import { runMigrations } from '../src/db/migrate.js';
import { seedDemoUsers } from '../src/db/seed.js';

describe('Primary API — Session Revocation, Access Token Validation & Cookie Security Tests', () => {
  let server: Server;
  let baseUrl: string;

  before(async () => {
    const pool = getDbPool();
    await runMigrations(pool);
    await seedDemoUsers();

    const { app } = createApiApp();
    await new Promise<void>((resolve) => {
      server = app.listen(0, () => {
        const addr = server.address() as AddressInfo;
        baseUrl = `http://127.0.0.1:${addr.port}`;
        resolve();
      });
    });
  });

  after(async () => {
    await new Promise<void>((resolve) => {
      server.close(() => resolve());
    });
    await closeDbPool();
  });

  async function getAdminToken(): Promise<string> {
    const res = await fetch(`${baseUrl}/api/v1/auth/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email: 'admin@envirotrust.local', password: 'DemoPassword123!' }),
    });
    const data = (await res.json()) as any;
    return data.accessToken;
  }

  it('1. Access token is IMMEDIATELY revoked after user logs out (cannot be used for remaining TTL)', async () => {
    // 1. Login to obtain access token and refresh cookie
    const loginRes = await fetch(`${baseUrl}/api/v1/auth/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email: 'operator@envirotrust.local', password: 'DemoPassword123!' }),
    });
    const loginBody = (await loginRes.json()) as any;
    const accessToken = loginBody.accessToken;
    const csrfToken = loginBody.csrfToken;

    const setCookies = loginRes.headers.getSetCookie ? loginRes.headers.getSetCookie() : [loginRes.headers.get('set-cookie') || ''];
    let refreshCookie: string | undefined;
    for (const sc of setCookies) {
      const match = sc.match(/envirotrust_refresh=([^;]+)/);
      if (match && match[1]) refreshCookie = match[1];
    }
    assert.ok(refreshCookie);

    // 2. Verify access token works initially
    const meResBefore = await fetch(`${baseUrl}/api/v1/auth/me`, {
      headers: { Authorization: `Bearer ${accessToken}` },
    });
    assert.equal(meResBefore.status, 200);

    // 3. User logs out
    const logoutRes = await fetch(`${baseUrl}/api/v1/auth/logout`, {
      method: 'POST',
      headers: {
        Cookie: `envirotrust_refresh=${refreshCookie}; envirotrust_csrf=${csrfToken}`,
        'X-CSRF-Token': csrfToken,
        Origin: 'http://localhost:5173',
      },
    });
    assert.equal(logoutRes.status, 200);

    // 4. Access token MUST BE REJECTED immediately!
    const meResAfter = await fetch(`${baseUrl}/api/v1/auth/me`, {
      headers: { Authorization: `Bearer ${accessToken}` },
    });
    assert.equal(meResAfter.status, 401);
    const meBodyAfter = (await meResAfter.json()) as any;
    assert.equal(meBodyAfter.code, 'SESSION_REVOKED');
  });

  it('2. Access token is IMMEDIATELY revoked when administrator disables user account', async () => {
    const adminToken = await getAdminToken();
    // 1. Create a dedicated test user
    const email = `revocation-test-${Date.now()}@envirotrust.local`;
    const createRes = await fetch(`${baseUrl}/api/v1/admin/users`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${adminToken}`,
      },
      body: JSON.stringify({
        fullName: 'Revocation Subject',
        email,
        password: 'Password123!',
        role: 'FACTORY_OPERATOR',
        sites: ['PLANT-001'],
      }),
    });
    const createBody = (await createRes.json()) as any;
    const userId = createBody.user.id;

    // 2. User logs in
    const loginRes = await fetch(`${baseUrl}/api/v1/auth/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email, password: 'Password123!' }),
    });
    const loginBody = (await loginRes.json()) as any;
    const accessToken = loginBody.accessToken;

    // 3. Verify access token works
    const meBefore = await fetch(`${baseUrl}/api/v1/auth/me`, {
      headers: { Authorization: `Bearer ${accessToken}` },
    });
    assert.equal(meBefore.status, 200);

    // 4. Admin disables user
    const disableRes = await fetch(`${baseUrl}/api/v1/admin/users/${userId}/status`, {
      method: 'PATCH',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${adminToken}`,
      },
      body: JSON.stringify({ status: 'DISABLED' }),
    });
    assert.equal(disableRes.status, 200);

    // 5. Access token is IMMEDIATELY rejected (403 ACCOUNT_DISABLED or 401 SESSION_REVOKED)
    const meAfter = await fetch(`${baseUrl}/api/v1/auth/me`, {
      headers: { Authorization: `Bearer ${accessToken}` },
    });
    assert.ok(meAfter.status === 401 || meAfter.status === 403);
    const meBody = (await meAfter.json()) as any;
    assert.ok(meBody.code === 'ACCOUNT_DISABLED' || meBody.code === 'SESSION_REVOKED');
  });

  it('3. Access token is IMMEDIATELY invalidated when administrator changes user role', async () => {
    const adminToken = await getAdminToken();
    // 1. Create user
    const email = `role-change-${Date.now()}@envirotrust.local`;
    const createRes = await fetch(`${baseUrl}/api/v1/admin/users`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${adminToken}`,
      },
      body: JSON.stringify({
        fullName: 'Role Change Subject',
        email,
        password: 'Password123!',
        role: 'FACTORY_OPERATOR',
        sites: ['PLANT-001'],
      }),
    });
    const createBody = (await createRes.json()) as any;
    const userId = createBody.user.id;

    // 2. User logs in
    const loginRes = await fetch(`${baseUrl}/api/v1/auth/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email, password: 'Password123!' }),
    });
    const loginBody = (await loginRes.json()) as any;
    const accessToken = loginBody.accessToken;

    // 3. Admin changes role to REGULATOR_AUDITOR
    const roleRes = await fetch(`${baseUrl}/api/v1/admin/users/${userId}/role`, {
      method: 'PATCH',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${adminToken}`,
      },
      body: JSON.stringify({ role: 'REGULATOR_AUDITOR' }),
    });
    assert.equal(roleRes.status, 200);

    // 4. Old access token with outdated role claim is IMMEDIATELY rejected!
    const meAfter = await fetch(`${baseUrl}/api/v1/auth/me`, {
      headers: { Authorization: `Bearer ${accessToken}` },
    });
    assert.equal(meAfter.status, 401);
    const body = (await meAfter.json()) as any;
    assert.equal(body.code, 'SESSION_REVOKED');
  });

  it('4. Hostile Origin header is REJECTED on cookie-authenticated operations (403 FORBIDDEN_ORIGIN)', async () => {
    // 1. Login
    const loginRes = await fetch(`${baseUrl}/api/v1/auth/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email: 'operator@envirotrust.local', password: 'DemoPassword123!' }),
    });
    const loginBody = (await loginRes.json()) as any;
    const csrfToken = loginBody.csrfToken;
    const setCookies = loginRes.headers.getSetCookie ? loginRes.headers.getSetCookie() : [loginRes.headers.get('set-cookie') || ''];
    let refreshCookie: string | undefined;
    for (const sc of setCookies) {
      const match = sc.match(/envirotrust_refresh=([^;]+)/);
      if (match && match[1]) refreshCookie = match[1];
    }

    // 2. Attempt refresh with hostile Origin: http://malicious-attacker.com
    const hostileRes = await fetch(`${baseUrl}/api/v1/auth/refresh`, {
      method: 'POST',
      headers: {
        Cookie: `envirotrust_refresh=${refreshCookie}; envirotrust_csrf=${csrfToken}`,
        'X-CSRF-Token': csrfToken,
        Origin: 'http://malicious-attacker.com',
      },
    });
    assert.equal(hostileRes.status, 403);
    const hostileBody = (await hostileRes.json()) as any;
    assert.equal(hostileBody.code, 'FORBIDDEN_ORIGIN');
  });

  it('5. Programmatic non-browser refresh endpoint rotates tokens when X-Client-Type header is present', async () => {
    // Attempt 1: Call without required header -> 400
    const badRes = await fetch(`${baseUrl}/api/v1/auth/token/refresh`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ refreshToken: 'some-token' }),
    });
    assert.equal(badRes.status, 400);

    // Attempt 2: Login to get a valid session
    const pool = getDbPool();
    const userRes = await pool.query<{ id: string }>("SELECT id FROM users WHERE email = 'operator@envirotrust.local'");
    const userId = userRes.rows[0]?.id;
    assert.ok(userId);

    const crypto = await import('node:crypto');
    const rawRefresh = crypto.randomBytes(40).toString('hex');
    const tokenHash = crypto.createHash('sha256').update(rawRefresh).digest('hex');
    const expiresAt = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000);

    await pool.query(
      'INSERT INTO authentication_sessions (user_id, token_hash, expires_at) VALUES ($1, $2, $3)',
      [userId, tokenHash, expiresAt.toISOString()]
    );

    const goodRes = await fetch(`${baseUrl}/api/v1/auth/token/refresh`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-Client-Type': 'non-browser',
      },
      body: JSON.stringify({ refreshToken: rawRefresh }),
    });

    assert.equal(goodRes.status, 200);
    const goodBody = (await goodRes.json()) as any;
    assert.ok(goodBody.accessToken);
    assert.ok(goodBody.refreshToken);
    assert.notEqual(goodBody.refreshToken, rawRefresh);
  });
});
