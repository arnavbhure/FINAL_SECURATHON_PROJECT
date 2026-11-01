import { describe, it, before, after } from 'node:test';
import assert from 'node:assert/strict';
import type { Server } from 'node:http';
import type { AddressInfo } from 'node:net';
import { createApiApp } from '../src/app.js';
import { getDbPool, closeDbPool } from '../src/db/connection.js';
import { runMigrations } from '../src/db/migrate.js';
import { seedDemoUsers } from '../src/db/seed.js';
import bcrypt from 'bcryptjs';
import { UserRepository } from '../src/repositories/user.repository.js';

describe('Primary API — Human Authentication & Session Lifecycle Tests', () => {
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

  it('1. Login with correct credentials succeeds and returns access token + refresh cookie (200)', async () => {
    const res = await fetch(`${baseUrl}/api/v1/auth/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        email: 'operator@envirotrust.local',
        password: 'DemoPassword123!',
      }),
    });

    assert.equal(res.status, 200);
    const body = (await res.json()) as any;
    assert.equal(body.success, true);
    assert.ok(body.accessToken);
    // SECURITY CHECK: Refresh token is NEVER returned in the JSON body for browser clients
    assert.equal(body.refreshToken, undefined);
    assert.equal(body.user.email, 'operator@envirotrust.local');
    assert.equal(body.user.role, 'FACTORY_OPERATOR');
    assert.ok(Array.isArray(body.user.sites));
    assert.ok(body.user.sites.includes('PLANT-001'));

    // SECURITY CHECK: password hash is NEVER returned in response
    assert.equal(body.user.passwordHash, undefined);
    assert.equal(body.passwordHash, undefined);

    // Verify Set-Cookie header is present with HttpOnly for refresh token
    const setCookie = res.headers.get('set-cookie');
    assert.ok(setCookie, 'Expected Set-Cookie header');
    assert.ok(setCookie.includes('HttpOnly'));
    assert.ok(setCookie.includes('envirotrust_refresh'));
    assert.ok(setCookie.includes('envirotrust_csrf'));
  });

  it('2. Login with incorrect password returns generic 401 error', async () => {
    const res = await fetch(`${baseUrl}/api/v1/auth/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        email: 'operator@envirotrust.local',
        password: 'WrongPassword999!',
      }),
    });

    assert.equal(res.status, 401);
    const body = (await res.json()) as any;
    assert.equal(body.success, false);
    assert.equal(body.code, 'INVALID_CREDENTIALS');
    assert.equal(body.message, 'Invalid email or password.');
  });

  it('3. Login with unknown email returns identical generic 401 error (no account enumeration)', async () => {
    const res = await fetch(`${baseUrl}/api/v1/auth/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        email: 'nonexistent-user@envirotrust.local',
        password: 'SomeRandomPassword!',
      }),
    });

    assert.equal(res.status, 401);
    const body = (await res.json()) as any;
    assert.equal(body.success, false);
    assert.equal(body.code, 'INVALID_CREDENTIALS');
    assert.equal(body.message, 'Invalid email or password.');
  });

  it('4. Normalized email handling: uppercase email logs in successfully', async () => {
    const res = await fetch(`${baseUrl}/api/v1/auth/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        email: 'OPERATOR@ENVIROTRUST.LOCAL  ',
        password: 'DemoPassword123!',
      }),
    });

    assert.equal(res.status, 200);
    const body = (await res.json()) as any;
    assert.equal(body.success, true);
    assert.equal(body.user.email, 'operator@envirotrust.local');
  });

  it('5. Disabled account cannot log in (403)', async () => {
    const pool = getDbPool();
    const userRepo = new UserRepository(pool);
    const passwordHash = await bcrypt.hash('DemoPassword123!', 10);
    const disabledEmail = `disabled-account-${Date.now()}@envirotrust.local`;
    await userRepo.createUser({
      fullName: 'Disabled Demo User',
      email: disabledEmail,
      passwordHash,
      role: 'FACTORY_OPERATOR',
      status: 'DISABLED',
    });

    const res = await fetch(`${baseUrl}/api/v1/auth/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        email: disabledEmail,
        password: 'DemoPassword123!',
      }),
    });

    assert.equal(res.status, 403);
    const body = (await res.json()) as any;
    assert.equal(body.success, false);
    assert.equal(body.code, 'ACCOUNT_DISABLED');
  });

  it('6. Token Refresh & Rotation: rotating refresh cookie issues new access token and rotates cookie', async () => {
    // 1. Initial Login
    const loginRes = await fetch(`${baseUrl}/api/v1/auth/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        email: 'admin@envirotrust.local',
        password: 'DemoPassword123!',
      }),
    });
    assert.equal(loginRes.status, 200);
    const loginBody = (await loginRes.json()) as any;
    assert.equal(loginBody.refreshToken, undefined, 'Refresh token must NOT be in JSON body');
    const csrfToken = loginBody.csrfToken;

    const setCookies = loginRes.headers.getSetCookie ? loginRes.headers.getSetCookie() : [loginRes.headers.get('set-cookie') || ''];
    let refreshCookie1: string | undefined;
    for (const sc of setCookies) {
      const match = sc.match(/envirotrust_refresh=([^;]+)/);
      if (match && match[1]) refreshCookie1 = match[1];
    }
    assert.ok(refreshCookie1, 'Expected envirotrust_refresh cookie');

    // 2. Perform Refresh using Cookie + CSRF + Origin
    const refreshRes = await fetch(`${baseUrl}/api/v1/auth/refresh`, {
      method: 'POST',
      headers: {
        Cookie: `envirotrust_refresh=${refreshCookie1}; envirotrust_csrf=${csrfToken}`,
        'X-CSRF-Token': csrfToken,
        Origin: 'http://localhost:5173',
      },
    });

    assert.equal(refreshRes.status, 200);
    const refreshBody = (await refreshRes.json()) as any;
    assert.ok(refreshBody.accessToken);
    assert.equal(refreshBody.refreshToken, undefined);

    const refreshSetCookies = refreshRes.headers.getSetCookie ? refreshRes.headers.getSetCookie() : [refreshRes.headers.get('set-cookie') || ''];
    let refreshCookie2: string | undefined;
    for (const sc of refreshSetCookies) {
      const match = sc.match(/envirotrust_refresh=([^;]+)/);
      if (match && match[1]) refreshCookie2 = match[1];
    }
    assert.ok(refreshCookie2, 'Expected rotated envirotrust_refresh cookie');
    assert.notEqual(refreshCookie1, refreshCookie2, 'Refresh cookie must rotate on every refresh');

    // 3. Attempting to use the OLD rotated cookie must be detected as REUSE!
    const reuseRes = await fetch(`${baseUrl}/api/v1/auth/refresh`, {
      method: 'POST',
      headers: {
        Cookie: `envirotrust_refresh=${refreshCookie1}; envirotrust_csrf=${csrfToken}`,
        'X-CSRF-Token': csrfToken,
        Origin: 'http://localhost:5173',
      },
    });

    assert.equal(reuseRes.status, 401);
    const reuseBody = (await reuseRes.json()) as any;
    assert.equal(reuseBody.code, 'TOKEN_REUSE_DETECTED');

    // 4. Because reuse was detected, the newest rotated token is also invalidated!
    const postReuseRes = await fetch(`${baseUrl}/api/v1/auth/refresh`, {
      method: 'POST',
      headers: {
        Cookie: `envirotrust_refresh=${refreshCookie2}; envirotrust_csrf=${csrfToken}`,
        'X-CSRF-Token': csrfToken,
        Origin: 'http://localhost:5173',
      },
    });
    assert.equal(postReuseRes.status, 401);
  });

  it('7. Logout revokes active refresh session and clears cookie', async () => {
    // 1. Login
    const loginRes = await fetch(`${baseUrl}/api/v1/auth/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        email: 'operator@envirotrust.local',
        password: 'DemoPassword123!',
      }),
    });
    const loginBody = (await loginRes.json()) as any;
    const csrfToken = loginBody.csrfToken;
    const setCookies = loginRes.headers.getSetCookie ? loginRes.headers.getSetCookie() : [loginRes.headers.get('set-cookie') || ''];
    let refreshCookie: string | undefined;
    for (const sc of setCookies) {
      const match = sc.match(/envirotrust_refresh=([^;]+)/);
      if (match && match[1]) refreshCookie = match[1];
    }
    assert.ok(refreshCookie);

    // 2. Logout with Cookie + CSRF + Origin
    const logoutRes = await fetch(`${baseUrl}/api/v1/auth/logout`, {
      method: 'POST',
      headers: {
        Cookie: `envirotrust_refresh=${refreshCookie}; envirotrust_csrf=${csrfToken}`,
        'X-CSRF-Token': csrfToken,
        Origin: 'http://localhost:5173',
      },
    });
    assert.equal(logoutRes.status, 200);

    // 3. Attempting to refresh with logged-out cookie fails
    const refreshRes = await fetch(`${baseUrl}/api/v1/auth/refresh`, {
      method: 'POST',
      headers: {
        Cookie: `envirotrust_refresh=${refreshCookie}; envirotrust_csrf=${csrfToken}`,
        'X-CSRF-Token': csrfToken,
        Origin: 'http://localhost:5173',
      },
    });
    assert.equal(refreshRes.status, 401);
  });

  it('8. GET /api/v1/auth/me returns authenticated user profile with valid Bearer token', async () => {
    const loginRes = await fetch(`${baseUrl}/api/v1/auth/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        email: 'operator@envirotrust.local',
        password: 'DemoPassword123!',
      }),
    });
    const loginBody = (await loginRes.json()) as any;
    const accessToken = loginBody.accessToken;

    const meRes = await fetch(`${baseUrl}/api/v1/auth/me`, {
      headers: { Authorization: `Bearer ${accessToken}` },
    });
    assert.equal(meRes.status, 200);
    const meBody = (await meRes.json()) as any;
    assert.equal(meBody.success, true);
    assert.equal(meBody.user.email, 'operator@envirotrust.local');
    assert.equal(meBody.user.role, 'FACTORY_OPERATOR');
    assert.ok(meBody.user.sites.includes('PLANT-001'));
  });

  it('9. GET /api/v1/auth/me rejects missing or forged tokens (401)', async () => {
    // No token
    const noTokenRes = await fetch(`${baseUrl}/api/v1/auth/me`);
    assert.equal(noTokenRes.status, 401);

    // Forged token
    const forgedRes = await fetch(`${baseUrl}/api/v1/auth/me`, {
      headers: { Authorization: 'Bearer forged.jwt.token.here' },
    });
    assert.equal(forgedRes.status, 401);
    const body = (await forgedRes.json()) as any;
    assert.equal(body.code, 'INVALID_TOKEN');
  });

  it('10. Authentication audit events are recorded in database without sensitive secrets', async () => {
    const pool = getDbPool();
    const auditRes = await pool.query<{ action: string; actor_email: string; details: any }>(
      `SELECT action, actor_email, details
       FROM auth_audit_events
       WHERE actor_email = 'operator@envirotrust.local'
       ORDER BY occurred_at DESC
       LIMIT 5`
    );

    assert.ok(auditRes.rows.length > 0);
    const actions = auditRes.rows.map((r) => r.action);
    assert.ok(actions.includes('LOGIN_SUCCESS'));

    // Check no passwords or tokens were recorded in audit details
    for (const row of auditRes.rows) {
      assert.equal(row.details['password'], undefined);
      assert.equal(row.details['refreshToken'], undefined);
      assert.equal(row.details['accessToken'], undefined);
    }
  });
});
