import { describe, it, before, after } from 'node:test';
import assert from 'node:assert/strict';
import type { Server } from 'node:http';
import type { AddressInfo } from 'node:net';
import { createApiApp } from '../src/app.js';
import { getDbPool, closeDbPool } from '../src/db/connection.js';
import { runMigrations } from '../src/db/migrate.js';
import { seedDemoUsers } from '../src/db/seed.js';
import jwt from 'jsonwebtoken';

describe('Primary API — Internal Service Introspection Endpoints', () => {
  let server: Server;
  let baseUrl: string;
  let operatorToken: string;
  let operatorSid: string;
  let operatorSub: string;
  const internalSecret = 'internal_auth_introspection_secret_34567';

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

    // Login operator to obtain an active session
    const loginRes = await fetch(`${baseUrl}/api/v1/auth/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email: 'operator@envirotrust.local', password: 'DemoPassword123!' }),
    });
    const loginData = (await loginRes.json()) as any;
    operatorToken = loginData.accessToken;
    const decoded = jwt.decode(operatorToken) as any;
    operatorSid = decoded.sid;
    operatorSub = decoded.sub;
  });

  after(async () => {
    await new Promise<void>((resolve) => {
      server.close(() => resolve());
    });
    await closeDbPool();
  });

  it('1. Rejects unauthenticated introspection request without service credential (401)', async () => {
    const res = await fetch(`${baseUrl}/api/v1/internal/auth/introspect`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ sid: operatorSid, sub: operatorSub }),
    });
    assert.equal(res.status, 401);
    const body = (await res.json()) as any;
    assert.equal(body.code, 'UNAUTHORIZED_SERVICE');
  });

  it('2. Rejects request with invalid or spoofed service credential (401)', async () => {
    const res = await fetch(`${baseUrl}/api/v1/internal/auth/introspect`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-Internal-Secret': 'invalid-spoofed-secret-key-12345',
      },
      body: JSON.stringify({ sid: operatorSid, sub: operatorSub }),
    });
    assert.equal(res.status, 401);
    const body = (await res.json()) as any;
    assert.equal(body.code, 'UNAUTHORIZED_SERVICE');
  });

  it('3. Rejects request missing sid or sub with 400', async () => {
    const res = await fetch(`${baseUrl}/api/v1/internal/auth/introspect`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-Internal-Secret': internalSecret,
      },
      body: JSON.stringify({ sid: operatorSid }),
    });
    assert.equal(res.status, 400);
    const body = (await res.json()) as any;
    assert.equal(body.code, 'MISSING_REQUIRED_FIELDS');
  });

  it('4. Successfully introspects valid active human session (200 with active: true)', async () => {
    const res = await fetch(`${baseUrl}/api/v1/internal/auth/introspect`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-Internal-Secret': internalSecret,
      },
      body: JSON.stringify({ sid: operatorSid, sub: operatorSub }),
    });
    assert.equal(res.status, 200);
    const body = (await res.json()) as any;
    assert.equal(body.active, true);
    assert.equal(body.user.id, operatorSub);
    assert.equal(body.user.email, 'operator@envirotrust.local');
    assert.equal(body.user.role, 'FACTORY_OPERATOR');
    assert.ok(body.user.sites.includes('PLANT-001'));
    // Never returns passwords or secrets
    assert.equal(body.user.password, undefined);
    assert.equal(body.user.passwordHash, undefined);
  });

  it('5. Returns active: false when session has been revoked', async () => {
    // Revoke the session
    const pool = getDbPool();
    await pool.query('UPDATE authentication_sessions SET revoked_at = now() WHERE id = $1', [operatorSid]);

    const res = await fetch(`${baseUrl}/api/v1/internal/auth/introspect`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-Internal-Secret': internalSecret,
      },
      body: JSON.stringify({ sid: operatorSid, sub: operatorSub }),
    });
    assert.equal(res.status, 200);
    const body = (await res.json()) as any;
    assert.equal(body.active, false);
    assert.equal(body.code, 'SESSION_REVOKED');
  });
});

