import { describe, it, before, after } from 'node:test';
import assert from 'node:assert/strict';
import type { Server } from 'node:http';
import type { AddressInfo } from 'node:net';
import { createApiApp } from '../src/app.js';
import { getDbPool, closeDbPool } from '../src/db/connection.js';
import { runMigrations } from '../src/db/migrate.js';
import { seedDemoUsers } from '../src/db/seed.js';

describe('Primary API — Administrative User Management & Governance Tests', () => {
  let server: Server;
  let baseUrl: string;
  let adminToken: string;
  let operatorToken: string;
  let auditorToken: string;

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

    async function getToken(email: string): Promise<string> {
      const res = await fetch(`${baseUrl}/api/v1/auth/login`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email, password: 'DemoPassword123!' }),
      });
      const data = (await res.json()) as any;
      return data.accessToken;
    }

    adminToken = await getToken('admin@envirotrust.local');
    operatorToken = await getToken('operator@envirotrust.local');
    auditorToken = await getToken('auditor@envirotrust.local');
  });

  after(async () => {
    await new Promise<void>((resolve) => {
      server.close(() => resolve());
    });
    await closeDbPool();
  });

  it('1. Non-admin roles (FACTORY_OPERATOR, REGULATOR_AUDITOR) are FORBIDDEN from admin endpoints (403)', async () => {
    const opRes = await fetch(`${baseUrl}/api/v1/admin/users`, {
      headers: { Authorization: `Bearer ${operatorToken}` },
    });
    assert.equal(opRes.status, 403);
    const opBody = (await opRes.json()) as any;
    assert.equal(opBody.code, 'FORBIDDEN_ROLE');

    const audRes = await fetch(`${baseUrl}/api/v1/admin/users`, {
      headers: { Authorization: `Bearer ${auditorToken}` },
    });
    assert.equal(audRes.status, 403);
    const audBody = (await audRes.json()) as any;
    assert.equal(audBody.code, 'FORBIDDEN_ROLE');
  });

  it('2. PLATFORM_ADMIN can list all human users and their assigned site scopes', async () => {
    const res = await fetch(`${baseUrl}/api/v1/admin/users`, {
      headers: { Authorization: `Bearer ${adminToken}` },
    });
    assert.equal(res.status, 200);
    const body = (await res.json()) as any;
    assert.equal(body.success, true);
    assert.ok(Array.isArray(body.users));
    assert.ok(body.users.length >= 3);

    // Passwords must NEVER be present in the user list response
    for (const u of body.users) {
      assert.equal(u.passwordHash, undefined);
      assert.equal(u.password, undefined);
    }
  });

  it('3. PLATFORM_ADMIN can create a new user with password hashing and site memberships', async () => {
    const newUserEmail = `new-operator-${Date.now()}@envirotrust.local`;
    const res = await fetch(`${baseUrl}/api/v1/admin/users`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${adminToken}`,
      },
      body: JSON.stringify({
        fullName: 'New Junior Operator',
        email: newUserEmail,
        password: 'SecurePassword123!',
        role: 'FACTORY_OPERATOR',
        sites: ['PLANT-001'],
      }),
    });

    assert.equal(res.status, 201);
    const body = (await res.json()) as any;
    assert.equal(body.success, true);
    assert.equal(body.user.email, newUserEmail);
    assert.equal(body.user.role, 'FACTORY_OPERATOR');
    assert.ok(body.user.sites.includes('PLANT-001'));
    assert.equal(body.user.passwordHash, undefined);

    // Verify user can now log in with the created credentials
    const loginRes = await fetch(`${baseUrl}/api/v1/auth/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        email: newUserEmail,
        password: 'SecurePassword123!',
      }),
    });
    assert.equal(loginRes.status, 200);
  });

  it('4. Last active administrator protection: cannot disable or demote the sole/last PLATFORM_ADMIN', async () => {
    const pool = getDbPool();
    const adminRes = await pool.query<{ id: string }>(
      "SELECT id FROM users WHERE email = 'admin@envirotrust.local'"
    );
    const adminUserId = adminRes.rows[0]?.id;
    assert.ok(adminUserId);

    // Attempt 1: Disable the last active admin
    const disableRes = await fetch(`${baseUrl}/api/v1/admin/users/${adminUserId}/status`, {
      method: 'PATCH',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${adminToken}`,
      },
      body: JSON.stringify({ status: 'DISABLED' }),
    });
    assert.equal(disableRes.status, 400);
    const disableBody = (await disableRes.json()) as any;
    assert.equal(disableBody.code, 'CANNOT_DISABLE_LAST_ADMIN');

    // Attempt 2: Demote the last active admin to FACTORY_OPERATOR
    const demoteRes = await fetch(`${baseUrl}/api/v1/admin/users/${adminUserId}/role`, {
      method: 'PATCH',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${adminToken}`,
      },
      body: JSON.stringify({ role: 'FACTORY_OPERATOR' }),
    });
    assert.equal(demoteRes.status, 400);
    const demoteBody = (await demoteRes.json()) as any;
    assert.equal(demoteBody.code, 'CANNOT_DEMOTE_LAST_ADMIN');
  });

  it('5. PLATFORM_ADMIN can assign and revoke site memberships', async () => {
    const pool = getDbPool();
    const opRes = await pool.query<{ id: string }>(
      "SELECT id FROM users WHERE email = 'operator@envirotrust.local'"
    );
    const opId = opRes.rows[0]?.id;
    assert.ok(opId);

    // Assign PLANT-002
    const addSiteRes = await fetch(`${baseUrl}/api/v1/admin/users/${opId}/sites`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${adminToken}`,
      },
      body: JSON.stringify({ siteCode: 'PLANT-002' }),
    });
    assert.equal(addSiteRes.status, 200);
    const addBody = (await addSiteRes.json()) as any;
    assert.ok(addBody.user.sites.includes('PLANT-002'));

    // Revoke PLANT-002
    const removeSiteRes = await fetch(`${baseUrl}/api/v1/admin/users/${opId}/sites/PLANT-002`, {
      method: 'DELETE',
      headers: { Authorization: `Bearer ${adminToken}` },
    });
    assert.equal(removeSiteRes.status, 200);
    const removeBody = (await removeSiteRes.json()) as any;
    assert.ok(!removeBody.user.sites.includes('PLANT-002'));
  });

  it('6. Administrative mutations are durably recorded in auth_audit_events without secrets', async () => {
    const res = await fetch(`${baseUrl}/api/v1/admin/audit-events?limit=20`, {
      headers: { Authorization: `Bearer ${adminToken}` },
    });
    assert.equal(res.status, 200);
    const body = (await res.json()) as any;
    assert.equal(body.success, true);
    assert.ok(Array.isArray(body.events));

    const actions = body.events.map((e: any) => e.action);
    assert.ok(actions.includes('USER_CREATED'));
    assert.ok(actions.includes('SITE_MEMBERSHIP_CHANGED'));

    // Check secrets are redacted
    for (const evt of body.events) {
      assert.equal(evt.details['password'], undefined);
      assert.equal(evt.details['refreshToken'], undefined);
      assert.equal(evt.details['accessToken'], undefined);
    }
  });
});
