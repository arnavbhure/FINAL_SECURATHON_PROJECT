import { describe, it, before, after } from 'node:test';
import assert from 'node:assert/strict';
import type { Server } from 'node:http';
import type { AddressInfo } from 'node:net';
import { createApiApp } from '../src/app.js';
import { getDbPool, closeDbPool } from '../src/db/connection.js';
import { runMigrations } from '../src/db/migrate.js';
import { seedDemoUsers } from '../src/db/seed.js';

describe('Primary API — Monitoring Read Endpoints & RBAC Isolation Tests', () => {
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

    async function login(email: string): Promise<string> {
      const res = await fetch(`${baseUrl}/api/v1/auth/login`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email, password: 'DemoPassword123!' }),
      });
      const data = (await res.json()) as { accessToken: string };
      return data.accessToken;
    }

    adminToken = await login('admin@envirotrust.local');
    operatorToken = await login('operator@envirotrust.local');
    auditorToken = await login('auditor@envirotrust.local');
  });

  after(async () => {
    await new Promise<void>((resolve) => {
      server.close(() => resolve());
    });
    await closeDbPool();
  });

  it('1. GET /api/v1/monitoring/sites: Returns all sites for PLATFORM_ADMIN, and assigned sites for operator', async () => {
    // Admin request
    const adminRes = await fetch(`${baseUrl}/api/v1/monitoring/sites`, {
      headers: { Authorization: `Bearer ${adminToken}` },
    });
    assert.equal(adminRes.status, 200);
    const adminData = (await adminRes.json()) as { success: boolean; count: number; sites: any[] };
    assert.equal(adminData.success, true);
    assert(adminData.count >= 2, 'Admin must see both PLANT-001 and PLANT-002');

    // Operator request (assigned only to PLANT-001)
    const opRes = await fetch(`${baseUrl}/api/v1/monitoring/sites`, {
      headers: { Authorization: `Bearer ${operatorToken}` },
    });
    assert.equal(opRes.status, 200);
    const opData = (await opRes.json()) as { success: boolean; count: number; sites: any[] };
    assert.equal(opData.success, true);
    assert.equal(opData.count, 1);
    assert.equal(opData.sites[0]?.siteCode, 'PLANT-001');
  });

  it('2. GET /api/v1/monitoring/overview: Returns aggregated statistics and latest readings', async () => {
    const res = await fetch(`${baseUrl}/api/v1/monitoring/overview?siteId=PLANT-001`, {
      headers: { Authorization: `Bearer ${operatorToken}` },
    });
    assert.equal(res.status, 200);
    const data = (await res.json()) as {
      success: boolean;
      siteFilter: string;
      metrics: { totalReadings: number; anomalySummary: Record<string, number>; latestReadings: any[] };
    };
    assert.equal(data.success, true);
    assert.equal(data.siteFilter, 'PLANT-001');
    assert(typeof data.metrics.totalReadings === 'number');
    assert(Array.isArray(data.metrics.latestReadings));
  });

  it('3. GET /api/v1/monitoring/readings: Returns filterable telemetry readings', async () => {
    const res = await fetch(`${baseUrl}/api/v1/monitoring/readings?siteId=PLANT-001&parameter=COD&limit=10`, {
      headers: { Authorization: `Bearer ${operatorToken}` },
    });
    assert.equal(res.status, 200);
    const data = (await res.json()) as { success: boolean; count: number; readings: any[] };
    assert.equal(data.success, true);
    assert(Array.isArray(data.readings));
    for (const r of data.readings) {
      assert.equal(r.parameter, 'COD');
      assert.equal(r.siteId, 'PLANT-001');
      assert(r.measuredAt !== null);
      assert(r.receivedAt !== null);
    }
  });

  it('4. RBAC & Site Isolation: Operator is FORBIDDEN (403) from querying PLANT-002 readings or overview', async () => {
    // 4a. Overview on unauthorized site
    const ovRes = await fetch(`${baseUrl}/api/v1/monitoring/overview?siteId=PLANT-002`, {
      headers: { Authorization: `Bearer ${operatorToken}` },
    });
    assert.equal(ovRes.status, 403);
    const ovBody = (await ovRes.json()) as { code: string };
    assert.equal(ovBody.code, 'FORBIDDEN_SITE_ACCESS');

    // 4b. Readings on unauthorized site
    const readRes = await fetch(`${baseUrl}/api/v1/monitoring/readings?siteId=PLANT-002`, {
      headers: { Authorization: `Bearer ${operatorToken}` },
    });
    assert.equal(readRes.status, 403);
    const readBody = (await readRes.json()) as { code: string };
    assert.equal(readBody.code, 'FORBIDDEN_SITE_ACCESS');
  });

  it('5. Auditor Read-Only Access: Auditor assigned to PLANT-001 can query readings and overview', async () => {
    const res = await fetch(`${baseUrl}/api/v1/monitoring/readings?siteId=PLANT-001&limit=5`, {
      headers: { Authorization: `Bearer ${auditorToken}` },
    });
    assert.equal(res.status, 200);
    const data = (await res.json()) as { success: boolean };
    assert.equal(data.success, true);
  });

  it('6. GET /api/v1/monitoring/security-events & audit-events: Returns event logs for authorized users', async () => {
    const secRes = await fetch(`${baseUrl}/api/v1/monitoring/security-events?siteId=PLANT-001&limit=10`, {
      headers: { Authorization: `Bearer ${adminToken}` },
    });
    assert.equal(secRes.status, 200);
    const secData = (await secRes.json()) as { success: boolean; events: any[] };
    assert.equal(secData.success, true);
    assert(Array.isArray(secData.events));

    const auditRes = await fetch(`${baseUrl}/api/v1/monitoring/audit-events?siteId=PLANT-001&limit=10`, {
      headers: { Authorization: `Bearer ${adminToken}` },
    });
    assert.equal(auditRes.status, 200);
    const auditData = (await auditRes.json()) as { success: boolean; events: any[] };
    assert.equal(auditData.success, true);
    assert(Array.isArray(auditData.events));
  });
});

