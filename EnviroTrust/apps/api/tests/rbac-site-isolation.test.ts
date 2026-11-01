import { describe, it, before, after } from 'node:test';
import assert from 'node:assert/strict';
import type { Server } from 'node:http';
import type { AddressInfo } from 'node:net';
import { createApiApp } from '../src/app.js';
import { getDbPool, closeDbPool } from '../src/db/connection.js';
import { runMigrations } from '../src/db/migrate.js';
import { seedDemoUsers } from '../src/db/seed.js';

describe('Primary API — RBAC & Multi-Site Isolation Tests', () => {
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

    // Acquire access tokens for all 3 demo roles
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

  it('1. Unauthenticated requests to protected endpoints are rejected with 401', async () => {
    // Sensor health list
    const resList = await fetch(`${baseUrl}/api/v1/sensors/health`);
    assert.equal(resList.status, 401);

    // Individual sensor health
    const resSingle = await fetch(`${baseUrl}/api/v1/sensors/PH-OUT-001/health`);
    assert.equal(resSingle.status, 401);

    // Heartbeat history
    const resHistory = await fetch(`${baseUrl}/api/v1/heartbeats/history?sensorId=PH-OUT-001`);
    assert.equal(resHistory.status, 401);
  });

  it('2. PLATFORM_ADMIN has global visibility across all sites (PLANT-001 and PLANT-002)', async () => {
    const res = await fetch(`${baseUrl}/api/v1/sensors/health`, {
      headers: { Authorization: `Bearer ${adminToken}` },
    });
    assert.equal(res.status, 200);
    const body = (await res.json()) as any;
    assert.equal(body.success, true);

    const siteCodes = new Set(body.sensors.map((s: any) => s.siteCode));
    assert.ok(siteCodes.has('PLANT-001'), 'Admin should see PLANT-001');
    assert.ok(siteCodes.has('PLANT-002'), 'Admin should see PLANT-002');

    // Admin can access individual sensors on both sites
    const resP1 = await fetch(`${baseUrl}/api/v1/sensors/PH-OUT-001/health`, {
      headers: { Authorization: `Bearer ${adminToken}` },
    });
    assert.equal(resP1.status, 200);

    const resP2 = await fetch(`${baseUrl}/api/v1/sensors/PH-OUT-002/health`, {
      headers: { Authorization: `Bearer ${adminToken}` },
    });
    assert.equal(resP2.status, 200);
  });

  it('3. FACTORY_OPERATOR assigned to PLANT-001 can access PLANT-001 data', async () => {
    const res = await fetch(`${baseUrl}/api/v1/sensors/PH-OUT-001/health`, {
      headers: { Authorization: `Bearer ${operatorToken}` },
    });
    assert.equal(res.status, 200);
    const body = (await res.json()) as any;
    assert.equal(body.success, true);
    assert.equal(body.sensor.sensorCode, 'PH-OUT-001');
    assert.equal(body.sensor.siteCode, 'PLANT-001');
  });

  it('4. FACTORY_OPERATOR assigned to PLANT-001 is FORBIDDEN (403) from accessing PLANT-002 sensor', async () => {
    const res = await fetch(`${baseUrl}/api/v1/sensors/PH-OUT-002/health`, {
      headers: { Authorization: `Bearer ${operatorToken}` },
    });
    assert.equal(res.status, 403);
    const body = (await res.json()) as any;
    assert.equal(body.success, false);
    assert.equal(body.code, 'FORBIDDEN_SITE_ACCESS');
  });

  it('5. FACTORY_OPERATOR cannot bypass isolation via query parameter (?siteId=PLANT-002)', async () => {
    const res = await fetch(`${baseUrl}/api/v1/sensors/health?siteId=PLANT-002`, {
      headers: { Authorization: `Bearer ${operatorToken}` },
    });
    assert.equal(res.status, 403);
    const body = (await res.json()) as any;
    assert.equal(body.code, 'FORBIDDEN_SITE_ACCESS');
  });

  it('6. FACTORY_OPERATOR cannot bypass isolation via forged X-Site-Id header', async () => {
    const res = await fetch(`${baseUrl}/api/v1/sensors/health`, {
      headers: {
        Authorization: `Bearer ${operatorToken}`,
        'x-site-id': 'PLANT-002',
      },
    });
    assert.equal(res.status, 403);
    const body = (await res.json()) as any;
    assert.equal(body.code, 'FORBIDDEN_SITE_ACCESS');
  });

  it('7. FACTORY_OPERATOR cannot access heartbeat history for an unassigned site sensor', async () => {
    const res = await fetch(`${baseUrl}/api/v1/heartbeats/history?sensorId=PH-OUT-002`, {
      headers: { Authorization: `Bearer ${operatorToken}` },
    });
    assert.equal(res.status, 403);
    const body = (await res.json()) as any;
    assert.equal(body.code, 'FORBIDDEN_SITE_ACCESS');
  });

  it('8. REGULATOR_AUDITOR assigned to PLANT-001 can access PLANT-001 but is rejected from PLANT-002', async () => {
    // Access allowed site PLANT-001
    const resOk = await fetch(`${baseUrl}/api/v1/sensors/PH-OUT-001/health`, {
      headers: { Authorization: `Bearer ${auditorToken}` },
    });
    assert.equal(resOk.status, 200);

    // Access unassigned site PLANT-002
    const resForbidden = await fetch(`${baseUrl}/api/v1/sensors/PH-OUT-002/health`, {
      headers: { Authorization: `Bearer ${auditorToken}` },
    });
    assert.equal(resForbidden.status, 403);
    const body = (await resForbidden.json()) as any;
    assert.equal(body.code, 'FORBIDDEN_SITE_ACCESS');
  });

  it('9. Machine Ingestion Endpoints remain decoupled from human JWT authentication', async () => {
    // Machine ingestion endpoints (telemetry & heartbeats) must NOT require human JWTs
    // Missing body -> 400 INVALID_SCHEMA, NOT 401 UNAUTHORIZED
    const resTelemetry = await fetch(`${baseUrl}/api/v1/ingestion/readings`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({}),
    });
    assert.equal(resTelemetry.status, 400);
    const bodyTel = (await resTelemetry.json()) as any;
    assert.equal(bodyTel.code, 'INVALID_SCHEMA');

    const resHeartbeat = await fetch(`${baseUrl}/api/v1/ingestion/heartbeats`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({}),
    });
    assert.equal(resHeartbeat.status, 400);
    const bodyHb = (await resHeartbeat.json()) as any;
    assert.equal(bodyHb.code, 'INVALID_SCHEMA');
  });
});
