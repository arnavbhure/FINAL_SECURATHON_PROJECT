import { describe, it, before, after } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import crypto from 'node:crypto';
import type { Server } from 'node:http';
import type { AddressInfo } from 'node:net';
import pg from 'pg';
import type { Pool } from 'pg';
import { createApiApp } from '../src/app.js';
import { getDbPool, closeDbPool } from '../src/db/connection.js';
import { runMigrations } from '../src/db/migrate.js';
import { seedDemoUsers } from '../src/db/seed.js';
import { loadApiEnvironment } from '../src/env.js';
import { SecurityEventRepository } from '../src/repositories/security-event.repository.js';
import { AlertService } from '../src/services/alert.service.js';
import { MlClient } from '../src/services/ml-client.js';
import {
  AttackLabEngine,
  AttackLabRunRepository,
  classifyCompromisedKey,
  classifyRejection,
  classifyTargetHost,
  evaluateSafety,
  isAttackLabEnabled,
  loadAttackLabConfig,
  restoreDemoEnvironment,
  type AttackLabConfig,
  type HttpExchange,
} from '../src/attack-lab/index.js';

function ex(target: 'PRIMARY' | 'WITNESS', status: number | null, code: string | null): HttpExchange {
  return {
    target,
    method: 'POST',
    endpoint: '/x',
    status,
    ok: status !== null && status >= 200 && status < 300,
    code,
    message: null,
    requestId: null,
    body: null,
    networkError: status === null ? 'ECONNREFUSED' : null,
    durationMs: 1,
  };
}

async function listen(app: http.RequestListener | import('express').Express): Promise<{ server: Server; url: string }> {
  return new Promise((resolve) => {
    const server = http.createServer(app as http.RequestListener).listen(0, '127.0.0.1', () => {
      resolve({ server, url: `http://127.0.0.1:${(server.address() as AddressInfo).port}` });
    });
  });
}

async function login(baseUrl: string, email: string): Promise<string> {
  const res = await fetch(`${baseUrl}/api/v1/auth/login`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ email, password: process.env['DEMO_USER_PASSWORD'] || 'DemoPassword123!' }),
  });
  return ((await res.json()) as { accessToken: string }).accessToken;
}

describe('Attack Simulation Lab — classification (unit)', () => {
  it('PREVENTED only when both services reject with the mechanism under test and nothing is stored', () => {
    const r = classifyRejection({
      expectedCode: 'INVALID_SIGNATURE',
      primary: ex('PRIMARY', 401, 'INVALID_SIGNATURE'),
      witness: ex('WITNESS', 401, 'INVALID_SIGNATURE'),
      primaryTrustedRecords: 0,
      witnessTrustedRecordFound: false,
    });
    assert.equal(r.outcome, 'PREVENTED');
    assert.equal(r.expectationMet, true);
  });

  it('a rejection by a different mechanism is INCONCLUSIVE, not DETECTED/PREVENTED', () => {
    const r = classifyRejection({
      expectedCode: 'INVALID_SIGNATURE',
      primary: ex('PRIMARY', 400, 'INVALID_SCHEMA'),
      witness: ex('WITNESS', 401, 'INVALID_SIGNATURE'),
      primaryTrustedRecords: 0,
      witnessTrustedRecordFound: false,
    });
    assert.equal(r.outcome, 'INCONCLUSIVE');
    assert.equal(r.expectationMet, false);
  });

  it('acceptance by either service (or a stored record) is ACCEPTED', () => {
    const r = classifyRejection({
      expectedCode: 'REPLAYED_SEQUENCE',
      primary: ex('PRIMARY', 409, 'REPLAYED_SEQUENCE'),
      witness: ex('WITNESS', 201, null),
      primaryTrustedRecords: 0,
      witnessTrustedRecordFound: true,
    });
    assert.equal(r.outcome, 'ACCEPTED');
    assert.equal(r.expectationMet, false);
  });

  it('an unreachable service yields SERVICE_UNAVAILABLE', () => {
    const r = classifyRejection({
      expectedCode: 'UNKNOWN_KEY',
      primary: ex('PRIMARY', 401, 'UNKNOWN_KEY'),
      witness: ex('WITNESS', null, null),
      primaryTrustedRecords: 0,
      witnessTrustedRecordFound: false,
    });
    assert.equal(r.outcome, 'SERVICE_UNAVAILABLE');
  });

  it('compromised-key verdict depends only on the actual ML result', () => {
    const base = { primaryAccepted: true, witnessAccepted: true };
    assert.equal(classifyCompromisedKey({ ...base, ml: { status: 'SUSPICIOUS', detail: '' } }).outcome, 'SUSPICIOUS');
    const notDetected = classifyCompromisedKey({ ...base, ml: { status: 'CONSISTENT', detail: '' } });
    assert.equal(notDetected.outcome, 'ACCEPTED');
    assert.equal(notDetected.classification, 'COMPROMISED_KEY_NOT_DETECTED');
    assert.equal(notDetected.expectationMet, true, 'non-detection is an honest, expected possibility');
    const off = classifyCompromisedKey({ ...base, ml: { status: 'ML_NOT_ENABLED', detail: 'off' } });
    assert.equal(off.outcome, 'PENDING');
    assert.equal(off.expectationMet, false);
    assert.equal(classifyCompromisedKey({ ...base, ml: { status: 'ML_UNAVAILABLE', detail: '' } }).outcome, 'PENDING');
    assert.equal(
      classifyCompromisedKey({ primaryAccepted: false, witnessAccepted: true, ml: { status: 'SUSPICIOUS', detail: '' } }).outcome,
      'INCONCLUSIVE'
    );
    const nonSpecific = classifyCompromisedKey({ ...base, ml: { status: 'SUSPICIOUS', detail: '' }, control: { evaluated: 20, flagged: 20 } });
    assert.equal(nonSpecific.outcome, 'INCONCLUSIVE', 'a flag the model also gives genuine readings is not a detection');
    assert.equal(nonSpecific.classification, 'ML_FLAG_NOT_SPECIFIC');
    const specific = classifyCompromisedKey({ ...base, ml: { status: 'SUSPICIOUS', detail: '' }, control: { evaluated: 20, flagged: 1 } });
    assert.equal(specific.outcome, 'SUSPICIOUS');
  });

  it('only local targets are allowed (private LAN only when explicitly enabled)', () => {
    assert.equal(classifyTargetHost('http://localhost:4000', false).ok, true);
    assert.equal(classifyTargetHost('http://127.0.0.1:4001', false).ok, true);
    assert.equal(classifyTargetHost('http://192.168.1.20:4000', false).ok, false);
    assert.equal(classifyTargetHost('http://192.168.1.20:4000', true).ok, true);
    assert.equal(classifyTargetHost('https://example.com', true).ok, false);
  });
});

describe('Attack Simulation Lab — safety gates, RBAC and evidence store (integration, local primary DB)', () => {
  const previousEnabled = process.env['ATTACK_LAB_ENABLED'];
  const pool = getDbPool();
  let witnessPool: Pool;
  let baseConfig: AttackLabConfig;
  let server: Server;
  let baseUrl: string;
  let engine: AttackLabEngine;
  let adminToken: string;
  let operatorToken: string;
  let auditorToken: string;

  before(async () => {
    await runMigrations(pool);
    await seedDemoUsers();
    process.env['ATTACK_LAB_ENABLED'] = 'true';
    const env = loadApiEnvironment();
    baseConfig = loadAttackLabConfig(env);
    witnessPool = new pg.Pool({ connectionString: baseConfig.witnessDatabaseUrl, max: 2 });
    engine = new AttackLabEngine(baseConfig, pool, witnessPool);
    await pool.query("UPDATE attack_lab_runs SET status = 'ABANDONED', finished_at = now() WHERE status = 'RUNNING'");
    const appInstance = createApiApp({ env: { ...env, DEMO_MODE: true }, attackLabEngine: engine });
    ({ server, url: baseUrl } = await listen(appInstance.app));
    adminToken = await login(baseUrl, 'admin@envirotrust.local');
    operatorToken = await login(baseUrl, 'operator@envirotrust.local');
    auditorToken = await login(baseUrl, 'auditor@envirotrust.local');
  });

  after(async () => {
    if (previousEnabled === undefined) delete process.env['ATTACK_LAB_ENABLED'];
    else process.env['ATTACK_LAB_ENABLED'] = previousEnabled;
    await new Promise<void>((r) => server.close(() => r()));
    await witnessPool.end();
    await closeDbPool();
  });

  it('demo-mode / lab-flag / production gates decide whether routes exist at all', async () => {
    assert.equal(isAttackLabEnabled({ DEMO_MODE: true, NODE_ENV: 'development' }), true);
    assert.equal(isAttackLabEnabled({ DEMO_MODE: false, NODE_ENV: 'development' }), false);
    assert.equal(isAttackLabEnabled({ DEMO_MODE: true, NODE_ENV: 'production' }), false);

    const disabled = createApiApp({ env: { ...loadApiEnvironment(), DEMO_MODE: false } });
    const { server: s2, url } = await listen(disabled.app);
    try {
      const res = await fetch(`${url}/api/v1/demo/attack-lab/scenarios/telemetry-tampering/runs`, {
        method: 'POST',
        headers: { Authorization: `Bearer ${adminToken}`, 'Content-Type': 'application/json' },
        body: '{}',
      });
      assert.equal(res.status, 404, 'routes must not exist when DEMO_MODE=false');
      assert.equal(disabled.attackLabEngine, undefined);
    } finally {
      await new Promise<void>((r) => s2.close(() => r()));
    }
  });

  it('safety evaluation refuses a misconfigured environment (wrong DB identity, production, public target)', async () => {
    const good = await evaluateSafety(baseConfig, pool, witnessPool);
    assert.equal(good.ok, true, JSON.stringify(good.checks.filter((c) => !c.ok)));

    const wrongDb = await evaluateSafety({ ...baseConfig, expectedPrimaryDbName: 'envirotrust_production' }, pool, witnessPool);
    assert.equal(wrongDb.ok, false);
    assert.equal(wrongDb.checks.find((c) => c.id === 'primary-db-identity')?.ok, false);

    const swapped = await evaluateSafety(baseConfig, pool, pool);
    assert.equal(swapped.ok, false, 'pointing the witness pool at the primary DB must fail identity checks');

    const prod = await evaluateSafety({ ...baseConfig, nodeEnv: 'production' }, pool, witnessPool);
    assert.equal(prod.checks.find((c) => c.id === 'not-production')?.ok, false);

    const publicTarget = await evaluateSafety({ ...baseConfig, primaryBaseUrl: 'https://example.com' }, pool, witnessPool);
    assert.equal(publicTarget.checks.find((c) => c.id === 'primary-target')?.ok, false);
  });

  it('server refuses to run when safety checks fail (503, nothing recorded)', async () => {
    const before = await pool.query<{ n: string }>('SELECT count(*)::text AS n FROM attack_lab_runs');
    const badEngine = new AttackLabEngine({ ...baseConfig, expectedWitnessDbName: 'not-the-witness' }, pool, witnessPool);
    await assert.rejects(
      () => badEngine.startRun('telemetry-tampering', { userId: null, label: 'test', source: 'TEST' }),
      (err: { code?: string; httpStatus?: number }) => err.code === 'ATTACK_LAB_MISCONFIGURED' && err.httpStatus === 503
    );
    const after = await pool.query<{ n: string }>('SELECT count(*)::text AS n FROM attack_lab_runs');
    assert.equal(after.rows[0]?.n, before.rows[0]?.n);
  });

  it('read access for every role; execution only for allowlisted PLATFORM_ADMIN', async () => {
    for (const token of [adminToken, operatorToken, auditorToken]) {
      const res = await fetch(`${baseUrl}/api/v1/demo/attack-lab/scenarios`, { headers: { Authorization: `Bearer ${token}` } });
      assert.equal(res.status, 200);
    }
    const auditorStatus = (await (await fetch(`${baseUrl}/api/v1/demo/attack-lab/scenarios`, { headers: { Authorization: `Bearer ${auditorToken}` } })).json()) as { canExecute: boolean; scenarios: unknown[] };
    assert.equal(auditorStatus.canExecute, false);
    assert.equal(auditorStatus.scenarios.length, 9);

    for (const token of [operatorToken, auditorToken]) {
      const res = await fetch(`${baseUrl}/api/v1/demo/attack-lab/scenarios/telemetry-tampering/runs`, {
        method: 'POST',
        headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' },
        body: '{}',
      });
      assert.equal(res.status, 403);
    }

    const unauth = await fetch(`${baseUrl}/api/v1/demo/attack-lab/scenarios`);
    assert.equal(unauth.status, 401);
  });

  it('a PLATFORM_ADMIN that is not on the demo allowlist cannot trigger attacks', async () => {
    const restricted = new AttackLabEngine({ ...baseConfig, authorizedAdminEmails: ['someone-else@envirotrust.local'] }, pool, witnessPool);
    const app = createApiApp({ env: { ...loadApiEnvironment(), DEMO_MODE: true }, attackLabEngine: restricted });
    const { server: s3, url } = await listen(app.app);
    try {
      const res = await fetch(`${url}/api/v1/demo/attack-lab/scenarios/telemetry-tampering/runs`, {
        method: 'POST',
        headers: { Authorization: `Bearer ${adminToken}`, 'Content-Type': 'application/json' },
        body: '{}',
      });
      assert.equal(res.status, 403);
      assert.equal(((await res.json()) as { code: string }).code, 'NOT_AUTHORIZED');
    } finally {
      await new Promise<void>((r) => s3.close(() => r()));
    }
  });

  it('only fixed scenario IDs are accepted; no payloads, URLs or scripts from the client', async () => {
    const post = (path: string, body: unknown) =>
      fetch(`${baseUrl}/api/v1/demo/attack-lab${path}`, {
        method: 'POST',
        headers: { Authorization: `Bearer ${adminToken}`, 'Content-Type': 'application/json' },
        body: JSON.stringify(body),
      });
    const unknown = await post('/scenarios/drop-tables/runs', {});
    assert.equal(unknown.status, 404);
    const injected = await post('/scenarios/telemetry-tampering/runs', { targetUrl: 'http://evil.example', payload: {} });
    assert.equal(injected.status, 400);
    assert.equal(((await injected.json()) as { code: string }).code, 'INVALID_RUN_REQUEST');
    const unconfirmed = await post('/scenarios/heartbeat-interruption/runs', {});
    assert.equal(unconfirmed.status, 400);
    assert.equal(((await unconfirmed.json()) as { code: string }).code, 'CONFIRMATION_REQUIRED');
  });

  it('run evidence is site-scoped for operators/auditors and only one run may execute at a time', async () => {
    const repo = new AttackLabRunRepository(pool);
    const foreignRun = await repo.createRun('telemetry-tampering', { userId: null, label: 'test', source: 'TEST' }, 'PLANT-002');
    try {
      await assert.rejects(
        () => repo.createRun('unknown-signing-key', { userId: null, label: 'test', source: 'TEST' }, 'PLANT-001'),
        (err: { code?: string }) => err.code === 'RUN_IN_PROGRESS'
      );
      const opDetail = await fetch(`${baseUrl}/api/v1/demo/attack-lab/runs/${foreignRun}`, { headers: { Authorization: `Bearer ${operatorToken}` } });
      assert.equal(opDetail.status, 404, 'operator assigned to PLANT-001 must not read PLANT-002 run evidence');
      const opList = (await (await fetch(`${baseUrl}/api/v1/demo/attack-lab/runs?limit=100`, { headers: { Authorization: `Bearer ${operatorToken}` } })).json()) as { runs: Array<{ id: string; siteCode: string }> };
      assert.equal(opList.runs.some((r) => r.id === foreignRun), false);
      assert.equal(opList.runs.every((r) => r.siteCode === 'PLANT-001'), true);
      const adminDetail = await fetch(`${baseUrl}/api/v1/demo/attack-lab/runs/${foreignRun}`, { headers: { Authorization: `Bearer ${adminToken}` } });
      assert.equal(adminDetail.status, 200);
    } finally {
      await repo.failRun(foreignRun, [], 'test fixture');
    }
  });

  it('rejected attempts raise one deduplicated SECURITY_EVENT alert per sensor and reason', async () => {
    const repo = new SecurityEventRepository(pool);
    const sensor = await pool.query<{ id: string; site_id: string }>(
      `SELECT s.id, st.site_id FROM sensors s JOIN monitoring_stations st ON st.id = s.station_id WHERE s.sensor_code = 'TSS-OUT-001'`
    );
    const { id: sensorId, site_id: siteId } = sensor.rows[0]!;
    await pool.query(
      `UPDATE alerts SET status = 'RESOLVED', resolved_at = now(), resolution_note = 'test reset'
       WHERE alert_type = 'SECURITY_EVENT' AND sensor_id = $1 AND status <> 'RESOLVED'`,
      [sensorId]
    );
    const e1 = await repo.recordSecurityEvent({ siteId, sensorId, eventType: 'TEST_SIGNATURE', reasonCode: 'INVALID_SIGNATURE', metadata: { requestId: crypto.randomUUID() } });
    const e2 = await repo.recordSecurityEvent({ siteId, sensorId, eventType: 'TEST_SIGNATURE', reasonCode: 'INVALID_SIGNATURE', metadata: { requestId: crypto.randomUUID() } });
    const alerts = await pool.query<{ id: string; severity: string; metadata: Record<string, unknown> }>(
      `SELECT id, severity, metadata FROM alerts
       WHERE alert_type = 'SECURITY_EVENT' AND sensor_id = $1 AND status = 'OPEN' AND metadata->>'reasonCode' = 'INVALID_SIGNATURE'`,
      [sensorId]
    );
    assert.equal(alerts.rows.length, 1, 'repeated rejections must not create duplicate alerts');
    assert.equal(alerts.rows[0]!.metadata['occurrenceCount'], 2);
    assert.deepEqual((alerts.rows[0]!.metadata['recentSecurityEventIds'] as string[]).slice(-2), [e1, e2]);
    assert.equal(alerts.rows[0]!.severity, 'HIGH');
    const tamper = await pool.query<{ n: string }>(
      `SELECT count(*)::text AS n FROM alerts WHERE alert_type = 'PHYSICAL_TAMPER' AND source_event_id = ANY($1::uuid[])`,
      [[e1, e2]]
    );
    assert.equal(tamper.rows[0]?.n, '0', 'security rejections are never classified as physical tampering');

    // Unknown key: no registered identity, so the alert is scoped to the (unauthenticated) claimed sensor.
    const e3 = await repo.recordSecurityEvent({ eventType: 'TEST_UNKNOWN', reasonCode: 'UNKNOWN_KEY', metadata: { sensorId: 'TSS-OUT-001', requestId: crypto.randomUUID() } });
    const unknownAlert = await pool.query<{ metadata: Record<string, unknown> }>(
      `SELECT metadata FROM alerts WHERE alert_type = 'SECURITY_EVENT' AND metadata->'recentSecurityEventIds' ? $1`,
      [e3]
    );
    assert.equal(unknownAlert.rows[0]?.metadata['scope'], 'CLAIMED_IDENTITY_UNAUTHENTICATED');
    await pool.query(
      `UPDATE alerts SET status = 'RESOLVED', resolved_at = now(), resolution_note = 'test cleanup'
       WHERE alert_type = 'SECURITY_EVENT' AND sensor_id = $1 AND status <> 'RESOLVED'`,
      [sensorId]
    );
  });

  it('availability evaluator ignores sensors that are not in service (demo identities while idle)', async () => {
    await pool.query("UPDATE sensors SET status = 'INACTIVE' WHERE is_demo_identity = TRUE");
    const demo = await pool.query<{ id: string }>('SELECT id FROM sensors WHERE is_demo_identity = TRUE');
    if (demo.rows.length === 0) return; // demo identities not provisioned in this database
    const ids = demo.rows.map((r) => r.id);
    const before = await pool.query<{ n: string }>(`SELECT count(*)::text AS n FROM alerts WHERE sensor_id = ANY($1::uuid[])`, [ids]);
    await new AlertService(pool).evaluateSensorAvailabilityAndSyncAlerts();
    const after = await pool.query<{ n: string }>(`SELECT count(*)::text AS n FROM alerts WHERE sensor_id = ANY($1::uuid[])`, [ids]);
    assert.equal(after.rows[0]?.n, before.rows[0]?.n);
  });

  it('demo restore refuses without confirmation or with failed safety, and never deletes evidence', async () => {
    await assert.rejects(() => restoreDemoEnvironment(engine, { confirm: false }), (e: { code?: string }) => e.code === 'CONFIRMATION_REQUIRED');
    const unsafe = new AttackLabEngine({ ...baseConfig, enabled: false }, pool, witnessPool);
    await assert.rejects(() => restoreDemoEnvironment(unsafe, { confirm: true }), (e: { code?: string }) => e.code === 'ATTACK_LAB_MISCONFIGURED');

    const tables = ['telemetry_readings', 'audit_events', 'security_events', 'alerts', 'attack_lab_runs'];
    const counts = async () =>
      Promise.all(tables.map(async (t) => Number((await pool.query<{ n: string }>(`SELECT count(*)::text AS n FROM ${t}`)).rows[0]?.n)));
    const witnessCount = async () => Number((await witnessPool.query<{ n: string }>('SELECT count(*)::text AS n FROM witness_events')).rows[0]?.n);
    const beforeCounts = await counts();
    const beforeWitness = await witnessCount();
    const { actions } = await restoreDemoEnvironment(engine, { confirm: true });
    assert.ok(actions.length >= 3);
    const afterCounts = await counts();
    tables.forEach((t, i) => assert.ok(afterCounts[i]! >= beforeCounts[i]!, `${t} rows must never be deleted by restore`));
    assert.ok((await witnessCount()) >= beforeWitness);
  });
});

describe('ML client — raw Isolation Forest output is preserved (isolated test with a MOCK ML server)', () => {
  it('returns the actual anomaly score/threshold from the service alongside the adapted result', async () => {
    // MOCK: stands in for the FastAPI service only in this isolated test; never reported as a live demonstration.
    const mock: http.RequestListener = (req, res) => {
      let body = '';
      req.on('data', (c) => (body += c));
      req.on('end', () => {
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(
          JSON.stringify({
            reading_id: 'r-1',
            anomaly_score: 0.1234,
            anomaly_threshold: 0.0694,
            is_anomaly: true,
            isolation_forest_flag: true,
            detection_sources: ['isolation_forest'],
            status: 'SUSPICIOUS',
            model_version: 'mock-model-v0',
            model_mode: 'MOCK',
            evaluated_at_utc: new Date().toISOString(),
          })
        );
      });
    };
    const { server, url } = await listen(mock);
    try {
      const client = new MlClient({ baseUrl: url, timeoutMs: 2000 });
      const result = await client.analyzeCod({
        readingId: 'r-1',
        siteId: 'PLANT-001',
        stationId: 'ETP-OUTLET-001',
        sensorId: 'LAB-COD-902',
        actualCod: 18.4,
        measuredAt: new Date().toISOString(),
        contextVerified: true,
        context: { productionRate: 400, wastewaterFlow: 11000, treatmentDose: 50, energyConsumption: 900, operatingMode: 'NORMAL' },
        recentCodReadings: [],
      });
      assert.equal(result.status, 'SUSPICIOUS');
      assert.equal(result.rawModelOutput?.anomalyScore, 0.1234);
      assert.equal(result.rawModelOutput?.anomalyThreshold, 0.0694);
      assert.equal(result.rawModelOutput?.isAnomaly, true);
      assert.equal(result.rawModelOutput?.modelVersion, 'mock-model-v0');
      assert.deepEqual(result.rawModelOutput?.detectionSources, ['isolation_forest']);
    } finally {
      await new Promise<void>((r) => server.close(() => r()));
    }
  });
});
