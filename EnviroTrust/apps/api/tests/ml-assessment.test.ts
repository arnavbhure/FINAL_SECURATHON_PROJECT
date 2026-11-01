import { describe, it, before, after } from 'node:test';
import assert from 'node:assert/strict';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import type { Server } from 'node:http';
import http from 'node:http';
import type { AddressInfo } from 'node:net';
import crypto from 'node:crypto';
import { createApiApp } from '../src/app.js';
import { getDbPool, closeDbPool } from '../src/db/connection.js';
import { runMigrations } from '../src/db/migrate.js';
import { seedDemoUsers } from '../src/db/seed.js';
import { SensorDevice } from '@envirotrust/sensor-simulator';
import { OpsContextSimulator } from '@envirotrust/ops-simulator';
import { registerKeysFromManifest } from '../src/services/key-registry.service.js';
import { MlClient } from '../src/services/ml-client.js';
import { MlAssessmentService } from '../src/services/ml-assessment.service.js';
import { loadApiEnvironment } from '../src/env.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const rootDir = path.resolve(__dirname, '../../..');

describe('Primary API — ML Assessment Integration, Synchronization, Reliability & RBAC Tests', () => {
  let primaryServer: Server;
  let primaryBaseUrl: string;
  let mockFastApiServer: http.Server;
  let mockFastApiPort: number;

  let codDevice: SensorDevice;
  let opsSimulator: OpsContextSimulator;

  let adminToken: string;
  let operatorToken: string;

  let mockFastApiStatus = 200;
  let mockFastApiBody: unknown;

  let mlService: MlAssessmentService;

  before(async () => {
    const pool = getDbPool();
    await runMigrations(pool);
    await seedDemoUsers();

    // Clean up any residual test records from previous suites
    await pool.query('DELETE FROM anomaly_results');
    await pool.query('DELETE FROM ml_assessment_jobs');
    await pool.query('DELETE FROM operations_context_readings');

    const manifestPath = path.resolve(rootDir, 'local-secrets/provisioning/public-key-manifest.json');
    await registerKeysFromManifest(manifestPath, pool);

    // 1. Start mock FastAPI HTTP server simulating teammate's Python service
    mockFastApiServer = http.createServer(async (req, res) => {
      let bodyStr = '';
      for await (const chunk of req) {
        bodyStr += chunk;
      }

      if (req.url === '/ml/v1/health' && req.method === 'GET') {
        res.writeHead(mockFastApiStatus, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ status: 'ok', ready: true, modelVersion: 'rf-cod-v1.0' }));
        return;
      }

      if (req.url === '/ml/v1/analyze/cod' && req.method === 'POST') {
        res.writeHead(mockFastApiStatus, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify(mockFastApiBody));
        return;
      }

      res.writeHead(404, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: 'Not found' }));
    });

    await new Promise<void>((resolve) => {
      mockFastApiServer.listen(0, '127.0.0.1', () => {
        const addr = mockFastApiServer.address() as AddressInfo;
        mockFastApiPort = addr.port;
        resolve();
      });
    });

    // 2. Configure Primary API with ML_ENABLED=true pointing to mock FastAPI
    const env = loadApiEnvironment();
    env.ML_ENABLED = true;
    env.ML_BASE_URL = `http://127.0.0.1:${mockFastApiPort}`;
    env.ML_TIMEOUT_MS = 3000;
    env.ML_SERVICE_TOKEN = 'test-ml-secret-token';
    env.ML_CONTEXT_WAIT_DEADLINE_SECONDS = 60;

    const customMlClient = new MlClient({
      baseUrl: env.ML_BASE_URL,
      timeoutMs: env.ML_TIMEOUT_MS,
      serviceToken: env.ML_SERVICE_TOKEN,
    });

    mlService = new MlAssessmentService(pool, env, customMlClient);

    const { app } = createApiApp({ mlAssessmentService: mlService, env });
    await new Promise<void>((resolve) => {
      primaryServer = app.listen(0, () => {
        const addr = primaryServer.address() as AddressInfo;
        primaryBaseUrl = `http://127.0.0.1:${addr.port}`;
        resolve();
      });
    });

    // 3. Acquire auth tokens
    async function getToken(email: string): Promise<string> {
      const res = await fetch(`${primaryBaseUrl}/api/v1/auth/login`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email, password: 'DemoPassword123!' }),
      });
      const data = (await res.json()) as { accessToken: string };
      return data.accessToken;
    }

    adminToken = await getToken('admin@envirotrust.local');
    operatorToken = await getToken('operator@envirotrust.local');

    // 4. Initialize sensor and ops simulators
    const codKeyDir = path.resolve(rootDir, 'local-secrets/sensor-keys/COD-OUT-001');
    const opsKeyDir = path.resolve(rootDir, 'local-secrets/ops-keys/OPS-001');

    codDevice = new SensorDevice({
      sensorId: 'COD-OUT-001',
      keyDir: codKeyDir,
      bootId: `BOOT-ML-${crypto.randomUUID().slice(0, 8)}`,
      initialTelemetrySequence: 1000,
    });

    const opsCursor = await pool.query<{ last_sequence_no: string }>(
      "SELECT last_sequence_no FROM operations_sequence_cursors WHERE source_id = 'OPS-001'"
    );
    const startOpsSeq = opsCursor.rows[0] ? Number(opsCursor.rows[0].last_sequence_no) + 1 : 1;

    opsSimulator = new OpsContextSimulator({
      keyDir: opsKeyDir,
      initialSequence: startOpsSeq,
    });
  });

  after(async () => {
    await new Promise<void>((resolve) => {
      primaryServer.close(() => resolve());
    });
    await new Promise<void>((resolve) => {
      mockFastApiServer.close(() => resolve());
    });
    await closeDbPool();
  });

  it('1. Telemetry Ingestion Decoupling: Ingesting verified COD reading enqueues ML assessment job even if ML service is down', async () => {
    const readingEnvelope = codDevice.generateReading({
      overrideValue: '78.50',
      measuredAt: new Date().toISOString(),
    });

    const res = await fetch(`${primaryBaseUrl}/api/v1/ingestion/readings`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(readingEnvelope),
    });

    assert.equal(res.status, 201);
    const body = (await res.json()) as { success: boolean; readingId: string; messageId: string };
    assert.equal(body.success, true);

    const pool = getDbPool();
    const jobRes = await pool.query<{ status: string; attempts: number }>(
      'SELECT status, attempts FROM ml_assessment_jobs WHERE reading_id = $1',
      [body.readingId]
    );

    assert.equal(jobRes.rows.length, 1);
    assert.equal(jobRes.rows[0]?.status, 'PENDING');
    assert.equal(jobRes.rows[0]?.attempts, 0);
  });

  it('2. Ingestion Idempotency: Duplicate telemetry submission does NOT create a second job', async () => {
    const readingEnvelope = codDevice.generateReading({
      overrideValue: '82.00',
      measuredAt: new Date().toISOString(),
    });

    const res1 = await fetch(`${primaryBaseUrl}/api/v1/ingestion/readings`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(readingEnvelope),
    });
    assert.equal(res1.status, 201);
    const body1 = (await res1.json()) as { readingId: string };

    const res2 = await fetch(`${primaryBaseUrl}/api/v1/ingestion/readings`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(readingEnvelope),
    });
    assert.equal(res2.status, 200);

    const pool = getDbPool();
    const jobRes = await pool.query<{ count: string }>(
      'SELECT count(*) as count FROM ml_assessment_jobs WHERE reading_id = $1',
      [body1.readingId]
    );

    assert.equal(Number(jobRes.rows[0]?.count), 1);
  });

  it('3. Context Arrival Race Condition (Fix): When COD arrives before OPS context, job stays PENDING and is not prematurely finalized', async () => {
    // Reading arrives now, but OPS context has NOT arrived yet
    const readingEnvelope = codDevice.generateReading({
      overrideValue: '88.50',
      measuredAt: new Date().toISOString(),
    });

    const res = await fetch(`${primaryBaseUrl}/api/v1/ingestion/readings`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(readingEnvelope),
    });
    assert.equal(res.status, 201);
    const { readingId } = (await res.json()) as { readingId: string };

    // Worker attempts cycle while context is absent
    const cycle = await mlService.runWorkerCycle(10, 'test-worker');
    assert(cycle.retried >= 1, 'Job should be retried rather than finalized as INSUFFICIENT_CONTEXT');

    const pool = getDbPool();
    const jobRes = await pool.query<{ status: string; last_error: string }>(
      'SELECT status, last_error FROM ml_assessment_jobs WHERE reading_id = $1',
      [readingId]
    );
    assert.equal(jobRes.rows[0]?.status, 'PENDING');
    assert.match(jobRes.rows[0]?.last_error || '', /WAITING_FOR_CONTEXT/);

    // No anomaly_results record should exist yet
    const assessRes = await pool.query(
      'SELECT id FROM anomaly_results WHERE reading_id = $1',
      [readingId]
    );
    assert.equal(assessRes.rows.length, 0, 'Must not finalize assessment before deadline');
  });

  it('4. Asynchronous Context Arrival: Ingesting matching OPS context immediately awakens waiting COD job and completes assessment', async () => {
    const pool = getDbPool();

    // 1. Find the waiting job from test 3
    const waitingJob = await pool.query<{ reading_id: string }>(
      "SELECT reading_id FROM ml_assessment_jobs WHERE status = 'PENDING' AND last_error LIKE '%WAITING_FOR_CONTEXT%' LIMIT 1"
    );
    assert(waitingJob.rows.length > 0);
    const readingId = waitingJob.rows[0]!.reading_id;

    const readingRes = await pool.query<{ measured_at: Date; message_id: string }>(
      'SELECT measured_at, message_id FROM telemetry_readings WHERE id = $1',
      [readingId]
    );
    const measuredAt = readingRes.rows[0]!.measured_at;
    const messageId = readingRes.rows[0]!.message_id;

    // 2. OPS context arrives now, covering the measurement interval
    const intervalStart = new Date(measuredAt.getTime() - 10000).toISOString();
    const intervalEnd = new Date(measuredAt.getTime() + 10000).toISOString();

    const opsEnvelope = opsSimulator.generateContext({
      overrides: {
        intervalStart,
        intervalEnd,
        productionRate: 450,
        wastewaterFlow: 12000,
        treatmentDose: 35,
        energyConsumption: 520,
        operatingMode: 'NORMAL',
      },
    });

    const opsRes = await fetch(`${primaryBaseUrl}/api/v1/ingestion/operations-context`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(opsEnvelope),
    });
    assert.equal(opsRes.status, 201);

    // Verify the waiting job was awakened (next_run_at reset to <= now())
    const awakenedJob = await pool.query<{ next_run_at: Date }>(
      'SELECT next_run_at FROM ml_assessment_jobs WHERE reading_id = $1',
      [readingId]
    );
    assert(awakenedJob.rows[0]!.next_run_at.getTime() <= Date.now() + 100);

    // 3. Configure mock FastAPI to return CONSISTENT
    mockFastApiStatus = 200;
    mockFastApiBody = {
      readingId: messageId,
      status: 'CONSISTENT',
      anomalyType: null,
      actualCod: 88.5,
      predictedCod: 87.9,
      absoluteResidual: 0.6,
      residualThreshold: 14.5,
      modelVersion: 'rf-cod-v1.0',
      reasons: ['Process conditions consistent with normal model behavior'],
      evaluatedAt: new Date().toISOString(),
    };

    // 4. Run worker cycle: job should now succeed immediately!
    const cycle = await mlService.runWorkerCycle(10, 'test-worker');
    assert(cycle.completed >= 1);

    const completedJob = await pool.query<{ status: string }>(
      'SELECT status FROM ml_assessment_jobs WHERE reading_id = $1',
      [readingId]
    );
    assert.equal(completedJob.rows[0]?.status, 'COMPLETED');

    const assessRes = await pool.query<{ status: string; actual_value: string }>(
      'SELECT status, actual_value FROM anomaly_results WHERE reading_id = $1',
      [readingId]
    );
    assert.equal(assessRes.rows[0]?.status, 'CONSISTENT');
  });

  it('5. Bounded Wait Deadline: When context NEVER arrives and deadline expires, job finalizes as INSUFFICIENT_CONTEXT', async () => {
    const pool = getDbPool();
    // Reading 1 hour in the past, where NO operations context has ever been emitted
    const readingTime = new Date(Date.now() - 3600 * 1000).toISOString();
    const readingEnvelope = codDevice.generateReading({
      overrideValue: '95.00',
      measuredAt: readingTime,
    });

    const res = await fetch(`${primaryBaseUrl}/api/v1/ingestion/readings`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(readingEnvelope),
    });
    assert.equal(res.status, 201);
    const { readingId } = (await res.json()) as { readingId: string };

    // Simulate deadline expiry by advancing job created_at past the 60s deadline
    await pool.query(
      "UPDATE ml_assessment_jobs SET created_at = now() - INTERVAL '120 seconds' WHERE reading_id = $1",
      [readingId]
    );

    // Run cycle
    const cycle = await mlService.runWorkerCycle(10, 'test-worker');
    assert(cycle.insufficientContext >= 1);

    const jobRes = await pool.query<{ status: string }>(
      'SELECT status FROM ml_assessment_jobs WHERE reading_id = $1',
      [readingId]
    );
    assert.equal(jobRes.rows[0]?.status, 'INSUFFICIENT_CONTEXT');

    const assessRes = await pool.query<{ status: string; processing_status: string; reasons: string[] }>(
      'SELECT status, processing_status, reasons FROM anomaly_results WHERE reading_id = $1',
      [readingId]
    );
    assert.equal(assessRes.rows[0]?.status, 'NOT_EVALUATED');
    assert.equal(assessRes.rows[0]?.processing_status, 'INSUFFICIENT_CONTEXT');
    assert.match(assessRes.rows[0]?.reasons[0] || '', /deadline/);
  });

  it('6. Time Window Alignment: Future operational context is strictly rejected', async () => {
    const pool = getDbPool();
    const t0 = Date.now() - 7200 * 1000; // 2 hours ago
    const readingTime = new Date(t0);
    const futureContextStart = new Date(t0 + 10000); // starts 10s after reading
    const futureContextEnd = new Date(t0 + 20000);

    // Ingest future ops context
    const opsEnvelope = opsSimulator.generateContext({
      overrides: {
        intervalStart: futureContextStart.toISOString(),
        intervalEnd: futureContextEnd.toISOString(),
        productionRate: 500,
        wastewaterFlow: 15000,
        treatmentDose: 40,
        energyConsumption: 600,
        operatingMode: 'NORMAL',
      },
    });

    const opsRes = await fetch(`${primaryBaseUrl}/api/v1/ingestion/operations-context`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(opsEnvelope),
    });
    assert.equal(opsRes.status, 201);

    // Ingest earlier reading
    const readingEnvelope = codDevice.generateReading({
      overrideValue: '75.00',
      measuredAt: readingTime.toISOString(),
    });

    const readRes = await fetch(`${primaryBaseUrl}/api/v1/ingestion/readings`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(readingEnvelope),
    });
    const { readingId } = (await readRes.json()) as { readingId: string };

    // Simulate deadline expiry so it evaluates rather than retries
    await pool.query(
      "UPDATE ml_assessment_jobs SET created_at = now() - INTERVAL '120 seconds' WHERE reading_id = $1",
      [readingId]
    );

    // Run cycle
    await mlService.runWorkerCycle(10, 'test-worker');

    // Must be INSUFFICIENT_CONTEXT because future context cannot be used
    const jobRes = await pool.query<{ status: string }>(
      'SELECT status FROM ml_assessment_jobs WHERE reading_id = $1',
      [readingId]
    );
    assert.equal(jobRes.rows[0]?.status, 'INSUFFICIENT_CONTEXT');
  });

  it('7. Staleness Bound: Stale operational context (> 900s old) is strictly rejected', async () => {
    const pool = getDbPool();
    const t0 = Date.now() - 5400 * 1000; // 1.5 hours ago
    const readingTime = new Date(t0);
    // Context from 1000s before reading (exceeds 900s limit)
    const staleContextStart = new Date(t0 - 1500 * 1000).toISOString();
    const staleContextEnd = new Date(t0 - 1000 * 1000).toISOString();

    const opsEnvelope = opsSimulator.generateContext({
      overrides: {
        intervalStart: staleContextStart,
        intervalEnd: staleContextEnd,
        productionRate: 400,
        wastewaterFlow: 10000,
        treatmentDose: 30,
        energyConsumption: 500,
        operatingMode: 'NORMAL',
      },
    });

    await fetch(`${primaryBaseUrl}/api/v1/ingestion/operations-context`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(opsEnvelope),
    });

    const readingEnvelope = codDevice.generateReading({
      overrideValue: '80.00',
      measuredAt: readingTime.toISOString(),
    });

    const readRes = await fetch(`${primaryBaseUrl}/api/v1/ingestion/readings`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(readingEnvelope),
    });
    const { readingId } = (await readRes.json()) as { readingId: string };

    await pool.query(
      "UPDATE ml_assessment_jobs SET created_at = now() - INTERVAL '120 seconds' WHERE reading_id = $1",
      [readingId]
    );

    await mlService.runWorkerCycle(10, 'test-worker');

    const jobRes = await pool.query<{ status: string }>(
      'SELECT status FROM ml_assessment_jobs WHERE reading_id = $1',
      [readingId]
    );
    assert.equal(jobRes.rows[0]?.status, 'INSUFFICIENT_CONTEXT');
  });

  it('8. Site Isolation: Operations context from PLANT-002 is NEVER matched for PLANT-001 reading', async () => {
    const pool = getDbPool();
    const t0 = Date.now() - 9000 * 1000; // 2.5 hours ago
    const intervalStart = new Date(t0 - 10000).toISOString();
    const intervalEnd = new Date(t0 + 10000).toISOString();
    const readingTime = new Date(t0).toISOString();

    // Context for PLANT-002
    const site2Res = await pool.query<{ id: string }>('SELECT id FROM sites WHERE site_code = $1', ['PLANT-002']);
    assert(site2Res.rows[0]);
    const site2Id = site2Res.rows[0].id;

    const station2Res = await pool.query<{ id: string }>(
      'SELECT id FROM monitoring_stations WHERE site_id = $1 LIMIT 1',
      [site2Id]
    );

    const opsKeyRes = await pool.query<{ key_id: string }>(
      'SELECT key_id FROM operations_source_keys WHERE site_id = $1 LIMIT 1',
      [site2Id]
    );

    if (station2Res.rows[0] && opsKeyRes.rows[0]) {
      await pool.query(
        `INSERT INTO operations_context_readings (
           message_id, source_id, key_id, site_id, station_id, sequence_no,
           interval_start, interval_end, production_rate, wastewater_flow,
           treatment_dose, energy_consumption, operating_mode,
           original_payload, signature_base64, payload_hash, verification_status
         )
         VALUES ($1, $2, $3, $4, $5, 9999, $6, $7, 900, 20000, 50, 700, 'HIGH_LOAD', '{}'::jsonb, 'sig', 'hash', 'VALID')`,
        [
          crypto.randomUUID(),
          'OPS-001',
          opsKeyRes.rows[0].key_id,
          site2Id,
          station2Res.rows[0].id,
          intervalStart,
          intervalEnd,
        ]
      );
    }

    // Ingest reading for PLANT-001
    const readingEnvelope = codDevice.generateReading({
      overrideValue: '80.00',
      measuredAt: readingTime,
    });

    const readRes = await fetch(`${primaryBaseUrl}/api/v1/ingestion/readings`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(readingEnvelope),
    });
    const { readingId } = (await readRes.json()) as { readingId: string };

    await pool.query(
      "UPDATE ml_assessment_jobs SET created_at = now() - INTERVAL '120 seconds' WHERE reading_id = $1",
      [readingId]
    );

    await mlService.runWorkerCycle(10, 'test-worker');

    const jobRes = await pool.query<{ status: string }>(
      'SELECT status FROM ml_assessment_jobs WHERE reading_id = $1',
      [readingId]
    );
    assert.equal(jobRes.rows[0]?.status, 'INSUFFICIENT_CONTEXT', 'PLANT-002 context must not match PLANT-001 reading');
  });

  it('9. Deterministic Disambiguation: Overlapping contexts deterministically select highest sequence number', async () => {
    const pool = getDbPool();
    const siteRes = await pool.query<{ id: string }>('SELECT id FROM sites WHERE site_code = $1', ['PLANT-001']);
    const siteId = siteRes.rows[0]!.id;

    const measuredAt = new Date(Date.now() - 10800 * 1000); // 3 hours ago
    const intervalStart = new Date(measuredAt.getTime() - 5000);
    const intervalEnd = new Date(measuredAt.getTime() + 5000);

    // Ingest two overlapping contexts for same site/time window with different sequence numbers
    const stationRes = await pool.query<{ id: string }>(
      'SELECT id FROM monitoring_stations WHERE site_id = $1 LIMIT 1',
      [siteId]
    );
    const keyRes = await pool.query<{ key_id: string }>(
      'SELECT key_id FROM operations_source_keys WHERE site_id = $1 LIMIT 1',
      [siteId]
    );

    const seqA = 8888;
    const seqB = 8889; // Newer sequence

    await pool.query(
      `INSERT INTO operations_context_readings (
         message_id, source_id, key_id, site_id, station_id, sequence_no,
         interval_start, interval_end, production_rate, wastewater_flow,
         treatment_dose, energy_consumption, operating_mode,
         original_payload, signature_base64, payload_hash, verification_status
       )
       VALUES ($1, 'OPS-001', $2, $3, $4, $5, $6, $7, 300, 10000, 20, 400, 'NORMAL', '{}'::jsonb, 'sig', 'hash', 'VALID')`,
      [crypto.randomUUID(), keyRes.rows[0]!.key_id, siteId, stationRes.rows[0]!.id, seqA, intervalStart, intervalEnd]
    );

    await pool.query(
      `INSERT INTO operations_context_readings (
         message_id, source_id, key_id, site_id, station_id, sequence_no,
         interval_start, interval_end, production_rate, wastewater_flow,
         treatment_dose, energy_consumption, operating_mode,
         original_payload, signature_base64, payload_hash, verification_status
       )
       VALUES ($1, 'OPS-001', $2, $3, $4, $5, $6, $7, 600, 15000, 40, 700, 'HIGH_LOAD', '{}'::jsonb, 'sig', 'hash', 'VALID')`,
      [crypto.randomUUID(), keyRes.rows[0]!.key_id, siteId, stationRes.rows[0]!.id, seqB, intervalStart, intervalEnd]
    );

    // Query matching context
    const selected = await mlService.getAssessmentRepo().findMatchingOpsContext(siteId, measuredAt);
    assert(selected !== null);
    assert.equal(selected.operating_mode, 'HIGH_LOAD', 'Must deterministically select newest sequence');
    assert.equal(Number(selected.production_rate), 600);
  });

  it('10. Application Restart Recovery: Worker safely resumes processing after service restart', async () => {
    const readingEnvelope = codDevice.generateReading({
      overrideValue: '77.00',
      measuredAt: new Date(Date.now() - 12600 * 1000).toISOString(), // 3.5 hours ago
    });

    const readRes = await fetch(`${primaryBaseUrl}/api/v1/ingestion/readings`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(readingEnvelope),
    });
    const { readingId } = (await readRes.json()) as { readingId: string };

    // Stop existing worker, simulate restart by creating a new service instance
    const pool = getDbPool();
    const env = loadApiEnvironment();
    env.ML_ENABLED = true;

    const restartedService = new MlAssessmentService(pool, env, mlService.getMlClient());

    // Advance deadline to evaluate
    await pool.query(
      "UPDATE ml_assessment_jobs SET created_at = now() - INTERVAL '120 seconds' WHERE reading_id = $1",
      [readingId]
    );

    const cycle = await restartedService.runWorkerCycle(10, 'restarted-worker');
    assert(cycle.insufficientContext >= 1);

    const jobRes = await pool.query<{ status: string }>(
      'SELECT status FROM ml_assessment_jobs WHERE reading_id = $1',
      [readingId]
    );
    assert.equal(jobRes.rows[0]?.status, 'INSUFFICIENT_CONTEXT');
  });

  it('11. Successful ML Inference: When verified matching context exists, worker calls FastAPI, evaluates CONSISTENT and stores result', async () => {
    const now = Date.now();
    const intervalStart = new Date(now - 15000).toISOString();
    const measuredAt = new Date(now - 5000).toISOString();
    const intervalEnd = new Date(now).toISOString();

    const opsEnvelope = opsSimulator.generateContext({
      overrides: {
        intervalStart,
        intervalEnd,
        productionRate: 420,
        wastewaterFlow: 11000,
        treatmentDose: 30,
        energyConsumption: 500,
        operatingMode: 'NORMAL',
      },
    });

    const opsRes = await fetch(`${primaryBaseUrl}/api/v1/ingestion/operations-context`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(opsEnvelope),
    });
    assert.equal(opsRes.status, 201);
    const { readingId: opsReadingId } = (await opsRes.json()) as { readingId: string };

    const readingEnvelope = codDevice.generateReading({
      overrideValue: '84.00',
      measuredAt,
    });

    const readRes = await fetch(`${primaryBaseUrl}/api/v1/ingestion/readings`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(readingEnvelope),
    });
    assert.equal(readRes.status, 201);
    const { readingId, messageId } = (await readRes.json()) as { readingId: string; messageId: string };

    mockFastApiStatus = 200;
    mockFastApiBody = {
      readingId: messageId,
      status: 'CONSISTENT',
      anomalyType: null,
      actualCod: 84.0,
      predictedCod: 83.2,
      absoluteResidual: 0.8,
      residualThreshold: 14.5,
      modelVersion: 'rf-cod-v1.0',
      reasons: ['Process conditions match learned model behavior'],
      evaluatedAt: new Date().toISOString(),
    };

    const cycle = await mlService.runWorkerCycle(10, 'test-worker');
    assert.equal(cycle.completed, 1);

    const pool = getDbPool();
    const jobRes = await pool.query<{ status: string }>(
      'SELECT status FROM ml_assessment_jobs WHERE reading_id = $1',
      [readingId]
    );
    assert.equal(jobRes.rows[0]?.status, 'COMPLETED');

    const assessRes = await pool.query<{
      status: string;
      actual_value: string;
      predicted_value: string;
      residual: string;
      threshold: string;
      severity: string;
      context_id: string;
    }>('SELECT * FROM anomaly_results WHERE reading_id = $1', [readingId]);

    assert.equal(assessRes.rows.length, 1);
    const assess = assessRes.rows[0]!;
    assert.equal(assess.status, 'CONSISTENT');
    assert.equal(Number(assess.actual_value), 84.0);
    assert.equal(Number(assess.predicted_value), 83.2);
    assert.equal(Number(assess.residual), 0.8);
    assert.equal(Number(assess.threshold), 14.5);
    assert.equal(assess.severity, 'NONE');
    assert.equal(assess.context_id, opsReadingId);
  });

  it('12. Anomaly Detection: Injected mismatch returns SUSPICIOUS and marks severity HIGH/CRITICAL', async () => {
    const now = Date.now();
    const intervalStart = new Date(now - 12000).toISOString();
    const measuredAt = new Date(now - 4000).toISOString();
    const intervalEnd = new Date(now).toISOString();

    const opsEnvelope = opsSimulator.generateContext({
      overrides: {
        intervalStart,
        intervalEnd,
        productionRate: 800,
        wastewaterFlow: 25000,
        treatmentDose: 10,
        energyConsumption: 950,
        operatingMode: 'HIGH_LOAD',
      },
    });

    await fetch(`${primaryBaseUrl}/api/v1/ingestion/operations-context`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(opsEnvelope),
    });

    const readingEnvelope = codDevice.generateReading({
      overrideValue: '22.00',
      measuredAt,
    });

    const readRes = await fetch(`${primaryBaseUrl}/api/v1/ingestion/readings`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(readingEnvelope),
    });
    const { readingId, messageId } = (await readRes.json()) as { readingId: string; messageId: string };

    mockFastApiStatus = 200;
    mockFastApiBody = {
      readingId: messageId,
      status: 'SUSPICIOUS',
      anomalyType: 'PROCESS_CONTEXT_MISMATCH',
      actualCod: 22.0,
      predictedCod: 98.4,
      absoluteResidual: 76.4,
      residualThreshold: 15.0,
      modelVersion: 'rf-cod-v1.0',
      reasons: ['Actual COD 22.00 is significantly below expected value 98.40 given operating context'],
      evaluatedAt: new Date().toISOString(),
    };

    const cycle = await mlService.runWorkerCycle(10, 'test-worker');
    assert.equal(cycle.completed, 1);

    const pool = getDbPool();
    const assessRes = await pool.query<{
      status: string;
      anomaly_type: string;
      residual: string;
      threshold: string;
      severity: string;
    }>('SELECT * FROM anomaly_results WHERE reading_id = $1', [readingId]);

    assert.equal(assessRes.rows[0]?.status, 'SUSPICIOUS');
    assert.equal(assessRes.rows[0]?.anomaly_type, 'PROCESS_CONTEXT_MISMATCH');
    assert.equal(assessRes.rows[0]?.severity, 'CRITICAL');
  });

  it('13. Sensor Behaviour Rule: Flatline sensor stream is flagged as SUSPICIOUS with CRITICAL severity', async () => {
    const now = Date.now();
    const intervalStart = new Date(now - 10000).toISOString();
    const measuredAt = new Date(now - 2000).toISOString();
    const intervalEnd = new Date(now).toISOString();

    const opsEnvelope = opsSimulator.generateContext({
      overrides: {
        intervalStart,
        intervalEnd,
        productionRate: 400,
        wastewaterFlow: 10000,
        treatmentDose: 30,
        energyConsumption: 480,
        operatingMode: 'NORMAL',
      },
    });

    await fetch(`${primaryBaseUrl}/api/v1/ingestion/operations-context`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(opsEnvelope),
    });

    const readingEnvelope = codDevice.generateReading({
      overrideValue: '45.00',
      measuredAt,
    });

    const readRes = await fetch(`${primaryBaseUrl}/api/v1/ingestion/readings`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(readingEnvelope),
    });
    const { readingId, messageId } = (await readRes.json()) as { readingId: string; messageId: string };

    mockFastApiStatus = 200;
    mockFastApiBody = {
      readingId: messageId,
      status: 'SUSPICIOUS',
      anomalyType: 'FLATLINE',
      actualCod: 45.0,
      predictedCod: 45.1,
      absoluteResidual: 0.1,
      residualThreshold: 14.0,
      modelVersion: 'rules-v1.0',
      reasons: ['Sensor values have remained flatline constant across 8 consecutive windows'],
      evaluatedAt: new Date().toISOString(),
    };

    await mlService.runWorkerCycle(10, 'test-worker');

    const pool = getDbPool();
    const assessRes = await pool.query<{ severity: string; anomaly_type: string }>(
      'SELECT severity, anomaly_type FROM anomaly_results WHERE reading_id = $1',
      [readingId]
    );

    assert.equal(assessRes.rows[0]?.anomaly_type, 'FLATLINE');
    assert.equal(assessRes.rows[0]?.severity, 'CRITICAL');
  });

  it('14. Resilience & Retry: Transient ML outage retries with backoff; exhausted attempts mark job FAILED and record ERROR assessment', async () => {
    const now = Date.now();
    const intervalStart = new Date(now - 8000).toISOString();
    const measuredAt = new Date(now - 1000).toISOString();
    const intervalEnd = new Date(now).toISOString();

    const opsEnvelope = opsSimulator.generateContext({
      overrides: {
        intervalStart,
        intervalEnd,
        productionRate: 400,
        wastewaterFlow: 10000,
        treatmentDose: 30,
        energyConsumption: 480,
        operatingMode: 'NORMAL',
      },
    });
    await fetch(`${primaryBaseUrl}/api/v1/ingestion/operations-context`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(opsEnvelope),
    });

    const readingEnvelope = codDevice.generateReading({
      overrideValue: '80.00',
      measuredAt,
    });
    const readRes = await fetch(`${primaryBaseUrl}/api/v1/ingestion/readings`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(readingEnvelope),
    });
    const { readingId } = (await readRes.json()) as { readingId: string };

    mockFastApiStatus = 500;
    mockFastApiBody = { detail: 'Internal model inference crash' };

    const pool = getDbPool();

    // Cycle 1: attempt 1 fails -> RETRIED
    const cycle1 = await mlService.runWorkerCycle(10, 'test-worker');
    assert.equal(cycle1.retried, 1);

    const job1 = await pool.query<{ status: string; attempts: number }>(
      'SELECT status, attempts FROM ml_assessment_jobs WHERE reading_id = $1',
      [readingId]
    );
    assert.equal(job1.rows[0]?.status, 'PENDING');
    assert.equal(job1.rows[0]?.attempts, 1);

    await pool.query("UPDATE ml_assessment_jobs SET next_run_at = now() - INTERVAL '1 second' WHERE reading_id = $1", [readingId]);

    // Cycle 2: attempt 2 fails -> RETRIED
    const cycle2 = await mlService.runWorkerCycle(10, 'test-worker');
    assert.equal(cycle2.retried, 1);

    await pool.query("UPDATE ml_assessment_jobs SET next_run_at = now() - INTERVAL '1 second' WHERE reading_id = $1", [readingId]);

    // Cycle 3: attempt 3 reaches max_attempts (3) -> FAILED
    const cycle3 = await mlService.runWorkerCycle(10, 'test-worker');
    assert.equal(cycle3.failed, 1);

    const job3 = await pool.query<{ status: string; attempts: number }>(
      'SELECT status, attempts FROM ml_assessment_jobs WHERE reading_id = $1',
      [readingId]
    );
    assert.equal(job3.rows[0]?.status, 'FAILED');
    assert.equal(job3.rows[0]?.attempts, 3);

    const assessRes = await pool.query<{ status: string; processing_status: string }>(
      'SELECT status, processing_status FROM anomaly_results WHERE reading_id = $1',
      [readingId]
    );
    assert.equal(assessRes.rows[0]?.status, 'ERROR');
    assert.equal(assessRes.rows[0]?.processing_status, 'FAILED');
  });

  it('15. Stale Worker Reclaim: A job stuck in PROCESSING from a crashed worker is safely reclaimed', async () => {
    const pool = getDbPool();
    const readingEnvelope = codDevice.generateReading({
      overrideValue: '70.00',
      measuredAt: new Date().toISOString(),
    });
    const readRes = await fetch(`${primaryBaseUrl}/api/v1/ingestion/readings`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(readingEnvelope),
    });
    const { readingId } = (await readRes.json()) as { readingId: string };

    await pool.query(
      `UPDATE ml_assessment_jobs
       SET status = 'PROCESSING',
           locked_at = now() - INTERVAL '120 seconds',
           locked_by = 'crashed-worker-pid-9999'
       WHERE reading_id = $1`,
      [readingId]
    );

    const claimed = await mlService.getAssessmentRepo().claimNextJobs(10, 'new-worker-pid-1');
    const matched = claimed.find((j) => j.reading_id === readingId);
    assert(matched !== undefined, 'Stale job should have been reclaimed');
    assert.equal(matched.locked_by, 'new-worker-pid-1');
  });

  it('16. Dashboard Read APIs: Returns latest assessments, time series, and job summaries', async () => {
    // 16a. Health
    const healthRes = await fetch(`${primaryBaseUrl}/api/v1/ml/health`);
    assert.equal(healthRes.status, 200);
    const health = (await healthRes.json()) as { success: boolean; enabled: boolean };
    assert.equal(health.success, true);
    assert.equal(health.enabled, true);

    // 16b. Latest assessments
    const latestRes = await fetch(`${primaryBaseUrl}/api/v1/ml/assessments/latest?siteId=PLANT-001`, {
      headers: { Authorization: `Bearer ${adminToken}` },
    });
    assert.equal(latestRes.status, 200);
    const latest = (await latestRes.json()) as { success: boolean; count: number; assessments: any[] };
    assert.equal(latest.success, true);
    assert(latest.count > 0);

    // 16c. Sensor assessment history
    const sensorRes = await fetch(`${primaryBaseUrl}/api/v1/ml/assessments/sensor/COD-OUT-001`, {
      headers: { Authorization: `Bearer ${adminToken}` },
    });
    assert.equal(sensorRes.status, 200);
    const sensorHistory = (await sensorRes.json()) as { success: boolean; sensorId: string };
    assert.equal(sensorHistory.sensorId, 'COD-OUT-001');

    // 16d. Time series COD
    const seriesRes = await fetch(`${primaryBaseUrl}/api/v1/ml/series/cod?siteId=PLANT-001`, {
      headers: { Authorization: `Bearer ${adminToken}` },
    });
    assert.equal(seriesRes.status, 200);
    const seriesData = (await seriesRes.json()) as { success: boolean; series: any[] };
    assert(seriesData.series.length > 0);

    // 16e. Residuals series
    const resSeries = await fetch(`${primaryBaseUrl}/api/v1/ml/series/residuals?siteId=PLANT-001`, {
      headers: { Authorization: `Bearer ${adminToken}` },
    });
    assert.equal(resSeries.status, 200);

    // 16f. Job status summary
    const statusRes = await fetch(`${primaryBaseUrl}/api/v1/ml/jobs/status?siteId=PLANT-001`, {
      headers: { Authorization: `Bearer ${adminToken}` },
    });
    assert.equal(statusRes.status, 200);
    const summary = (await statusRes.json()) as { success: boolean; summary: Record<string, number> };
    assert(typeof summary.summary['COMPLETED'] === 'number');
  });

  it('17. RBAC & Site Isolation: Operator authorized for PLANT-001 is FORBIDDEN (403) from querying PLANT-002 ML data', async () => {
    const res = await fetch(`${primaryBaseUrl}/api/v1/ml/assessments/latest?siteId=PLANT-002`, {
      headers: { Authorization: `Bearer ${operatorToken}` },
    });
    assert.equal(res.status, 403);
    const body = (await res.json()) as { code: string };
    assert.equal(body.code, 'FORBIDDEN_SITE_ACCESS');

    const res2 = await fetch(`${primaryBaseUrl}/api/v1/ml/series/cod?siteId=PLANT-002`, {
      headers: { Authorization: `Bearer ${operatorToken}` },
    });
    assert.equal(res2.status, 403);
  });

  it('18. ML-Disabled Behavior: When ML_ENABLED=false, worker skips processing and health check reflects disabled state', async () => {
    const disabledEnv = loadApiEnvironment();
    disabledEnv.ML_ENABLED = false;

    const disabledService = new MlAssessmentService(getDbPool(), disabledEnv);
    const health = await disabledService.checkHealth();
    assert.equal(health.enabled, false);
    assert.equal(health.reachable, false);
    assert.match(health.error || '', /ML_ENABLED=false/);

    const cycle = await disabledService.runWorkerCycle();
    assert.equal(cycle.jobsClaimed, 0);
  });
});
