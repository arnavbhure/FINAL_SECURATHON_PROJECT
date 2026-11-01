import { describe, it, before, after } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import crypto from 'node:crypto';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import type { Server } from 'node:http';
import type { AddressInfo } from 'node:net';
import pg from 'pg';
import { createApiApp } from '../../api/src/app.js';
import { getDbPool, closeDbPool } from '../../api/src/db/connection.js';
import { runMigrations } from '../../api/src/db/migrate.js';
import { loadApiEnvironment } from '../../api/src/env.js';
import { AttackLabEngine, loadAttackLabConfig, type AttackLabRunRecord } from '../../api/src/attack-lab/index.js';
import type { MlAssessmentJobRow } from '../../api/src/repositories/ml-assessment.repository.js';
import { createWitnessApp } from '../src/app.js';
import { closeWitnessDbPool } from '../src/db/connection.js';
import { runWitnessMigrations } from '../src/db/migrate.js';
import { SensorDevice } from '../../sensor-simulator/src/sensor.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const rootDir = path.resolve(__dirname, '../../..');
const actor = { userId: null, label: 'automated e2e test', source: 'TEST' as const };

function listen(handler: http.RequestListener): Promise<{ server: Server; url: string }> {
  return new Promise((resolve) => {
    const server = http.createServer(handler).listen(0, '127.0.0.1', () => {
      resolve({ server, url: `http://127.0.0.1:${(server.address() as AddressInfo).port}` });
    });
  });
}

const close = (s: Server) => new Promise<void>((r) => s.close(() => r()));

/**
 * End-to-end Attack Lab scenarios against real in-process Primary API and Witness apps and the local
 * PostgreSQL databases. The only mock is the ML service used in scenario F, and it is labelled as such.
 */
describe('Attack Simulation Lab — end-to-end scenarios (Primary + Witness, local databases)', () => {
  const previousEnabled = process.env['ATTACK_LAB_ENABLED'];
  let primary: { server: Server; url: string };
  let witness: { server: Server; url: string };
  let mlMock: { server: Server; url: string };
  let engine: AttackLabEngine;
  let witnessPool: pg.Pool;
  let apiInstance: ReturnType<typeof createApiApp>;
  let labIdentitiesReady = false;

  before(async () => {
    process.env['ATTACK_LAB_ENABLED'] = 'true';
    await runMigrations(getDbPool());
    await runWitnessMigrations();
    await getDbPool().query("UPDATE attack_lab_runs SET status = 'ABANDONED', finished_at = now() WHERE status = 'RUNNING'");

    // MOCK ML service (isolated test only): returns a fixed, recognisable result so the test can prove the
    // lab reports exactly what the service returned rather than a fabricated value.
    mlMock = await listen((req, res) => {
      let body = '';
      req.on('data', (c) => (body += c));
      req.on('end', () => {
        res.writeHead(200, { 'Content-Type': 'application/json' });
        if (req.url?.startsWith('/health')) return res.end(JSON.stringify({ status: 'healthy' }));
        if (req.url?.startsWith('/model/status')) return res.end(JSON.stringify({ ready: true, model_version: 'TEST-MOCK-not-a-real-model' }));
        res.end(
          JSON.stringify({
            anomaly_score: 0.4321,
            anomaly_threshold: 0.0694,
            is_anomaly: true,
            isolation_forest_flag: true,
            detection_sources: ['test-mock'],
            status: 'SUSPICIOUS',
            model_version: 'TEST-MOCK-not-a-real-model',
            model_mode: 'TEST_MOCK',
            evaluated_at_utc: new Date().toISOString(),
          })
        );
      });
    });

    const env = { ...loadApiEnvironment(), DEMO_MODE: true, ML_ENABLED: true, ML_BASE_URL: mlMock.url, ML_TIMEOUT_MS: 3000 };
    apiInstance = createApiApp({ env });
    primary = await listen(apiInstance.app);
    witness = await listen(createWitnessApp().app);
    // The availability evaluator normally runs in server.ts; scenario H needs it.
    apiInstance.alertService.startEvaluator(2000);

    const config = {
      ...loadAttackLabConfig(env),
      primaryBaseUrl: primary.url,
      witnessBaseUrl: witness.url,
      mlBaseUrl: mlMock.url,
      mlWaitSeconds: 30,
    };
    witnessPool = new pg.Pool({ connectionString: config.witnessDatabaseUrl, max: 3 });
    engine = new AttackLabEngine(config, getDbPool(), witnessPool);
    const status = await engine.status();
    labIdentitiesReady = Object.values(status.demoIdentities).every((d) => d.ready);
  });

  after(async () => {
    apiInstance.alertService.stopEvaluator();
    if (previousEnabled === undefined) delete process.env['ATTACK_LAB_ENABLED'];
    else process.env['ATTACK_LAB_ENABLED'] = previousEnabled;
    await Promise.all([close(primary.server), close(witness.server), close(mlMock.server)]);
    await witnessPool.end();
    await closeWitnessDbPool();
    await closeDbPool();
  });

  const run = (id: string, confirm = false): Promise<AttackLabRunRecord> => engine.runScenario(id, actor, { confirm });

  it('A — payload modified after signing is rejected by both services with INVALID_SIGNATURE', async () => {
    const r = await run('telemetry-tampering');
    assert.equal(r.outcome, 'PREVENTED', r.summary ?? '');
    assert.equal(r.classification, 'INVALID_SIGNATURE');
    assert.equal(r.primaryOutcome?.['code'], 'INVALID_SIGNATURE');
    assert.equal(r.witnessOutcome?.['code'], 'INVALID_SIGNATURE');
    assert.equal(r.primaryOutcome?.['trustedRecords'], 0);
    assert.ok(r.securityEventIds.primary.length > 0 && r.securityEventIds.witness.length > 0);
    assert.ok(r.alertIds.length > 0);
    assert.equal(r.expectationMet, true);
  });

  it('B — envelope signed by an unregistered ephemeral key is rejected with UNKNOWN_KEY; key not persisted', async () => {
    const r = await run('unknown-signing-key');
    assert.equal(r.outcome, 'PREVENTED', r.summary ?? '');
    assert.equal(r.classification, 'UNKNOWN_KEY');
    assert.equal(r.verificationEvidence['attackerPrivateKeyPersisted'], false);
    assert.equal(JSON.stringify(r).includes('PRIVATE KEY'), false, 'no private key material in run evidence');
  });

  it('C — corrupted tamper signal is rejected and no PHYSICAL_TAMPER alert is created', async () => {
    const r = await run('invalid-tamper-signal');
    assert.equal(r.outcome, 'PREVENTED', r.summary ?? '');
    const eventId = String(r.verificationEvidence['eventId']);
    const alerts = await getDbPool().query('SELECT id FROM alerts WHERE deduplication_key = $1', [`tamper:${eventId}`]);
    assert.equal(alerts.rows.length, 0);
  });

  it('D — identical re-delivery is idempotent; sequence rollback is rejected by both services', async () => {
    const r = await run('replay-attack');
    assert.equal(r.outcome, 'PREVENTED', r.summary ?? '');
    assert.equal(r.classification, 'REPLAYED_SEQUENCE');
    const captured = String(r.verificationEvidence['capturedMessageId']);
    const rolled = String(r.verificationEvidence['rollbackMessageId']);
    const pool = getDbPool();
    const c1 = await pool.query('SELECT id FROM telemetry_readings WHERE message_id = $1', [captured]);
    const a1 = await pool.query("SELECT id FROM audit_events WHERE message_id = $1 AND event_type = 'TELEMETRY_INGESTION'", [captured]);
    const c2 = await pool.query('SELECT id FROM telemetry_readings WHERE message_id = $1', [rolled]);
    const w2 = await witnessPool.query('SELECT id FROM witness_events WHERE message_id = $1', [rolled]);
    assert.equal(c1.rows.length, 1, 'no second trusted record for the duplicate');
    assert.equal(a1.rows.length, 1, 'no duplicate ingestion audit-chain event');
    assert.equal(c2.rows.length, 0);
    assert.equal(w2.rows.length, 0);
  });

  it('E — sensor identity / key mismatch is rejected by both services and recorded', async () => {
    const r = await run('identity-key-mismatch');
    assert.equal(r.outcome, 'PREVENTED', r.summary ?? '');
    assert.equal(r.classification, 'IDENTITY_BINDING_FAILURE');
    assert.ok(r.securityEventIds.primary.length > 0, 'primary records a binding-mismatch security event');
    assert.ok(r.securityEventIds.witness.length > 0, 'witness records a binding-mismatch security event');
  });

  it('F — compromised key passes crypto; the reported ML values are exactly what the (MOCK) service returned', async (t) => {
    if (!labIdentitiesReady) return t.skip('demo identities not provisioned (npm run demo:provision)');
    const started = new Date();
    const { runId, completion } = await engine.startRun('compromised-signing-key', actor);
    // Process only this run's assessment job, so no mock result is written for any other reading.
    let processed = false;
    const deadline = Date.now() + 20000;
    while (!processed && Date.now() < deadline) {
      const job = await getDbPool().query<MlAssessmentJobRow>(
        `SELECT j.* FROM ml_assessment_jobs j JOIN sensors s ON s.id = j.sensor_id
         WHERE s.sensor_code = 'LAB-COD-902' AND j.created_at >= $1 AND j.status = 'PENDING'
         ORDER BY j.created_at DESC LIMIT 1`,
        [started]
      );
      if (job.rows[0]) {
        await apiInstance.mlAssessmentService.processJob(job.rows[0]);
        processed = true;
      } else {
        await new Promise((r) => setTimeout(r, 300));
      }
    }
    const r = await completion;
    assert.equal(r.id, runId);
    assert.equal(processed, true);
    assert.equal(r.primaryOutcome?.['httpStatus'], 201, 'legitimately signed value is accepted by Primary');
    assert.equal(r.witnessOutcome?.['httpStatus'], 201, 'and by the Witness');
    assert.equal(r.mlResult?.status, 'SUSPICIOUS');
    assert.equal(r.mlResult?.anomalyScore, 0.4321);
    assert.equal(r.mlResult?.anomalyThreshold, 0.0694);
    assert.equal(r.mlResult?.modelVersion, 'TEST-MOCK-not-a-real-model');
    assert.equal(r.outcome, 'SUSPICIOUS');
    assert.equal(JSON.stringify(r.mlResult).toLowerCase().includes('predicted'), false, 'no COD prediction is reported');
  });

  it('G — modified checkpoint export fails offline verification; untouched export passes; witness DB unchanged', async (t) => {
    if (!labIdentitiesReady) return t.skip('demo identities not provisioned (npm run demo:provision)');
    const r = await run('checkpoint-history-tampering');
    assert.equal(r.outcome, 'DETECTED', r.summary ?? '');
    assert.equal(r.classification, 'CHECKPOINT_VERIFICATION_FAILED');
    const failure = r.verificationEvidence['failureReason'] as { type: string };
    assert.equal(failure.type, 'EVENT_HASH_MISMATCH');
    assert.equal(r.verificationEvidence['witnessDatabaseUntouched'], true);
  });

  it('I — witness outage: Primary accepts, outbox keeps the envelope, retry is accepted with the same signature', async (t) => {
    if (!labIdentitiesReady) return t.skip('demo identities not provisioned (npm run demo:provision)');
    await assert.rejects(() => run('witness-outage', false), (e: { code?: string }) => e.code === 'CONFIRMATION_REQUIRED');
    const r = await run('witness-outage', true);
    assert.equal(r.outcome, 'DETECTED', r.summary ?? '');
    assert.equal(r.classification, 'WITNESS_DELIVERY_FAILURE_RECOVERED');
    assert.equal(r.witnessOutcome?.['duringOutage'], 'WITNESS_FAILED');
    assert.equal(r.witnessOutcome?.['afterRetry'], 'WITNESS_ACCEPTED');
    assert.equal(r.verificationEvidence['sensorAvailabilityDuringOutage'], 'ONLINE');
  });

  it('H — heartbeat interruption: STALE → OFFLINE → recovery, no duplicate alerts', async (t) => {
    if (!labIdentitiesReady) return t.skip('demo identities not provisioned (npm run demo:provision)');
    const r = await run('heartbeat-interruption', true);
    assert.equal(r.outcome, 'DETECTED', r.summary ?? '');
    assert.equal(r.verificationEvidence['staleAlertCount'], 1);
    assert.equal(r.verificationEvidence['offlineAlertCount'], 1);
    const status = await getDbPool().query<{ status: string }>("SELECT status FROM sensors WHERE sensor_code = 'LAB-COD-901'");
    assert.equal(status.rows[0]?.status, 'INACTIVE', 'demo sensor is taken out of service after the run');
  });

  it('Witness enforces (sensor, boot, sequence) uniqueness but still accepts delayed, never-seen sequences', async () => {
    const device = new SensorDevice({
      sensorId: 'TSS-OUT-001',
      keyDir: path.resolve(rootDir, 'local-secrets/sensor-keys/TSS-OUT-001'),
      bootId: `BOOT-E2E-${crypto.randomUUID().slice(0, 8)}`,
    });
    const token = process.env['WITNESS_INGESTION_TOKEN'] || 'witness_ingestion_internal_token_secret_98765';
    const send = (env: unknown) =>
      fetch(`${witness.url}/witness/v1/ingestion/readings`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'X-Witness-Token': token },
        body: JSON.stringify(env),
      });
    const s1 = device.generateReading({ overrideSequence: 1 });
    const s3 = device.generateReading({ overrideSequence: 3 });
    assert.equal((await send(s1)).status, 201);
    assert.equal((await send(s3)).status, 201);
    const delayed = device.generateReading({ overrideSequence: 2 });
    assert.equal((await send(delayed)).status, 201, 'outbox catch-up of a never-witnessed sequence is accepted');
    const rollback = device.generateReading({ overrideSequence: 3, overrideMessageId: crypto.randomUUID() });
    const res = await send(rollback);
    assert.equal(res.status, 409);
    assert.equal(((await res.json()) as { code: string }).code, 'REPLAYED_SEQUENCE');
    assert.equal((await send(s1)).status, 200, 'identical re-delivery stays idempotent');
  });
});
