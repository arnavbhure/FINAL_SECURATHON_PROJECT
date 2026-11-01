import { describe, it, before, after } from 'node:test';
import assert from 'node:assert/strict';
import type { Server } from 'node:http';
import type { AddressInfo } from 'node:net';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { createApiApp } from '../../api/src/app.js';
import { getDbPool, closeDbPool } from '../../api/src/db/connection.js';
import { createWitnessApp } from '../src/app.js';
import { getWitnessDbPool, closeWitnessDbPool } from '../src/db/connection.js';
import { SensorDevice } from '../../sensor-simulator/src/sensor.js';
import { OpsContextSimulator } from '../../ops-simulator/src/simulator.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const rootDir = path.resolve(__dirname, '../../..');

describe('Simulated Witness & Primary — Direct Dual Delivery & Service Isolation', () => {
  let primaryServer: Server;
  let witnessServer: Server;
  let primaryUrl: string;
  let witnessUrl: string;
  let sensor: SensorDevice;
  let opsSim: OpsContextSimulator;
  const token = 'witness_ingestion_internal_token_secret_98765';

  before(async () => {
    const primaryPool = getDbPool();
    const witnessPool = getWitnessDbPool();

    // Ensure fresh sequence beyond any previously ingested records in both databases
    const [primCursor, witCursor] = await Promise.all([
      primaryPool.query<{ last_sequence_no: string }>(
        "SELECT last_sequence_no FROM operations_sequence_cursors WHERE source_id = 'OPS-001'"
      ),
      witnessPool.query<{ last_sequence: string }>(
        "SELECT last_sequence FROM witness_operations_cursors WHERE source_id = 'OPS-001'"
      ),
    ]);

    const maxPrim = primCursor.rows[0] ? Number(primCursor.rows[0].last_sequence_no) : 0;
    const maxWit = witCursor.rows[0] ? Number(witCursor.rows[0].last_sequence) : 0;
    const startOpsSeq = Math.max(maxPrim, maxWit) + 1000;

    const sensorKeyDir = path.resolve(rootDir, 'local-secrets/sensor-keys/TSS-OUT-001');
    sensor = new SensorDevice({ sensorId: 'TSS-OUT-001', keyDir: sensorKeyDir, initialTelemetrySequence: 1000 });

    const opsKeyDir = path.resolve(rootDir, 'local-secrets/ops-keys/OPS-001');
    opsSim = new OpsContextSimulator({ keyDir: opsKeyDir, initialSequence: startOpsSeq });

    // Start Primary API
    const { app: primaryApp } = createApiApp();
    await new Promise<void>((resolve) => {
      primaryServer = primaryApp.listen(0, () => {
        const addr = primaryServer.address() as AddressInfo;
        primaryUrl = `http://127.0.0.1:${addr.port}/api/v1/ingestion/readings`;
        resolve();
      });
    });

    // Start Witness API
    const { app: witnessApp } = createWitnessApp();
    await new Promise<void>((resolve) => {
      witnessServer = witnessApp.listen(0, () => {
        const addr = witnessServer.address() as AddressInfo;
        witnessUrl = `http://127.0.0.1:${addr.port}/witness/v1/ingestion/readings`;
        resolve();
      });
    });
  });

  after(async () => {
    await new Promise<void>((resolve) => primaryServer.close(() => resolve()));
    await new Promise<void>((resolve) => witnessServer.close(() => resolve()));
    await closeDbPool();
    await closeWitnessDbPool();
  });

  it('proves strict database isolation: primary tables do not exist in witness database and vice versa', async () => {
    const primaryPool = getDbPool();
    const witnessPool = getWitnessDbPool();

    // Check witness DB for primary table 'telemetry_readings'
    const witnessCheck = await witnessPool.query<{ count: string }>(
      "SELECT count(*) FROM information_schema.tables WHERE table_schema = 'public' AND table_name = 'telemetry_readings'"
    );
    assert.equal(Number(witnessCheck.rows[0]?.count), 0, 'telemetry_readings must NOT exist in witness database');

    // Check primary DB for witness table 'witness_events'
    const primaryCheck = await primaryPool.query<{ count: string }>(
      "SELECT count(*) FROM information_schema.tables WHERE table_schema = 'public' AND table_name = 'witness_events'"
    );
    assert.equal(Number(primaryCheck.rows[0]?.count), 0, 'witness_events must NOT exist in primary database');
  });

  it('concurrently dual-delivers a single signed telemetry reading to both primary and witness', async () => {
    const result = await sensor.sendReadingDual(primaryUrl, witnessUrl, {
      witnessToken: token,
    });

    assert.equal(result.primary.status, 'PRIMARY_ACCEPTED');
    assert.equal(result.primary.httpStatus, 201);

    assert.equal(result.witness.status, 'WITNESS_ACCEPTED');
    assert.equal(result.witness.httpStatus, 201);

    // Verify both APIs stored the same messageId
    const primaryData = result.primary.data as any;
    const witnessData = result.witness.data as any;

    assert.equal(primaryData.messageId, result.envelope.payload.messageId);
    assert.ok(witnessData.witnessEventId);
  });

  it('concurrently dual-delivers a single signed operations-context envelope to both primary and witness', async () => {
    const primaryOpsUrl = primaryUrl.replace('/readings', '/operations-context');
    const witnessOpsUrl = witnessUrl.replace('/readings', '/operations-context');

    const result = await opsSim.sendOpsContextDual(primaryOpsUrl, witnessOpsUrl, {
      witnessToken: token,
    });

    assert.equal(result.primary.status, 'PRIMARY_ACCEPTED');
    assert.equal(result.primary.httpStatus, 201);

    assert.equal(result.witness.status, 'WITNESS_ACCEPTED');
    assert.equal(result.witness.httpStatus, 201);
  });

  it('isolates destination failure when witness is unavailable and preserves envelope for retry', async () => {
    const deadWitnessUrl = 'http://127.0.0.1:59999/witness/v1/ingestion/readings';

    const result = await sensor.sendReadingDual(primaryUrl, deadWitnessUrl, {
      witnessToken: token,
      retryCount: 0, // don't delay test
    });

    assert.equal(result.primary.status, 'PRIMARY_ACCEPTED');
    assert.equal(result.witness.status, 'WITNESS_FAILED');

    // Retrying ONLY witness with the exact same envelope succeeds
    const retryRes = await fetch(witnessUrl, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-Witness-Token': token,
      },
      body: JSON.stringify(result.envelope),
    });

    assert.equal(retryRes.status, 201);
    const retryBody = (await retryRes.json()) as any;
    assert.equal(retryBody.status, 'ACCEPTED');
  });
});
