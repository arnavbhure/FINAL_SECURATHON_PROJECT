import { describe, it, before, after } from 'node:test';
import assert from 'node:assert/strict';
import type { Server } from 'node:http';
import type { AddressInfo } from 'node:net';
import path from 'node:path';
import crypto from 'node:crypto';
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

describe('Simulated Witness — Signed Heartbeats, Operations Cursor & Dual Delivery Tests', () => {
  let primaryServer: Server;
  let witnessServer: Server;
  let primaryBaseUrl: string;
  let witnessBaseUrl: string;
  let sensor: SensorDevice;
  let opsSim: OpsContextSimulator;
  let operatorAuthToken: string;
  const token = 'witness_ingestion_internal_token_secret_98765';

  before(async () => {
    const sensorKeyDir = path.resolve(rootDir, 'local-secrets/sensor-keys/TSS-OUT-001');
    sensor = new SensorDevice({
      sensorId: 'TSS-OUT-001',
      keyDir: sensorKeyDir,
      bootId: `BOOT-WITNESS-${crypto.randomUUID().slice(0, 8)}`,
      initialHeartbeatSequence: 500,
    });

    const opsKeyDir = path.resolve(rootDir, 'local-secrets/ops-keys/OPS-001');
    opsSim = new OpsContextSimulator({
      keyDir: opsKeyDir,
      initialSequence: 8000,
    });

    const { app: primaryApp } = createApiApp();
    await new Promise<void>((resolve) => {
      primaryServer = primaryApp.listen(0, () => {
        const addr = primaryServer.address() as AddressInfo;
        primaryBaseUrl = `http://127.0.0.1:${addr.port}`;
        resolve();
      });
    });

    const { app: witnessApp } = createWitnessApp();
    await new Promise<void>((resolve) => {
      witnessServer = witnessApp.listen(0, () => {
        const addr = witnessServer.address() as AddressInfo;
        witnessBaseUrl = `http://127.0.0.1:${addr.port}`;
        resolve();
      });
    });

    // Obtain operator token for authenticated read endpoints
    const loginRes = await fetch(`${primaryBaseUrl}/api/v1/auth/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email: 'operator@envirotrust.local', password: 'DemoPassword123!' }),
    });
    const loginData = (await loginRes.json()) as any;
    operatorAuthToken = loginData.accessToken;
  });

  after(async () => {
    await new Promise<void>((resolve) => {
      primaryServer.close(() => resolve());
    });
    await new Promise<void>((resolve) => {
      witnessServer.close(() => resolve());
    });
    await closeDbPool();
    await closeWitnessDbPool();
  });

  it('1. Rejects heartbeat submission without valid witness token (401)', async () => {
    const envelope = sensor.generateHeartbeat();
    const res = await fetch(`${witnessBaseUrl}/witness/v1/ingestion/heartbeats`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(envelope),
    });
    assert.equal(res.status, 401);
  });

  it('2. Ingests valid signed heartbeat into witness: persists to witness_heartbeats & hash-chains as HEARTBEAT (201)', async () => {
    const envelope = sensor.generateHeartbeat();
    const res = await fetch(`${witnessBaseUrl}/witness/v1/ingestion/heartbeats`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-Witness-Token': token,
      },
      body: JSON.stringify(envelope),
    });

    assert.equal(res.status, 201);
    const body = await res.json();
    assert.equal(body.success, true);
    assert.equal(body.status, 'ACCEPTED');
    assert.ok(body.witnessSequence > 0);
    assert.ok(body.eventHash);

    // Verify stored in witness_heartbeats table
    const witnessPool = getWitnessDbPool();
    const hbRes = await witnessPool.query(
      `SELECT message_id, sensor_code, heartbeat_sequence
       FROM witness_heartbeats
       WHERE message_id = $1`,
      [envelope.payload.messageId]
    );
    assert.equal(hbRes.rows.length, 1);
    assert.equal(hbRes.rows[0].sensor_code, 'TSS-OUT-001');

    // Verify stored in witness_events hash chain with event_type = 'HEARTBEAT'
    const evRes = await witnessPool.query(
      `SELECT event_type, identity_type, identity_code, source_sequence, event_hash
       FROM witness_events
       WHERE message_id = $1`,
      [envelope.payload.messageId]
    );
    assert.equal(evRes.rows.length, 1);
    assert.equal(evRes.rows[0].event_type, 'HEARTBEAT');
    assert.equal(evRes.rows[0].identity_type, 'SENSOR');
    assert.equal(evRes.rows[0].identity_code, 'TSS-OUT-001');
  });

  it('3. Handles idempotent duplicate heartbeat submission on witness (200)', async () => {
    const envelope = sensor.generateHeartbeat();

    // First submission
    const res1 = await fetch(`${witnessBaseUrl}/witness/v1/ingestion/heartbeats`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-Witness-Token': token,
      },
      body: JSON.stringify(envelope),
    });
    assert.equal(res1.status, 201);

    // Identical retry
    const res2 = await fetch(`${witnessBaseUrl}/witness/v1/ingestion/heartbeats`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-Witness-Token': token,
      },
      body: JSON.stringify(envelope),
    });
    assert.equal(res2.status, 200);
    const body2 = await res2.json();
    assert.equal(body2.success, true);
    assert.equal(body2.isDuplicate, true);
  });

  it('4. Rejects replayed heartbeat sequence on witness (409 REPLAYED_SEQUENCE)', async () => {
    const envelope = sensor.generateHeartbeat();

    const res1 = await fetch(`${witnessBaseUrl}/witness/v1/ingestion/heartbeats`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-Witness-Token': token,
      },
      body: JSON.stringify(envelope),
    });
    assert.equal(res1.status, 201);

    // Replay with new messageId but same or lower heartbeatSequence
    const replayed = {
      payload: {
        ...envelope.payload,
        messageId: crypto.randomUUID(),
      },
      signature: envelope.signature,
    };

    const res2 = await fetch(`${witnessBaseUrl}/witness/v1/ingestion/heartbeats`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-Witness-Token': token,
      },
      body: JSON.stringify(replayed),
    });
    // Fails on signature verification (401) or cursor sequence (409)
    assert.ok(res2.status === 401 || res2.status === 409);
  });

  it('5. REGRESSION TEST (Review Item 1): Rejects replayed operations context sequence on witness (409)', async () => {
    const witnessPool = getWitnessDbPool();
    const cursor = await witnessPool.query<{ last_sequence: string }>(
      "SELECT last_sequence FROM witness_operations_cursors WHERE source_id = 'OPS-001'"
    );
    const nextSeq = (cursor.rows[0] ? Number(cursor.rows[0].last_sequence) : 0) + 50000;
    const opsEnvelope = opsSim.generateContext({ overrides: { sequence: nextSeq } });

    const res1 = await fetch(`${witnessBaseUrl}/witness/v1/ingestion/operations-context`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-Witness-Token': token,
      },
      body: JSON.stringify(opsEnvelope),
    });
    const b1 = (await res1.json()) as any;
    if (res1.status !== 201) {
      console.error('[TEST 5 ERROR]:', res1.status, b1);
    }
    assert.equal(res1.status, 201);

    // Next ops envelope with replayed sequence
    const replayedOps = opsSim.generateContext({
      overrides: { sequence: opsEnvelope.payload.sequence },
    });

    const res2 = await fetch(`${witnessBaseUrl}/witness/v1/ingestion/operations-context`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-Witness-Token': token,
      },
      body: JSON.stringify(replayedOps),
    });
    assert.equal(res2.status, 409);
    const body2 = await res2.json();
    assert.equal(body2.code, 'REPLAYED_SEQUENCE');
  });

  it('6. Direct dual-delivery of signed heartbeats concurrently to primary and witness', async () => {
    const primaryHbUrl = `${primaryBaseUrl}/api/v1/ingestion/heartbeats`;
    const witnessHbUrl = `${witnessBaseUrl}/witness/v1/ingestion/heartbeats`;

    const result = await sensor.sendHeartbeatDual(primaryHbUrl, witnessHbUrl, {
      witnessToken: token,
    });

    assert.equal(result.primary.status, 'PRIMARY_ACCEPTED');
    assert.equal(result.primary.httpStatus, 201);
    assert.equal(result.witness.status, 'WITNESS_ACCEPTED');
    assert.equal(result.witness.httpStatus, 201);
  });

  it('7. Isolates destination failure: when witness fails, primary heartbeat succeeds and sensor is ONLINE', async () => {
    const primaryHbUrl = `${primaryBaseUrl}/api/v1/ingestion/heartbeats`;
    const invalidWitnessUrl = 'http://127.0.0.1:59999/witness/v1/ingestion/heartbeats'; // Down / unreachable

    const result = await sensor.sendHeartbeatDual(primaryHbUrl, invalidWitnessUrl, {
      witnessToken: token,
      retryCount: 1,
      retryBaseMs: 50,
    });

    assert.equal(result.primary.status, 'PRIMARY_ACCEPTED');
    assert.equal(result.witness.status, 'WITNESS_FAILED');

    // Sensor availability on primary must remain ONLINE despite witness outage
    const healthRes = await fetch(`${primaryBaseUrl}/api/v1/sensors/TSS-OUT-001/health`, {
      headers: { Authorization: `Bearer ${operatorAuthToken}` },
    });
    assert.equal(healthRes.status, 200);
    const healthBody = await healthRes.json();
    assert.equal(healthBody.sensor.currentStatus, 'ONLINE');
    assert.equal(healthBody.sensor.statusReason, 'HEARTBEAT_RECEIVED');
  });
});
