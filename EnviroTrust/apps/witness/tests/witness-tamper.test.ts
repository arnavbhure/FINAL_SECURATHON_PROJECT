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

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const rootDir = path.resolve(__dirname, '../../..');

describe('Simulated Witness — Signed Tamper Events & Independent Ingestion Tests', () => {
  let primaryServer: Server;
  let witnessServer: Server;
  let primaryBaseUrl: string;
  let witnessBaseUrl: string;
  let sensor: SensorDevice;
  const witnessToken = 'witness_ingestion_internal_token_secret_98765';
  const baseSeq = Math.floor(Date.now() / 1000) * 10;

  before(async () => {
    const witnessPool = getWitnessDbPool();
    await witnessPool.query('DELETE FROM witness_tamper_events');
    const primaryPool = getDbPool();
    await primaryPool.query("DELETE FROM alerts WHERE deduplication_key LIKE 'tamper:%' OR deduplication_key LIKE 'test:%'");
    await primaryPool.query('DELETE FROM tamper_events');

    const sensorKeyDir = path.resolve(rootDir, 'local-secrets/sensor-keys/COD-OUT-001');
    sensor = new SensorDevice({
      sensorId: 'COD-OUT-001',
      keyDir: sensorKeyDir,
      bootId: `BOOT-WITNESS-TAMPER-${crypto.randomUUID().slice(0, 8)}`,
      initialTamperSequence: baseSeq,
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

  it('1. Rejects tamper event submission without valid witness token (401)', async () => {
    const envelope = sensor.generateTamperEvent({ overrideSequence: baseSeq + 1 });
    const res = await fetch(`${witnessBaseUrl}/witness/v1/tamper/events`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(envelope),
    });
    assert.equal(res.status, 401);
  });

  it('2. Ingests valid signed tamper event into witness: persists to witness_tamper_events & hash-chains as PHYSICAL_TAMPER (201)', async () => {
    const envelope = sensor.generateTamperEvent({
      eventType: 'ENCLOSURE_OPENED',
      tamperSource: 'SIMULATED',
      overrideSequence: baseSeq + 2,
    });

    const res = await fetch(`${witnessBaseUrl}/witness/v1/tamper/events`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-Witness-Token': witnessToken,
      },
      body: JSON.stringify(envelope),
    });

    assert.equal(res.status, 201);
    const data = (await res.json()) as any;
    assert.equal(data.success, true);
    assert.equal(data.status, 'ACCEPTED');
    assert.ok(data.witnessEventId);
    assert.ok(data.witnessSequence > 0);
    assert.ok(data.eventHash);

    // Verify row in witness_tamper_events
    const pool = getWitnessDbPool();
    const rowRes = await pool.query('SELECT * FROM witness_tamper_events WHERE event_id = $1', [envelope.payload.eventId]);
    assert.equal(rowRes.rowCount, 1);
    assert.equal(rowRes.rows[0].event_type, 'ENCLOSURE_OPENED');
    assert.equal(rowRes.rows[0].tamper_source, 'SIMULATED');

    // Verify row in witness_events hash chain
    const chainRes = await pool.query("SELECT * FROM witness_events WHERE message_id = $1 AND event_type = 'PHYSICAL_TAMPER'", [envelope.payload.eventId]);
    assert.equal(chainRes.rowCount, 1);
  });

  it('3. Handles idempotent duplicate tamper submission on witness (200 with isDuplicate: true)', async () => {
    const envelope = sensor.generateTamperEvent({ overrideSequence: baseSeq + 3 });

    // First submission
    const res1 = await fetch(`${witnessBaseUrl}/witness/v1/tamper/events`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-Witness-Token': witnessToken,
      },
      body: JSON.stringify(envelope),
    });
    assert.equal(res1.status, 201);

    // Exact duplicate resubmission
    const res2 = await fetch(`${witnessBaseUrl}/witness/v1/tamper/events`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-Witness-Token': witnessToken,
      },
      body: JSON.stringify(envelope),
    });
    assert.equal(res2.status, 200);
    const data2 = (await res2.json()) as any;
    assert.equal(data2.isDuplicate, true);
  });

  it('4. Rejects replayed tamper sequence on witness (409 REPLAYED_SEQUENCE)', async () => {
    // Attempt to submit lower or equal sequence (baseSeq + 3 was already accepted)
    const replayed = sensor.generateTamperEvent({ overrideSequence: baseSeq + 3 });
    const res = await fetch(`${witnessBaseUrl}/witness/v1/tamper/events`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-Witness-Token': witnessToken,
      },
      body: JSON.stringify(replayed),
    });
    assert.equal(res.status, 409);
    const data = (await res.json()) as any;
    assert.equal(data.code, 'REPLAYED_SEQUENCE');
  });

  it('5. Negative: Rejects invalid Ed25519 tamper signature on witness (401 INVALID_SIGNATURE)', async () => {
    const envelope = sensor.generateTamperEvent({ overrideSequence: baseSeq + 4 });
    const chars = envelope.signature.split('');
    chars[15] = chars[15] === 'A' ? 'B' : 'A';
    envelope.signature = chars.join('');

    const res = await fetch(`${witnessBaseUrl}/witness/v1/tamper/events`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-Witness-Token': witnessToken,
      },
      body: JSON.stringify(envelope),
    });
    assert.equal(res.status, 401);
    const data = (await res.json()) as any;
    assert.equal(data.code, 'INVALID_SIGNATURE');
  });

  it('6. Direct dual-delivery: SensorDevice delivers signed tamper event concurrently to primary and witness (Scenario A)', async () => {
    const envelope = sensor.generateTamperEvent({
      eventType: 'ENCLOSURE_OPENED',
      tamperSource: 'SIMULATED',
      overrideSequence: baseSeq + 5,
    });

    const result = await sensor.sendTamperEventDual(
      `${primaryBaseUrl}/api/v1/tamper/events`,
      `${witnessBaseUrl}/witness/v1/tamper/events`,
      {
        providedEnvelope: envelope,
        witnessToken,
      }
    );

    assert.equal(result.primary.status, 'PRIMARY_ACCEPTED');
    assert.equal(result.primary.httpStatus, 201);
    assert.equal(result.witness.status, 'WITNESS_ACCEPTED');
    assert.equal(result.witness.httpStatus, 201);
  });
});
