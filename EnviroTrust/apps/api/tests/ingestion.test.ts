import { describe, it, before, after } from 'node:test';
import assert from 'node:assert/strict';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import type { Server } from 'node:http';
import type { AddressInfo } from 'node:net';
import crypto from 'node:crypto';
import { createApiApp } from '../src/app.js';
import { getDbPool, closeDbPool } from '../src/db/connection.js';
import { runMigrations } from '../src/db/migrate.js';
import { SensorDevice } from '@envirotrust/sensor-simulator';
import { OpsContextSimulator } from '@envirotrust/ops-simulator';
import { registerKeysFromManifest } from '../src/services/key-registry.service.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const rootDir = path.resolve(__dirname, '../../..');

describe('Primary API — Ingestion & Audit Integration Tests', () => {
  let server: Server;
  let baseUrl: string;
  let phDevice: SensorDevice;
  let codDevice: SensorDevice;
  let opsSimulator: OpsContextSimulator;

  before(async () => {
    // 1. Ensure migrations and keys are registered in PostgreSQL
    const pool = getDbPool();
    await runMigrations(pool);
    const manifestPath = path.resolve(rootDir, 'local-secrets/provisioning/public-key-manifest.json');
    await registerKeysFromManifest(manifestPath, pool);

    // 2. Initialize simulators with local keys and fresh sequence counters
    const phKeyDir = path.resolve(rootDir, 'local-secrets/sensor-keys/PH-OUT-001');
    const codKeyDir = path.resolve(rootDir, 'local-secrets/sensor-keys/COD-OUT-001');
    const opsKeyDir = path.resolve(rootDir, 'local-secrets/ops-keys/OPS-001');

    const opsCursor = await pool.query<{ last_sequence_no: string }>(
      "SELECT last_sequence_no FROM operations_sequence_cursors WHERE source_id = 'OPS-001'"
    );
    const startOpsSeq = opsCursor.rows[0] ? Number(opsCursor.rows[0].last_sequence_no) + 1 : 1;

    phDevice = new SensorDevice({
      sensorId: 'PH-OUT-001',
      keyDir: phKeyDir,
      bootId: `BOOT-TEST-${crypto.randomUUID().slice(0, 8)}`,
      initialTelemetrySequence: 100,
    });

    codDevice = new SensorDevice({
      sensorId: 'COD-OUT-001',
      keyDir: codKeyDir,
      bootId: `BOOT-TEST-${crypto.randomUUID().slice(0, 8)}`,
      initialTelemetrySequence: 200,
    });

    opsSimulator = new OpsContextSimulator({
      keyDir: opsKeyDir,
      initialSequence: startOpsSeq,
    });

    // 3. Start API server on random port
    const { app } = createApiApp();
    await new Promise<void>((resolve) => {
      server = app.listen(0, () => {
        const addr = server.address() as AddressInfo;
        baseUrl = `http://127.0.0.1:${addr.port}`;
        resolve();
      });
    });
  });

  after(async () => {
    await new Promise<void>((resolve) => {
      server.close(() => resolve());
    });
    await closeDbPool();
  });

  it('1. Successfully ingests valid signed pH telemetry reading (201 Created)', async () => {
    const envelope = phDevice.generateReading({ overrideValue: '7.40' });
    const res = await fetch(`${baseUrl}/api/v1/ingestion/readings`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(envelope),
    });

    assert.equal(res.status, 201);
    const body = (await res.json()) as {
      success: boolean;
      messageId: string;
      readingId: string;
      signatureStatus: string;
      protocolStatus: string;
      primaryAuditSequence: number;
      chainHeadHash: string;
      witnessStatus: string;
    };

    assert.equal(body.success, true);
    assert.equal(body.messageId, envelope.payload.messageId);
    assert.ok(body.readingId);
    assert.equal(body.signatureStatus, 'VALID');
    assert.equal(body.protocolStatus, 'FRESH');
    assert.ok(body.primaryAuditSequence > 0);
    assert.equal(body.chainHeadHash.length, 64);
    assert.equal(body.witnessStatus, 'PENDING');
  });

  it('2. Successfully ingests valid signed COD telemetry reading (201 Created)', async () => {
    const envelope = codDevice.generateReading({ overrideValue: '185.50' });
    const res = await fetch(`${baseUrl}/api/v1/ingestion/readings`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(envelope),
    });

    assert.equal(res.status, 201);
    const body = (await res.json()) as { success: boolean; signatureStatus: string };
    assert.equal(body.success, true);
    assert.equal(body.signatureStatus, 'VALID');
  });

  it('3. Successfully ingests valid signed operations context (201 Created)', async () => {
    const envelope = opsSimulator.generateContext({ mode: 'NORMAL' });
    const res = await fetch(`${baseUrl}/api/v1/ingestion/operations-context`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(envelope),
    });

    assert.equal(res.status, 201);
    const body = (await res.json()) as {
      success: boolean;
      verificationStatus: string;
      primaryAuditSequence: number;
    };
    assert.equal(body.success, true);
    assert.equal(body.verificationStatus, 'VALID');
    assert.ok(body.primaryAuditSequence > 0);
  });

  it('4. Idempotent retry: resubmitting exact same telemetry envelope returns 200 with isDuplicate: true', async () => {
    const envelope = phDevice.generateReading({ overrideValue: '7.35' });

    // First submission
    const res1 = await fetch(`${baseUrl}/api/v1/ingestion/readings`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(envelope),
    });
    assert.equal(res1.status, 201);
    const body1 = (await res1.json()) as { readingId: string; primaryAuditSequence: number };

    // Duplicate submission with exact same envelope
    const res2 = await fetch(`${baseUrl}/api/v1/ingestion/readings`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(envelope),
    });
    assert.equal(res2.status, 200);
    const body2 = (await res2.json()) as {
      success: boolean;
      readingId: string;
      isDuplicate: boolean;
      primaryAuditSequence: number;
    };
    assert.equal(body2.success, true);
    assert.equal(body2.readingId, body1.readingId);
    assert.equal(body2.isDuplicate, true);
  });

  it('5. Negative: rejects tampered reading value (401 INVALID_SIGNATURE)', async () => {
    const envelope = phDevice.generateReading({ overrideValue: '7.10' });
    // Tamper with value without re-signing
    envelope.payload.value = '7.99';

    const res = await fetch(`${baseUrl}/api/v1/ingestion/readings`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(envelope),
    });

    assert.equal(res.status, 401);
    const body = (await res.json()) as { success: boolean; code: string };
    assert.equal(body.success, false);
    assert.equal(body.code, 'INVALID_SIGNATURE');
  });

  it('6. Negative: rejects invalid Base64 signature encoding (400 INVALID_SIGNATURE_ENCODING)', async () => {
    const envelope = phDevice.generateReading();
    envelope.signature = 'Not_Valid_Base64!!!';

    const res = await fetch(`${baseUrl}/api/v1/ingestion/readings`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(envelope),
    });

    assert.equal(res.status, 400);
    const body = (await res.json()) as { success: boolean; code: string };
    assert.equal(body.success, false);
  });

  it('7. Negative: rejects unknown key ID (401 UNKNOWN_KEY)', async () => {
    const envelope = phDevice.generateReading();
    envelope.payload.keyId = 'UNKNOWN-KEY-V99';

    const res = await fetch(`${baseUrl}/api/v1/ingestion/readings`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(envelope),
    });

    assert.equal(res.status, 401);
    const body = (await res.json()) as { success: boolean; code: string };
    assert.equal(body.success, false);
    assert.equal(body.code, 'UNKNOWN_KEY');
  });

  it('8. Negative: rejects parameter mismatch (400 KEY_PARAMETER_MISMATCH)', async () => {
    // Generate reading with COD device, but tamper parameter to pH
    const envelope = codDevice.generateReading();
    envelope.payload.parameter = 'pH';

    const res = await fetch(`${baseUrl}/api/v1/ingestion/readings`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(envelope),
    });

    assert.equal(res.status, 400);
    const body = (await res.json()) as { success: boolean; code: string };
    assert.equal(body.success, false);
    assert.equal(body.code, 'KEY_PARAMETER_MISMATCH');
  });

  it('9. Negative: rejects sensor mismatch (400 KEY_SENSOR_MISMATCH)', async () => {
    // Generate reading with PH device, but change sensorId to COD-OUT-001
    const envelope = phDevice.generateReading();
    envelope.payload.sensorId = 'COD-OUT-001';

    const res = await fetch(`${baseUrl}/api/v1/ingestion/readings`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(envelope),
    });

    assert.equal(res.status, 400);
    const body = (await res.json()) as { success: boolean; code: string };
    assert.equal(body.success, false);
    assert.equal(body.code, 'KEY_SENSOR_MISMATCH');
  });

  it('10. Negative: rejects future timestamp beyond skew threshold (400 TIMESTAMP_FUTURE)', async () => {
    // 500 seconds into the future (limit is 120s)
    const futureDate = new Date(Date.now() + 500 * 1000).toISOString();
    const envelope = phDevice.generateReading({ measuredAt: futureDate });

    const res = await fetch(`${baseUrl}/api/v1/ingestion/readings`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(envelope),
    });

    assert.equal(res.status, 400);
    const body = (await res.json()) as { success: boolean; code: string };
    assert.equal(body.success, false);
    assert.equal(body.code, 'TIMESTAMP_FUTURE');
  });

  it('11. Flags stale timestamp beyond max telemetry age as DELAYED (201 Created)', async () => {
    // 400 seconds into the past (limit is 300s)
    const pastDate = new Date(Date.now() - 400 * 1000).toISOString();
    const envelope = phDevice.generateReading({ measuredAt: pastDate });

    const res = await fetch(`${baseUrl}/api/v1/ingestion/readings`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(envelope),
    });

    assert.equal(res.status, 201);
    const body = (await res.json()) as { success: boolean; protocolStatus: string };
    assert.equal(body.success, true);
    assert.equal(body.protocolStatus, 'DELAYED');
  });

  it('12. Negative: rejects replay of sequence number in same boot session (409 REPLAYED_SEQUENCE)', async () => {
    // Send reading sequence N
    const envelope1 = phDevice.generateReading();
    const res1 = await fetch(`${baseUrl}/api/v1/ingestion/readings`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(envelope1),
    });
    assert.equal(res1.status, 201);

    // Try sending another reading with lower sequence number (signed properly)
    const staleEnvelope = phDevice.generateReading({
      overrideSequence: envelope1.payload.sequence - 1,
    });

    const res2 = await fetch(`${baseUrl}/api/v1/ingestion/readings`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(staleEnvelope),
    });

    assert.equal(res2.status, 409);
    const body2 = (await res2.json()) as { success: boolean; code: string };
    assert.equal(body2.success, false);
    assert.equal(body2.code, 'REPLAYED_SEQUENCE');
  });

  it('13. Negative: rejects duplicate messageId with modified payload (409 DUPLICATE_MESSAGE)', async () => {
    const envelope = codDevice.generateReading();
    const res1 = await fetch(`${baseUrl}/api/v1/ingestion/readings`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(envelope),
    });
    assert.equal(res1.status, 201);

    // Create a different payload with the same messageId (signed properly)
    const conflictEnvelope = codDevice.generateReading({
      overrideMessageId: envelope.payload.messageId,
      overrideValue: '210.00',
    });

    const res2 = await fetch(`${baseUrl}/api/v1/ingestion/readings`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(conflictEnvelope),
    });

    assert.equal(res2.status, 409);
    const body2 = (await res2.json()) as { success: boolean; code: string };
    assert.equal(body2.success, false);
    assert.equal(body2.code, 'DUPLICATE_MESSAGE');
  });

  it('14. Negative: operations context rejects intervalStart >= intervalEnd (400 INVALID_INTERVAL)', async () => {
    const envelope = opsSimulator.generateContext({
      overrides: {
        intervalStart: '2026-10-31T12:00:00.000Z',
        intervalEnd: '2026-10-31T11:00:00.000Z', // earlier than start!
      },
    });

    const res = await fetch(`${baseUrl}/api/v1/ingestion/operations-context`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(envelope),
    });

    assert.equal(res.status, 400);
    const body = (await res.json()) as { success: boolean; code: string };
    assert.equal(body.success, false);
    assert.equal(body.code, 'INVALID_INTERVAL');
  });

  it('15. Verifies audit chain link integrity in database', async () => {
    const pool = getDbPool();
    const client = await pool.connect();
    try {
      const res = await client.query<{
        event_sequence: string;
        previous_hash: string;
        event_hash: string;
      }>(
        `SELECT event_sequence, previous_hash, event_hash
         FROM audit_events
         ORDER BY event_sequence ASC`
      );

      assert.ok(res.rows.length >= 3, 'Expected at least 3 audit events');
      for (let i = 1; i < res.rows.length; i++) {
        const prev = res.rows[i - 1];
        const curr = res.rows[i];
        if (prev && curr) {
          assert.equal(
            curr.previous_hash,
            prev.event_hash,
            `Hash chain break between sequence ${prev.event_sequence} and ${curr.event_sequence}`
          );
        }
      }
    } finally {
      client.release();
    }
  });
});
