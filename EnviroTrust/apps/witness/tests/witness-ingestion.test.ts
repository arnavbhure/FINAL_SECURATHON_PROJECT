import { describe, it, before, after } from 'node:test';
import assert from 'node:assert/strict';
import type { Server } from 'node:http';
import type { AddressInfo } from 'node:net';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import crypto from 'node:crypto';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const rootDir = path.resolve(__dirname, '../../..');
import { createWitnessApp } from '../src/app.js';
import { getWitnessDbPool, closeWitnessDbPool } from '../src/db/connection.js';
import { SensorDevice } from '../../sensor-simulator/src/sensor.js';
import { OpsContextSimulator } from '../../ops-simulator/src/simulator.js';

describe('Simulated Witness — Ingestion & Independent Cryptographic Verification', () => {
  let server: Server;
  let baseUrl: string;
  let codSensor: SensorDevice;
  let opsSim: OpsContextSimulator;
  const token = 'witness_ingestion_internal_token_secret_98765';

  before(async () => {
    const codKeyDir = path.resolve(rootDir, 'local-secrets/sensor-keys/COD-OUT-001');
    codSensor = new SensorDevice({ sensorId: 'COD-OUT-001', keyDir: codKeyDir });

    const opsKeyDir = path.resolve(rootDir, 'local-secrets/ops-keys/OPS-001');
    const witnessPool = getWitnessDbPool();
    const opsCursor = await witnessPool.query<{ last_sequence: string }>(
      "SELECT last_sequence FROM witness_operations_cursors WHERE source_id = 'OPS-001'"
    );
    const startOpsSeq = opsCursor.rows[0] ? Number(opsCursor.rows[0].last_sequence) + 100 : 10000;
    opsSim = new OpsContextSimulator({ keyDir: opsKeyDir, initialSequence: startOpsSeq });

    const { app } = createWitnessApp();
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
    await closeWitnessDbPool();
  });

  it('rejects telemetry without witness token (401)', async () => {
    const reading = codSensor.generateReading();
    const res = await fetch(`${baseUrl}/witness/v1/ingestion/readings`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(reading),
    });

    assert.equal(res.status, 401);
    const body = (await res.json()) as { code: string };
    assert.equal(body.code, 'UNAUTHORIZED');
  });

  it('rejects telemetry with invalid witness token (401)', async () => {
    const reading = codSensor.generateReading();
    const res = await fetch(`${baseUrl}/witness/v1/ingestion/readings`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-Witness-Token': 'wrong-internal-token-12345',
      },
      body: JSON.stringify(reading),
    });

    assert.equal(res.status, 401);
    const body = (await res.json()) as { code: string };
    assert.equal(body.code, 'UNAUTHORIZED');
  });

  it('accepts valid signed telemetry reading with correct token (201)', async () => {
    const reading = codSensor.generateReading();
    const res = await fetch(`${baseUrl}/witness/v1/ingestion/readings`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-Witness-Token': token,
      },
      body: JSON.stringify(reading),
    });

    assert.equal(res.status, 201);
    const body = (await res.json()) as {
      success: boolean;
      status: string;
      witnessEventId: string;
      witnessSequence: number;
      eventHash: string;
    };
    assert.equal(body.success, true);
    assert.equal(body.status, 'ACCEPTED');
    assert.ok(body.witnessEventId);
    assert.ok(typeof body.witnessSequence === 'number');
    assert.equal(body.eventHash.length, 64);
  });

  it('handles idempotent duplicate telemetry submission gracefully (200)', async () => {
    const reading = codSensor.generateReading();
    // First submission
    const res1 = await fetch(`${baseUrl}/witness/v1/ingestion/readings`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-Witness-Token': token,
      },
      body: JSON.stringify(reading),
    });
    assert.equal(res1.status, 201);
    const body1 = (await res1.json()) as { witnessSequence: number; eventHash: string };

    // Duplicate submission with identical signed envelope
    const res2 = await fetch(`${baseUrl}/witness/v1/ingestion/readings`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-Witness-Token': token,
      },
      body: JSON.stringify(reading),
    });
    assert.equal(res2.status, 200);
    const body2 = (await res2.json()) as { isDuplicate: boolean; witnessSequence: number; eventHash: string };
    assert.equal(body2.isDuplicate, true);
    assert.equal(body2.witnessSequence, body1.witnessSequence);
    assert.equal(body2.eventHash, body1.eventHash);
  });

  it('rejects conflicting duplicate with same messageId but different payload content (409)', async () => {
    const reading = codSensor.generateReading();
    // First submission
    const res1 = await fetch(`${baseUrl}/witness/v1/ingestion/readings`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-Witness-Token': token,
      },
      body: JSON.stringify(reading),
    });
    assert.equal(res1.status, 201);

    // Create conflicting envelope using same messageId but different value
    const conflictingReading = codSensor.generateReading({
      overrideMessageId: reading.payload.messageId,
      overrideValue: '999.99',
    });

    const res2 = await fetch(`${baseUrl}/witness/v1/ingestion/readings`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-Witness-Token': token,
      },
      body: JSON.stringify(conflictingReading),
    });
    assert.equal(res2.status, 409);
    const body2 = (await res2.json()) as { code: string };
    assert.equal(body2.code, 'DUPLICATE_MESSAGE');
  });

  it('rejects telemetry with unknown key ID (401)', async () => {
    const reading = codSensor.generateReading();
    const tampered = {
      ...reading,
      payload: { ...reading.payload, keyId: 'UNKNOWN-KEY-V99' },
    };

    const res = await fetch(`${baseUrl}/witness/v1/ingestion/readings`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-Witness-Token': token,
      },
      body: JSON.stringify(tampered),
    });
    assert.equal(res.status, 401);
    const body = (await res.json()) as { code: string };
    assert.equal(body.code, 'UNKNOWN_KEY');
  });

  it('rejects telemetry with mismatched parameter binding (400)', async () => {
    const reading = codSensor.generateReading();
    // COD key bound to parameter 'COD', tamper with parameter 'TSS'
    const tampered = {
      ...reading,
      payload: { ...reading.payload, parameter: 'TSS' },
    };

    const res = await fetch(`${baseUrl}/witness/v1/ingestion/readings`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-Witness-Token': token,
      },
      body: JSON.stringify(tampered),
    });
    assert.equal(res.status, 400);
    const body = (await res.json()) as { code: string };
    assert.equal(body.code, 'KEY_PARAMETER_MISMATCH');
  });

  it('rejects telemetry with invalid signature (401)', async () => {
    const reading = codSensor.generateReading();
    // Tamper with value without updating signature
    const tampered = {
      ...reading,
      payload: { ...reading.payload, value: '123.45' },
    };

    const res = await fetch(`${baseUrl}/witness/v1/ingestion/readings`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-Witness-Token': token,
      },
      body: JSON.stringify(tampered),
    });
    assert.equal(res.status, 401);
    const body = (await res.json()) as { code: string };
    assert.equal(body.code, 'INVALID_SIGNATURE');
  });

  it('rejects telemetry with timestamp in the far future (400)', async () => {
    const futureDate = new Date(Date.now() + 3600 * 1000).toISOString();
    const reading = codSensor.generateReading({ measuredAt: futureDate });

    const res = await fetch(`${baseUrl}/witness/v1/ingestion/readings`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-Witness-Token': token,
      },
      body: JSON.stringify(reading),
    });
    assert.equal(res.status, 400);
    const body = (await res.json()) as { code: string };
    assert.equal(body.code, 'TIMESTAMP_FUTURE');
  });

  it('accepts valid signed operations context envelope (201)', async () => {
    const pool = getWitnessDbPool();
    const cursor = await pool.query<{ last_sequence: string }>(
      "SELECT last_sequence FROM witness_operations_cursors WHERE source_id = 'OPS-001'"
    );
    const nextSeq = cursor.rows[0] ? Number(cursor.rows[0].last_sequence) + 1 : 1;
    const opsContext = opsSim.generateContext({ overrides: { sequence: nextSeq } });
    const res = await fetch(`${baseUrl}/witness/v1/ingestion/operations-context`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-Witness-Token': token,
      },
      body: JSON.stringify(opsContext),
    });

    assert.equal(res.status, 201);
    const body = (await res.json()) as any;
    assert.equal(body.success, true);
    assert.equal(body.status, 'ACCEPTED');
    assert.ok(body.witnessEventId);
  });

  it('rejects operations context with tampered signature (401)', async () => {
    const opsContext = opsSim.generateContext();
    const tampered = {
      ...opsContext,
      payload: { ...opsContext.payload, productionRate: 999.99 },
    };

    const res = await fetch(`${baseUrl}/witness/v1/ingestion/operations-context`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-Witness-Token': token,
      },
      body: JSON.stringify(tampered),
    });
    assert.equal(res.status, 401);
    const body = (await res.json()) as { code: string };
    assert.equal(body.code, 'INVALID_SIGNATURE');
  });

  it('rejects operations context without token (401)', async () => {
    const opsContext = opsSim.generateContext();
    const res = await fetch(`${baseUrl}/witness/v1/ingestion/operations-context`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(opsContext),
    });
    assert.equal(res.status, 401);
    const body = (await res.json()) as { code: string };
    assert.equal(body.code, 'UNAUTHORIZED');
  });
});
