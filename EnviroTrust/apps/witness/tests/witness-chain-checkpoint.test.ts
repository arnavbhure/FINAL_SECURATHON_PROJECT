import { describe, it, before, after } from 'node:test';
import assert from 'node:assert/strict';
import type { Server } from 'node:http';
import type { AddressInfo } from 'node:net';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import fs from 'node:fs';
import { createWitnessApp } from '../src/app.js';
import { getWitnessDbPool, closeWitnessDbPool } from '../src/db/connection.js';
import { SensorDevice } from '../../sensor-simulator/src/sensor.js';
import { CheckpointService } from '../src/services/checkpoint.service.js';
import { exportCheckpoints, type CheckpointExportFile } from '../../../scripts/export-checkpoints.js';
import { verifyExportedCheckpoints } from '../../../scripts/verify-checkpoint.js';
import { loadWitnessEnvironment } from '../src/env.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const rootDir = path.resolve(__dirname, '../../..');

describe('Simulated Witness — Hash Chain, Periodic Checkpoints & Offline Verification', () => {
  let server: Server;
  let baseUrl: string;
  let phSensor: SensorDevice;
  let checkpointService: CheckpointService;
  const token = 'witness_ingestion_internal_token_secret_98765';
  const testStationId = 'ETP-OUTLET-001';

  before(async () => {
    const phKeyDir = path.resolve(rootDir, 'local-secrets/sensor-keys/PH-OUT-001');
    phSensor = new SensorDevice({ sensorId: 'PH-OUT-001', keyDir: phKeyDir });

    const keyDir = path.resolve(rootDir, 'local-secrets/witness-keys');
    checkpointService = new CheckpointService(keyDir);

    // Create app with WITNESS_CHECKPOINT_EVERY = 3 for testing
    const baseEnv = loadWitnessEnvironment();
    const testEnv = {
      ...baseEnv,
      WITNESS_CHECKPOINT_EVERY: 3,
      WITNESS_KEY_DIR: keyDir,
      WITNESS_SERVICE_TOKEN: token,
      WITNESS_INGESTION_TOKEN: token,
    };
    const { app } = createWitnessApp(undefined, testEnv);

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

  it('triggers a signed checkpoint when witnessSequence reaches checkpoint interval', async () => {
    // Send readings until a checkpoint is triggered at the interval boundary
    let lastCheckpointInfo: any = null;
    let savedReading: any = null;

    for (let i = 0; i < 10; i++) {
      const reading = phSensor.generateReading();
      savedReading = reading;
      const res = await fetch(`${baseUrl}/witness/v1/ingestion/readings`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'X-Witness-Token': token,
        },
        body: JSON.stringify(reading),
      });

      assert.equal(res.status, 201);
      const body = (await res.json()) as any;
      if (body.checkpointCreated) {
        lastCheckpointInfo = body.checkpointCreated;
        break;
      }
    }

    assert.ok(lastCheckpointInfo, 'Expected checkpoint to be created at interval boundary');
    assert.ok(lastCheckpointInfo.checkpointId);
    assert.ok(lastCheckpointInfo.chainHeadHash);
    assert.ok(lastCheckpointInfo.checkpointHash);

    // Query latest checkpoint endpoint
    const cpRes = await fetch(`${baseUrl}/witness/v1/checkpoints/${testStationId}/latest`, {
      headers: { 'X-Witness-Token': token },
    });
    assert.equal(cpRes.status, 200);
    const cpBody = (await cpRes.json()) as any;
    assert.equal(cpBody.success, true);
    assert.equal(cpBody.checkpoint.stationId, testStationId);
    assert.ok(cpBody.checkpoint.checkpointSequence >= lastCheckpointInfo.checkpointSequence);
    assert.ok(cpBody.checkpoint.chainHeadHash);

    // Cryptographically verify checkpoint signature
    const verifyResult = checkpointService.verifyCheckpoint({
      payload: cpBody.checkpoint.payload,
      signature: cpBody.checkpoint.signature,
      witnessPublicKeyFingerprint: cpBody.checkpoint.witnessPublicKeyFingerprint,
    });

    assert.equal(verifyResult.valid, true, `Checkpoint signature failed verification: ${verifyResult.reason}`);
  });

  it('GET /witness/v1/events/:messageId returns full witness event details', async () => {
    const reading = phSensor.generateReading();
    const ingestRes = await fetch(`${baseUrl}/witness/v1/ingestion/readings`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-Witness-Token': token,
      },
      body: JSON.stringify(reading),
    });
    assert.equal(ingestRes.status, 201);

    const getRes = await fetch(`${baseUrl}/witness/v1/events/${reading.payload.messageId}`, {
      headers: { 'X-Witness-Token': token },
    });
    assert.equal(getRes.status, 200);
    const body = (await getRes.json()) as any;
    assert.equal(body.success, true);
    assert.equal(body.event.messageId, reading.payload.messageId);
    assert.equal(body.event.identityCode, 'PH-OUT-001');
    assert.ok(body.event.eventHash);
    assert.ok(body.event.previousHash);
  });

  it('POST /witness/v1/verify/chain recomputes and validates hash chain continuity', async () => {
    const res = await fetch(`${baseUrl}/witness/v1/verify/chain`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-Witness-Token': token,
      },
      body: JSON.stringify({ stationId: testStationId }),
    });

    assert.equal(res.status, 200);
    const body = (await res.json()) as {
      valid: boolean;
      stationId: string;
      eventCount: number;
      discrepancies: any[];
    };
    assert.equal(body.valid, true);
    assert.equal(body.stationId, testStationId);
    assert.ok(body.eventCount > 0);
    assert.equal(body.discrepancies.length, 0);
  });

  it('POST /witness/v1/verify/primary-record checks matching against witness record', async () => {
    const reading = phSensor.generateReading();
    await fetch(`${baseUrl}/witness/v1/ingestion/readings`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-Witness-Token': token,
      },
      body: JSON.stringify(reading),
    });

    // Compute canonical payload hash
    const crypto = await import('node:crypto');
    const { canonicalizePayload } = await import('@envirotrust/crypto');
    const payloadHash = crypto.createHash('sha256').update(canonicalizePayload(reading.payload)).digest('hex');

    // 1. MATCHED check
    const matchRes = await fetch(`${baseUrl}/witness/v1/verify/primary-record`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-Witness-Token': token,
      },
      body: JSON.stringify({
        messageId: reading.payload.messageId,
        payloadHash,
        signature: reading.signature,
      }),
    });
    assert.equal(matchRes.status, 200);
    const matchBody = (await matchRes.json()) as any;
    assert.equal(matchBody.status, 'MATCHED');
    assert.equal(matchBody.witnessObserved, true);

    // 2. PAYLOAD_MISMATCH check
    const mismatchRes = await fetch(`${baseUrl}/witness/v1/verify/primary-record`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-Witness-Token': token,
      },
      body: JSON.stringify({
        messageId: reading.payload.messageId,
        payloadHash: '0000000000000000000000000000000000000000000000000000000000000000',
        signature: reading.signature,
      }),
    });
    assert.equal(mismatchRes.status, 200);
    const mismatchBody = (await mismatchRes.json()) as any;
    assert.equal(mismatchBody.status, 'PAYLOAD_MISMATCH');

    // 3. MISSING_FROM_WITNESS check
    const missingRes = await fetch(`${baseUrl}/witness/v1/verify/primary-record`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-Witness-Token': token,
      },
      body: JSON.stringify({
        messageId: '00000000-0000-0000-0000-000000000000',
        payloadHash,
        signature: reading.signature,
      }),
    });
    assert.equal(missingRes.status, 200);
    const missingBody = (await missingRes.json()) as any;
    assert.equal(missingBody.status, 'MISSING_FROM_WITNESS');
  });

  it('offline verification passes for exported checkpoints and fails on tampering', async () => {
    const tmpExportPath = path.resolve(process.cwd(), 'tmp-test-checkpoint-export.json');

    try {
      // Export checkpoints
      await exportCheckpoints({
        stationId: testStationId,
        outputPath: tmpExportPath,
      });

      assert.ok(fs.existsSync(tmpExportPath));
      const exportData = JSON.parse(fs.readFileSync(tmpExportPath, 'utf-8')) as CheckpointExportFile;
      assert.ok(exportData.checkpoints.length > 0);

      // Verify un-tampered export -> PASS
      const reportPass = verifyExportedCheckpoints(exportData);
      assert.equal(reportPass.overallStatus, 'PASS');
      assert.equal(reportPass.checkpointsValid, true);
      assert.equal(reportPass.eventsValid, true);
      assert.equal(reportPass.discrepancies.length, 0);

      // Tamper with an event in memory -> FAIL
      const tamperedExport: CheckpointExportFile = JSON.parse(JSON.stringify(exportData));
      if (tamperedExport.checkpoints[0]?.events[0]) {
        tamperedExport.checkpoints[0].events[0].eventHash = 'ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff';
      }

      const reportFail = verifyExportedCheckpoints(tamperedExport);
      assert.equal(reportFail.overallStatus, 'FAIL');
      assert.equal(reportFail.eventsValid, false);
      assert.ok(reportFail.discrepancies.some((d) => d.type === 'EVENT_HASH_MISMATCH'));
    } finally {
      if (fs.existsSync(tmpExportPath)) {
        fs.unlinkSync(tmpExportPath);
      }
    }
  });
});
