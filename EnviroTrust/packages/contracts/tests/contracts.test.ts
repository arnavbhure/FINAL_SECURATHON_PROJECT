import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { execSync } from 'node:child_process';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import {
  validateTelemetryPayload,
  validateSignedTelemetryEnvelope,
  validateHeartbeatPayload,
  validateSignedHeartbeatEnvelope,
  validateOpsContextPayload,
  validateSignedOpsContextEnvelope,
  validateMlRequest,
  validateMlResult,
  validateWitnessCheckpointPayload,
  validateTamperPayload,
  validateSignedTamperEnvelope,
  type TelemetryPayload,
  type HeartbeatPayload,
  type OpsContextPayload,
  type MlAnalysisRequest,
  type MlAnalysisResult,
} from '../src/index.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// Dummy valid base64 signature of 88 chars (64 raw bytes encoded)
const VALID_SIG_BASE64 = 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA';

describe('Contracts — Specification Drift Check', () => {
  it('runtime schemas in packages/contracts/src/schemas strictly match canonical docs/contracts/', () => {
    const checkScript = path.resolve(__dirname, '../scripts/check.js');
    const result = execSync(`node "${checkScript}"`, { encoding: 'utf-8' });
    assert.match(result, /SUCCESS: All \d+ runtime schemas strictly match canonical docs\/contracts\//);
  });
});

describe('Contracts — Telemetry Payload Validation', () => {
  const validPayload: TelemetryPayload = {
    schemaVersion: 1,
    eventType: 'TELEMETRY',
    messageId: 'b2147436-3c45-48c3-ad91-03b31c64bb64',
    sensorId: 'COD-OUT-001',
    keyId: 'COD-KEY-V1',
    siteId: 'PLANT-001',
    stationId: 'ETP-OUTLET-001',
    parameter: 'COD',
    value: '185.40',
    unit: 'mg/L',
    measuredAt: '2026-10-31T12:00:00.000Z',
    sequence: 101,
    bootId: 'BOOT-2026-10-31-01',
    calibrationRecordId: null,
  };

  it('accepts a valid telemetry payload', () => {
    const res = validateTelemetryPayload(validPayload);
    assert.equal(res.valid, true);
    if (res.valid) {
      assert.equal(res.data.parameter, 'COD');
      assert.equal(res.data.value, '185.40');
    }
  });

  it('accepts integer and decimal string values', () => {
    assert.equal(validateTelemetryPayload({ ...validPayload, value: '0' }).valid, true);
    assert.equal(validateTelemetryPayload({ ...validPayload, value: '7.5' }).valid, true);
    assert.equal(validateTelemetryPayload({ ...validPayload, value: '-2.1' }).valid, true);
  });

  it('rejects invalid non-decimal string value formats', () => {
    assert.equal(validateTelemetryPayload({ ...validPayload, value: 'abc' }).valid, false);
    assert.equal(validateTelemetryPayload({ ...validPayload, value: '1.2.3' }).valid, false);
    assert.equal(validateTelemetryPayload({ ...validPayload, value: '1e5' }).valid, false);
    assert.equal(validateTelemetryPayload({ ...validPayload, value: '' }).valid, false);
  });

  it('rejects invalid parameter enum', () => {
    const invalid = { ...validPayload, parameter: 'TURBIDITY' };
    const res = validateTelemetryPayload(invalid);
    assert.equal(res.valid, false);
    assert.ok(res.errors && res.errors.length > 0);
  });

  it('rejects missing required fields', () => {
    const missing = { ...validPayload };
    delete (missing as Record<string, unknown>)['messageId'];
    const res = validateTelemetryPayload(missing);
    assert.equal(res.valid, false);
  });

  it('rejects invalid UUID for messageId', () => {
    const invalid = { ...validPayload, messageId: 'not-a-uuid' };
    const res = validateTelemetryPayload(invalid);
    assert.equal(res.valid, false);
  });
});

describe('Contracts — Signed Telemetry Envelope Validation', () => {
  const validEnvelope = {
    payload: {
      schemaVersion: 1,
      eventType: 'TELEMETRY',
      messageId: 'b2147436-3c45-48c3-ad91-03b31c64bb64',
      sensorId: 'PH-OUT-001',
      keyId: 'PH-KEY-V1',
      siteId: 'PLANT-001',
      stationId: 'ETP-OUTLET-001',
      parameter: 'pH',
      value: '7.20',
      unit: 'pH',
      measuredAt: '2026-10-31T12:00:00.000Z',
      sequence: 1,
      bootId: 'BOOT-2026-10-31-01',
    },
    signature: VALID_SIG_BASE64,
  };

  it('accepts a valid signed telemetry envelope', () => {
    const res = validateSignedTelemetryEnvelope(validEnvelope);
    assert.equal(res.valid, true);
  });

  it('rejects envelope missing signature', () => {
    const res = validateSignedTelemetryEnvelope({ payload: validEnvelope.payload });
    assert.equal(res.valid, false);
  });

  it('rejects envelope with too short signature', () => {
    const res = validateSignedTelemetryEnvelope({ ...validEnvelope, signature: 'short' });
    assert.equal(res.valid, false);
  });
});

describe('Contracts — Heartbeat Validation', () => {
  const validHeartbeat: HeartbeatPayload = {
    schemaVersion: 1,
    eventType: 'HEARTBEAT',
    messageId: 'b2147436-3c45-48c3-ad91-03b31c64bb64',
    sensorId: 'COD-OUT-001',
    keyId: 'COD-KEY-V1',
    siteId: 'PLANT-001',
    stationId: 'ETP-OUTLET-001',
    bootId: 'BOOT-2026-10-31-01',
    heartbeatSequence: 12,
    sentAt: '2026-10-31T12:00:10.000Z',
  };

  it('accepts a valid heartbeat payload', () => {
    const res = validateHeartbeatPayload(validHeartbeat);
    assert.equal(res.valid, true);
  });

  it('accepts a valid signed heartbeat envelope', () => {
    const res = validateSignedHeartbeatEnvelope({
      payload: validHeartbeat,
      signature: VALID_SIG_BASE64,
    });
    assert.equal(res.valid, true);
  });

  it('rejects heartbeat missing bootId', () => {
    const missing = { ...validHeartbeat };
    delete (missing as Record<string, unknown>)['bootId'];
    const res = validateHeartbeatPayload(missing);
    assert.equal(res.valid, false);
  });
});

describe('Contracts — Operations Context Validation', () => {
  const validOpsContext: OpsContextPayload = {
    schemaVersion: 1,
    eventType: 'OPERATIONS_CONTEXT',
    messageId: 'b2147436-3c45-48c3-ad91-03b31c64bb64',
    sourceId: 'OPS-001',
    keyId: 'OPS-KEY-V1',
    siteId: 'PLANT-001',
    stationId: 'ETP-OUTLET-001',
    sequence: 45,
    intervalStart: '2026-10-31T11:50:00.000Z',
    intervalEnd: '2026-10-31T12:00:00.000Z',
    productionRate: 450.5,
    wastewaterFlow: 12000.0,
    treatmentDose: 35.2,
    energyConsumption: 520.0,
    operatingMode: 'NORMAL',
  };

  it('accepts a valid operations context payload', () => {
    const res = validateOpsContextPayload(validOpsContext);
    assert.equal(res.valid, true);
  });

  it('accepts a valid signed operations context envelope', () => {
    const res = validateSignedOpsContextEnvelope({
      payload: validOpsContext,
      signature: VALID_SIG_BASE64,
    });
    assert.equal(res.valid, true);
  });

  it('rejects invalid operatingMode', () => {
    const invalid = { ...validOpsContext, operatingMode: 'INVALID_MODE' };
    const res = validateOpsContextPayload(invalid);
    assert.equal(res.valid, false);
  });

  it('rejects sourceId other than OPS-001', () => {
    const invalid = { ...validOpsContext, sourceId: 'OTHER-SOURCE' };
    const res = validateOpsContextPayload(invalid);
    assert.equal(res.valid, false);
  });
});

describe('Contracts — ML Request and Result Validation', () => {
  const validMlRequest: MlAnalysisRequest = {
    readingId: 'READING-12345',
    siteId: 'PLANT-001',
    stationId: 'ETP-OUTLET-001',
    sensorId: 'COD-OUT-001',
    actualCod: 210.5,
    measuredAt: '2026-10-31T12:00:00.000Z',
    contextVerified: true,
    context: {
      productionRate: 450.0,
      wastewaterFlow: 12000.0,
      treatmentDose: 35.0,
      energyConsumption: 520.0,
      operatingMode: 'NORMAL',
    },
    recentCodReadings: [205.1, 208.3, 210.5],
  };

  it('accepts a valid ML analysis request with contextVerified: true', () => {
    const res = validateMlRequest(validMlRequest);
    assert.equal(res.valid, true);
  });

  it('strictly rejects an ML request if contextVerified is not true', () => {
    const unverified = { ...validMlRequest, contextVerified: false };
    const res = validateMlRequest(unverified);
    assert.equal(res.valid, false);
  });

  it('accepts a valid ML analysis result for CONSISTENT outcome', () => {
    const consistentResult: MlAnalysisResult = {
      readingId: 'READING-12345',
      status: 'CONSISTENT',
      anomalyType: null,
      actualCod: 210.5,
      predictedCod: 208.2,
      absoluteResidual: 2.3,
      residualThreshold: 15.0,
      modelVersion: 'RF-COD-v1.0.0',
      reasons: ['Within normal operating residual threshold'],
      evaluatedAt: '2026-10-31T12:00:01.000Z',
    };
    const res = validateMlResult(consistentResult);
    assert.equal(res.valid, true);
  });

  it('accepts a valid ML analysis result for SUSPICIOUS outcome', () => {
    const suspiciousResult: MlAnalysisResult = {
      readingId: 'READING-12346',
      status: 'SUSPICIOUS',
      anomalyType: 'PROCESS_CONTEXT_MISMATCH',
      actualCod: 85.0,
      predictedCod: 220.0,
      absoluteResidual: 135.0,
      residualThreshold: 15.0,
      modelVersion: 'RF-COD-v1.0.0',
      reasons: ['COD residual 135.0 exceeds threshold 15.0 given high production load'],
      evaluatedAt: '2026-10-31T12:00:01.000Z',
    };
    const res = validateMlResult(suspiciousResult);
    assert.equal(res.valid, true);
  });

  it('accepts a valid ML analysis result for NOT_EVALUATED outcome', () => {
    const notEvaluatedResult: MlAnalysisResult = {
      readingId: 'READING-12347',
      status: 'NOT_EVALUATED',
      anomalyType: null,
      actualCod: 210.5,
      predictedCod: null,
      absoluteResidual: null,
      residualThreshold: null,
      modelVersion: 'RF-COD-v1.0.0',
      reasons: ['Operational context missing or stale'],
      evaluatedAt: '2026-10-31T12:00:01.000Z',
    };
    const res = validateMlResult(notEvaluatedResult);
    assert.equal(res.valid, true);
  });

  it('rejects an ML result with invalid status', () => {
    const invalidResult = {
      readingId: 'READING-12348',
      status: 'FRAUD_CONFIRMED',
      anomalyType: null,
      actualCod: 210.5,
      predictedCod: 200.0,
      absoluteResidual: 10.5,
      residualThreshold: 15.0,
      modelVersion: 'RF-COD-v1.0.0',
      reasons: [],
      evaluatedAt: '2026-10-31T12:00:01.000Z',
    };
    const res = validateMlResult(invalidResult);
    assert.equal(res.valid, false);
  });
});

describe('Contracts — Witness Checkpoint Payload Validation', () => {
  const validCheckpoint = {
    schemaVersion: 1,
    checkpointId: '9b1deb4d-3b7d-4bad-9bdd-2b0d7b3dcb6d',
    witnessId: 'WITNESS-001',
    witnessKeyId: 'WITNESS-KEY-V1',
    siteId: 'PLANT-001',
    stationId: 'ETP-OUTLET-001',
    checkpointSequence: 1,
    lastWitnessSequence: 10,
    chainHeadHash: 'a'.repeat(64),
    previousCheckpointHash: '0'.repeat(64),
    createdAt: '2026-10-31T12:00:00.000Z',
  };

  it('accepts a valid witness checkpoint payload', () => {
    const res = validateWitnessCheckpointPayload(validCheckpoint);
    assert.equal(res.valid, true);
  });

  it('rejects a checkpoint missing chainHeadHash', () => {
    const { chainHeadHash, ...missingHash } = validCheckpoint;
    const res = validateWitnessCheckpointPayload(missingHash);
    assert.equal(res.valid, false);
  });

  it('rejects a checkpoint with invalid hash length', () => {
    const res = validateWitnessCheckpointPayload({ ...validCheckpoint, chainHeadHash: 'too-short' });
    assert.equal(res.valid, false);
  });

  it('rejects a checkpoint with sequence < 1', () => {
    const res = validateWitnessCheckpointPayload({ ...validCheckpoint, checkpointSequence: 0 });
    assert.equal(res.valid, false);
  });
});

describe('Contracts — Tamper Event Payload Validation', () => {
  const validTamperPayload = {
    schemaVersion: 1,
    eventId: 'c3d4e5f6-a7b8-4c9d-0e1f-2a3b4c5d6e7f',
    sensorId: 'COD-OUT-001',
    siteId: 'PLANT-001',
    stationId: 'ETP-OUTLET-001',
    eventType: 'ENCLOSURE_OPENED',
    eventTimestamp: '2026-10-31T12:00:00.000Z',
    keyId: 'COD-KEY-V1',
    tamperSource: 'SIMULATED',
    sequence: 1,
  };

  it('accepts a valid tamper event payload', () => {
    const res = validateTamperPayload(validTamperPayload);
    assert.equal(res.valid, true);
    if (res.valid) {
      assert.equal(res.data.eventType, 'ENCLOSURE_OPENED');
    }
  });

  it('accepts all allowed tamper event types', () => {
    for (const type of ['ENCLOSURE_OPENED', 'PHYSICAL_INTERFERENCE', 'DEVICE_MOVEMENT']) {
      const res = validateTamperPayload({ ...validTamperPayload, eventType: type });
      assert.equal(res.valid, true);
    }
  });

  it('rejects an invalid tamper event type', () => {
    const res = validateTamperPayload({ ...validTamperPayload, eventType: 'WIRE_CUT' });
    assert.equal(res.valid, false);
  });

  it('rejects invalid eventId format', () => {
    const res = validateTamperPayload({ ...validTamperPayload, eventId: 'not-a-uuid' });
    assert.equal(res.valid, false);
  });

  it('validates signed tamper envelope', () => {
    const validEnvelope = {
      payload: validTamperPayload,
      signature: VALID_SIG_BASE64,
    };
    const res = validateSignedTamperEnvelope(validEnvelope);
    assert.equal(res.valid, true);
  });

  it('rejects signed tamper envelope with invalid signature length', () => {
    const invalidEnvelope = {
      payload: validTamperPayload,
      signature: 'short',
    };
    const res = validateSignedTamperEnvelope(invalidEnvelope);
    assert.equal(res.valid, false);
  });
});
