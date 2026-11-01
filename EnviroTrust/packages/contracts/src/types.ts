/**
 * EnviroTrust Shared Contract Types
 * Directly mirroring JSON schemas in docs/contracts/
 */

export interface TelemetryPayload {
  schemaVersion: 1;
  eventType: 'TELEMETRY';
  messageId: string;
  sensorId: string;
  keyId: string;
  siteId: string;
  stationId: string;
  parameter: 'pH' | 'COD' | 'TSS';
  value: string;
  unit: string;
  measuredAt: string;
  sequence: number;
  bootId: string;
  calibrationRecordId?: string | null;
}

export interface SignedTelemetryEnvelope {
  payload: TelemetryPayload;
  signature: string;
}

export interface HeartbeatPayload {
  schemaVersion: 1;
  eventType: 'HEARTBEAT';
  messageId: string;
  sensorId: string;
  keyId: string;
  siteId: string;
  stationId: string;
  bootId: string;
  heartbeatSequence: number;
  sentAt: string;
}

export interface SignedHeartbeatEnvelope {
  payload: HeartbeatPayload;
  signature: string;
}

export type OperatingMode = 'NORMAL' | 'HIGH_LOAD' | 'CLEANING' | 'LOW_LOAD';

export interface OpsContextPayload {
  schemaVersion: 1;
  eventType: 'OPERATIONS_CONTEXT';
  messageId: string;
  sourceId: 'OPS-001';
  keyId: string;
  siteId: string;
  stationId: string;
  sequence: number;
  intervalStart: string;
  intervalEnd: string;
  productionRate: number;
  wastewaterFlow: number;
  treatmentDose: number;
  energyConsumption: number;
  operatingMode: OperatingMode;
}

export interface SignedOpsContextEnvelope {
  payload: OpsContextPayload;
  signature: string;
}

export type TamperEventType = 'ENCLOSURE_OPENED' | 'PHYSICAL_INTERFERENCE' | 'DEVICE_MOVEMENT';

export interface TamperEventPayload {
  schemaVersion: 1;
  eventId: string;
  sensorId: string;
  siteId: string;
  stationId: string;
  eventType: TamperEventType;
  eventTimestamp: string;
  keyId: string;
  tamperSource: string;
  sequence: number;
  eventSequence?: number;
  metadata?: Record<string, unknown>;
}

export interface SignedTamperEnvelope {
  payload: TamperEventPayload;
  signature: string;
}

export interface MlAnalysisRequest {
  readingId: string;
  siteId: string;
  stationId: string;
  sensorId: string;
  actualCod: number;
  measuredAt: string;
  contextVerified: true;
  context: {
    productionRate: number;
    wastewaterFlow: number;
    treatmentDose: number;
    energyConsumption: number;
    operatingMode: OperatingMode;
  };
  recentCodReadings: number[];
}

export type MlAnalysisStatus = 'CONSISTENT' | 'SUSPICIOUS' | 'NOT_EVALUATED' | 'ERROR';

export interface MlAnalysisResult {
  readingId: string;
  status: MlAnalysisStatus;
  anomalyType: string | null;
  actualCod: number | null;
  predictedCod: number | null;
  absoluteResidual: number | null;
  residualThreshold: number | null;
  modelVersion: string;
  reasons: string[];
  evaluatedAt: string;
}

export interface WitnessCheckpointPayload {
  schemaVersion: 1;
  checkpointId: string;
  witnessId: string;
  witnessKeyId: string;
  siteId: string;
  stationId: string;
  checkpointSequence: number;
  lastWitnessSequence: number;
  chainHeadHash: string;
  previousCheckpointHash: string;
  createdAt: string;
}

export interface SignedWitnessCheckpoint {
  payload: WitnessCheckpointPayload;
  signature: string;
  witnessPublicKeyFingerprint: string;
}

export interface ValidationErrorDetail {
  path: string;
  message: string;
  keyword: string;
  params: Record<string, unknown>;
}

export type ValidationResult<T> =
  | { valid: true; data: T; errors?: undefined }
  | { valid: false; errors: ValidationErrorDetail[]; data?: undefined };
