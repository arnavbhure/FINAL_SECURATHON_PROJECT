export type UserRole = 'PLATFORM_ADMIN' | 'FACTORY_OPERATOR' | 'REGULATOR_AUDITOR';

export interface User {
  id: string;
  email: string;
  role: UserRole;
  sites: string[];
  name?: string;
  status: 'ACTIVE' | 'DISABLED';
  createdAt?: string;
}

export interface Site {
  id: string;
  siteCode: string;
  name: string;
  industryType: string;
  demoLabel: string;
  status: string;
  stationCount: number;
  sensorCount: number;
  createdAt: string;
}

export type SensorAvailabilityStatus = 'ONLINE' | 'STALE' | 'OFFLINE' | 'NO_HEARTBEAT_EVER_RECEIVED';

export interface SensorHealth {
  sensorId: string;
  sensorCode?: string;
  siteId: string;
  siteCode: string;
  stationId: string;
  stationCode: string;
  parameter: 'pH' | 'COD' | 'TSS';
  unit: string;
  status: SensorAvailabilityStatus;
  lastHeartbeatReceivedAt: string | null;
  lastHeartbeatSentAt: string | null;
  missedIntervalsCount: number;
  expectedIntervalSeconds: number;
  primaryDeliveryStatus: string;
  witnessDeliveryStatus: string;
  lastKnownSequence: number | null;
  evaluatedAt: string;
}

export interface HeartbeatRecord {
  id: string;
  messageId: string;
  sensorId: string;
  sequenceNo: number;
  sentAt: string;
  receivedAt: string;
  signatureStatus: string;
}

export interface TelemetryReading {
  id: string;
  messageId: string;
  sensorId: string;
  siteId: string;
  siteName: string;
  stationId: string;
  parameter: 'pH' | 'COD' | 'TSS';
  valueNumeric: number;
  valueWire: string;
  unit: string;
  measuredAt: string | null;
  receivedAt: string | null;
  bootId: string;
  sequenceNo: number;
  keyId: string;
  payloadHash: string;
  signatureStatus: 'VALID' | 'INVALID' | 'UNKNOWN_KEY';
  protocolStatus: 'FRESH' | 'GAP_DETECTED' | 'DELAYED';
  calibrationStatus: string;
  witnessStatus: string;
  anomaly?: {
    id: string;
    status: 'CONSISTENT' | 'SUSPICIOUS' | 'NOT_EVALUATED' | 'ERROR';
    severity: 'NONE' | 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  } | null;
}

export interface AnomalyAssessment {
  id: string;
  readingId: string;
  messageId: string;
  sensorId: string;
  siteId: string;
  stationId: string;
  status: 'CONSISTENT' | 'SUSPICIOUS' | 'NOT_EVALUATED' | 'ERROR';
  anomalyType: string | null;
  actualValue: number | null;
  predictedValue: number | null;
  residual: number | null;
  threshold: number | null;
  severity: 'NONE' | 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  modelVersion: string;
  processingStatus: 'COMPLETED' | 'INSUFFICIENT_CONTEXT' | 'FAILED';
  reasons: string[];
  evaluatedAt: string;
  measuredAt?: string;
  contextId?: string | null;
}

export interface CodSeriesPoint {
  readingId: string;
  siteId?: string;
  sensorId?: string;
  measuredAt: string;
  actualCod: number;
  predictedCod: number | null;
  residual: number | null;
  threshold: number | null;
  severity: string;
  status: string;
  modelVersion?: string | null;
}

export interface MlHealth {
  enabled: boolean;
  reachable: boolean;
  baseUrl: string;
  ready?: boolean;
  modelVersion?: string;
  error?: string;
  latencyMs?: number;
}

export interface WitnessCheckpoint {
  id: string;
  witnessId: string;
  witnessKeyId: string;
  siteId: string;
  stationId: string;
  checkpointSequence: number;
  lastWitnessSequence: number;
  chainHeadHash: string;
  previousCheckpointHash: string;
  createdAt: string;
  signature: string;
  checkpointHash: string;
  witnessPublicKeyFingerprint: string;
}

export interface SecurityEvent {
  id: string;
  eventType: string;
  reasonCode: string;
  metadata: Record<string, any>;
  siteId: string | null;
  sensorId: string | null;
  occurredAt: string | null;
  createdAt: string | null;
}

export interface AuditEvent {
  id: string;
  eventSequence: number;
  eventType: string;
  entityId: string | null;
  messageId: string | null;
  payload: Record<string, any>;
  previousHash: string | null;
  eventHash: string;
  siteId: string;
  stationId: string;
  createdAt: string | null;
}

export interface ChainVerificationResult {
  valid: boolean;
  stationId: string;
  eventCount: number;
  headSequence: number;
  headHash: string;
  discrepancies: Array<{
    sequence: number;
    messageId: string;
    expectedHash: string;
    actualHash: string;
    reason: string;
  }>;
}

export interface RecordVerificationResult {
  status: 'MATCHED' | 'PAYLOAD_MISMATCH' | 'SIGNATURE_MISMATCH' | 'MISSING_FROM_WITNESS';
  messageId: string;
  witnessObserved: boolean;
  witnessSequence?: number;
  witnessReceivedAt?: string;
  eventHash?: string;
  reason?: string;
}

export interface TamperAlert {
  alert_id: string;
  device_id: string;
  event_type: string;
  severity: 'INFO' | 'WARNING' | 'CRITICAL';
  status: 'ACTIVE' | 'ACKNOWLEDGED' | 'RESOLVED';
  timestamp_utc: string;
  details?: Record<string, unknown>;
}

export interface GatewayStatus {
  service: string;
  is_online: boolean;
  total_recorded_messages: number;
  timestamp_utc: string;
}

export type AlertSeverity = 'CRITICAL' | 'HIGH' | 'WARNING' | 'INFO';
export type AlertStatus = 'OPEN' | 'ACKNOWLEDGED' | 'RESOLVED';
export type AlertType =
  | 'PHYSICAL_TAMPER'
  | 'SENSOR_STALE'
  | 'SENSOR_OFFLINE'
  | 'SENSOR_RECOVERED'
  | 'SECURITY_EVENT';

export interface Alert {
  id: string;
  site_id: string;
  sensor_id: string | null;
  station_id: string | null;
  alert_type: AlertType;
  severity: AlertSeverity;
  title: string;
  description: string;
  source_event_id: string | null;
  detection_source: string;
  status: AlertStatus;
  recommended_action: string;
  deduplication_key: string | null;
  metadata: Record<string, unknown>;
  created_at: string;
  acknowledged_at: string | null;
  acknowledged_by: string | null;
  resolved_at: string | null;
  resolved_by: string | null;
  resolution_note: string | null;
  site_code?: string;
  site_name?: string;
  sensor_code?: string;
  station_code?: string;
  acknowledged_by_name?: string | null;
  resolved_by_name?: string | null;
}

export interface AlertSummary {
  totalOpen: number;
  critical: number;
  high: number;
  warning: number;
  resolved: number;
  activeIncidents: number;
}



// ---------------------------------------------------------------------------
// Attack Simulation Lab (demo-only; mirrors apps/api/src/attack-lab/types.ts)
// ---------------------------------------------------------------------------

export type AttackRunOutcome =
  | 'PREVENTED'
  | 'DETECTED'
  | 'SUSPICIOUS'
  | 'ACCEPTED'
  | 'PENDING'
  | 'INCONCLUSIVE'
  | 'SERVICE_UNAVAILABLE';

export interface AttackScenario {
  id: string;
  letter: string;
  name: string;
  description: string;
  threatCategory: string;
  mechanismTested: string;
  expectedResponse: string;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
  requiresConfirmation: boolean;
  requiresDemoIdentities: boolean;
  estimatedDurationSeconds: number;
  evidenceLinks: Array<{ label: string; path: string }>;
}

export interface AttackRunStep {
  index: number;
  key: string;
  title: string;
  status: 'RUNNING' | 'PASSED' | 'FAILED' | 'INFO' | 'SKIPPED';
  startedAt: string;
  finishedAt: string | null;
  detail: string;
  data?: Record<string, unknown>;
}

export interface AttackMlEvidence {
  status: 'SUSPICIOUS' | 'CONSISTENT' | 'NOT_EVALUATED' | 'ML_NOT_ENABLED' | 'ML_UNAVAILABLE' | 'PENDING';
  detail: string;
  anomalyResultId?: string | null;
  anomalyScore?: number | null;
  anomalyThreshold?: number | null;
  isAnomaly?: boolean | null;
  detectionSources?: string[] | null;
  modelVersion?: string | null;
  evaluatedAt?: string | null;
  reasons?: string[];
}

export interface AttackRun {
  id: string;
  scenarioId: string;
  status: 'RUNNING' | 'COMPLETED' | 'FAILED' | 'ABANDONED';
  outcome: AttackRunOutcome | null;
  classification: string | null;
  summary: string | null;
  expectationMet: boolean | null;
  actorLabel: string;
  actorSource: 'UI' | 'CLI' | 'TEST';
  siteCode: string;
  startedAt: string;
  finishedAt: string | null;
  steps: AttackRunStep[];
  primaryOutcome: Record<string, unknown> | null;
  witnessOutcome: Record<string, unknown> | null;
  mlResult: AttackMlEvidence | null;
  alertIds: string[];
  securityEventIds: { primary: string[]; witness: string[] };
  verificationEvidence: Record<string, unknown>;
  error: string | null;
}

export interface AttackLabServiceStatus {
  reachable: boolean;
  httpStatus: number | null;
  detail: string;
}

export interface AttackLabStatus {
  environmentLabel: string;
  siteCode: string;
  stationCode: string;
  canExecute: boolean;
  safety: { ok: boolean; checks: Array<{ id: string; label: string; ok: boolean; detail: string }> };
  services: {
    primary: AttackLabServiceStatus;
    witness: AttackLabServiceStatus & { witnessId: string | null; displayName: string | null };
    ml: AttackLabServiceStatus & {
      enabledOnPrimary: boolean;
      ready: boolean | null;
      modelVersion: string | null;
      modelMode: string | null;
    };
  };
  demoIdentities: Record<string, { ready: boolean; keyId: string | null }>;
  activeRun: { id: string; scenarioId: string; startedAt: string } | null;
}
