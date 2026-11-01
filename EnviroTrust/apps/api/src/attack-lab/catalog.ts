import type { ScenarioDefinition, ScenarioId } from './types.js';

const LINKS = {
  alerts: { label: 'Alert Center', path: '/alerts' },
  anomalies: { label: 'ML Anomaly Engine', path: '/anomalies' },
  audit: { label: 'Audit & Witness', path: '/audit' },
  monitoring: { label: 'Sensor Telemetry', path: '/monitoring' },
  sensors: { label: 'Fleet Availability', path: '/sensors' },
};

/** The only scenarios the lab can execute. Requests name one of these IDs; nothing else is accepted. */
export const SCENARIO_CATALOG: readonly ScenarioDefinition[] = [
  {
    id: 'telemetry-tampering',
    letter: 'A',
    name: 'Telemetry Payload Tampering',
    description:
      'A genuine COD reading is signed with the registered COD-OUT-001 key, then the value is changed after signing while the original signature is kept. The modified envelope is sent to the Primary API and the Independent Witness.',
    threatCategory: 'Data integrity — modification in transit',
    mechanismTested: 'Ed25519 signature over the RFC 8785 canonical payload (independently verified by Primary and Witness)',
    expectedResponse:
      'Both services reject with INVALID_SIGNATURE; no trusted record is stored; a security rejection event and security alert are recorded. No physical-tamper alert is raised.',
    severity: 'HIGH',
    requiresConfirmation: false,
    requiresDemoIdentities: false,
    estimatedDurationSeconds: 3,
    evidenceLinks: [LINKS.alerts, LINKS.monitoring, LINKS.audit],
  },
  {
    id: 'unknown-signing-key',
    letter: 'B',
    name: 'Unknown Signing Key',
    description:
      'An attacker generates an ephemeral Ed25519 key in memory and submits a syntactically valid, correctly signed envelope that claims to come from COD-OUT-001.',
    threatCategory: 'Spoofed device identity',
    mechanismTested: 'Enrolled public-key registry (keys are never trusted from the request itself)',
    expectedResponse:
      'Both services reject with UNKNOWN_KEY; no trusted measurement; a security rejection event is recorded. The attacker key is never persisted.',
    severity: 'HIGH',
    requiresConfirmation: false,
    requiresDemoIdentities: false,
    estimatedDurationSeconds: 3,
    evidenceLinks: [LINKS.alerts, LINKS.monitoring],
  },
  {
    id: 'invalid-tamper-signal',
    letter: 'C',
    name: 'Invalid Tamper Signal',
    description:
      'A physical-tamper event is generated for COD-OUT-001 and its signature is corrupted before submission to the existing tamper ingestion endpoints.',
    threatCategory: 'Forged physical-tamper signal',
    mechanismTested: 'Signature verification on the tamper-event ingestion path',
    expectedResponse:
      'Rejected with INVALID_SIGNATURE by both services; a SECURITY_EVENT rejection is recorded; no verified PHYSICAL_TAMPER alert is created.',
    severity: 'HIGH',
    requiresConfirmation: false,
    requiresDemoIdentities: false,
    estimatedDurationSeconds: 3,
    evidenceLinks: [LINKS.alerts],
  },
  {
    id: 'replay-attack',
    letter: 'D',
    name: 'Replay Attack',
    description:
      'Case 1 re-delivers a captured, already accepted COD-OUT-001 envelope byte-for-byte. Case 2 sends a correctly signed message with a new message ID that reuses an already consumed sequence for the same sensor and boot session.',
    threatCategory: 'Replay / sequence rollback',
    mechanismTested: 'Message-ID idempotency and (sensor, boot, sequence) replay protection at Primary and Witness',
    expectedResponse:
      'Case 1 returns the idempotent duplicate response with no second record or audit event. Case 2 is rejected with REPLAYED_SEQUENCE by both services and recorded as a security event.',
    severity: 'HIGH',
    requiresConfirmation: false,
    requiresDemoIdentities: false,
    estimatedDurationSeconds: 4,
    evidenceLinks: [LINKS.alerts, LINKS.audit, LINKS.monitoring],
  },
  {
    id: 'identity-key-mismatch',
    letter: 'E',
    name: 'Sensor Identity / Key Mismatch',
    description:
      'A payload claims sensorId COD-OUT-001 but is signed with the registered PH-OUT-001 key and names that key.',
    threatCategory: 'Identity confusion / key misuse',
    mechanismTested: 'Key-to-sensor/site/station/parameter binding in both registries',
    expectedResponse: 'Both services reject with KEY_SENSOR_MISMATCH; no trusted reading; a security event is recorded.',
    severity: 'HIGH',
    requiresConfirmation: false,
    requiresDemoIdentities: false,
    estimatedDurationSeconds: 3,
    evidenceLinks: [LINKS.alerts, LINKS.monitoring],
  },
  {
    id: 'compromised-signing-key',
    letter: 'F',
    name: 'Authorised Insider / Compromised Signing Key',
    description:
      'SIMULATED COMPROMISED KEY: a dedicated, explicitly marked demo COD identity (LAB-COD-902) legitimately signs an intentionally manipulated COD value. Matching verified OPS-001 context is provided and the genuine FastAPI Isolation Forest evaluates the accepted reading.',
    threatCategory: 'Insider / stolen device key',
    mechanismTested: 'Process-consistency anomaly detection (cryptography alone cannot detect a legitimately signed false value)',
    expectedResponse:
      'Signatures verify at both services (expected). The ML service returns its actual classification, detection source, Isolation Forest score and threshold; the lab compares it with the verdicts on genuine readings. Detection is not guaranteed and an anomaly is not proof of fraud.',
    severity: 'CRITICAL',
    requiresConfirmation: false,
    requiresDemoIdentities: true,
    estimatedDurationSeconds: 30,
    evidenceLinks: [LINKS.anomalies, LINKS.monitoring, LINKS.audit],
  },
  {
    id: 'checkpoint-history-tampering',
    letter: 'G',
    name: 'Historical Witness Record Tampering',
    description:
      'Genuine readings are witnessed until a signed checkpoint covers them. The checkpoint and covered history are exported; one covered event is modified in a separate copy and the real offline verifier checks both copies against the independently pinned witness key fingerprint.',
    threatCategory: 'Retroactive history rewrite',
    mechanismTested: 'Witness SHA-256 hash chain + Ed25519-signed checkpoints, offline verification',
    expectedResponse:
      'The untouched export passes; the modified copy fails with the exact hash-mismatch reason; the witness database is not modified.',
    severity: 'HIGH',
    requiresConfirmation: false,
    requiresDemoIdentities: true,
    estimatedDurationSeconds: 20,
    evidenceLinks: [LINKS.audit],
  },
  {
    id: 'heartbeat-interruption',
    letter: 'H',
    name: 'Sensor Heartbeat Interruption',
    description:
      'The Attack Lab demo sensor (LAB-COD-901) streams signed heartbeats, then stops. The availability engine is observed moving it to STALE and OFFLINE; heartbeats are then restored and recovery is observed.',
    threatCategory: 'Availability / communication loss',
    mechanismTested: 'Signed heartbeats + availability state machine + alert deduplication',
    expectedResponse:
      'STALE warning, OFFLINE high-severity alert, persistent recovery event and incident resolution, with no duplicate alerts. Communication loss does not prove intentional tampering.',
    severity: 'MEDIUM',
    requiresConfirmation: true,
    requiresDemoIdentities: true,
    estimatedDurationSeconds: 75,
    evidenceLinks: [LINKS.sensors, LINKS.alerts],
  },
  {
    id: 'witness-outage',
    letter: 'I',
    name: 'Witness Service Outage',
    description:
      'After a successful dual delivery, the demo sensor’s delivery path to the witness is isolated (simulated network partition; the shared witness process keeps running). A new signed reading is sent, the durable outbox is checked, the path is restored and the original envelope is retried without re-signing.',
    threatCategory: 'Availability / independent-observer gap',
    mechanismTested: 'Independent dual delivery, durable outbox and idempotent retry',
    expectedResponse:
      'Primary accepts while witness delivery fails; the outbox keeps the original envelope; the retry is accepted by the witness with the same signature; the sensor is not marked OFFLINE because of the witness failure.',
    severity: 'MEDIUM',
    requiresConfirmation: true,
    requiresDemoIdentities: true,
    estimatedDurationSeconds: 15,
    evidenceLinks: [LINKS.audit, LINKS.sensors, LINKS.monitoring],
  },
];

export function getScenarioDefinition(id: string): ScenarioDefinition | undefined {
  return SCENARIO_CATALOG.find((s) => s.id === id);
}

export function isScenarioId(id: unknown): id is ScenarioId {
  return typeof id === 'string' && SCENARIO_CATALOG.some((s) => s.id === id);
}
