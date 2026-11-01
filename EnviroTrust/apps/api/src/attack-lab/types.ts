/**
 * Attack Simulation Lab — shared types.
 * Everything recorded here is evidence derived from real HTTP responses, database rows and
 * verifier output. Private keys, tokens and credentials are never part of these structures.
 */

export type ScenarioId =
  | 'telemetry-tampering'
  | 'unknown-signing-key'
  | 'invalid-tamper-signal'
  | 'replay-attack'
  | 'identity-key-mismatch'
  | 'compromised-signing-key'
  | 'checkpoint-history-tampering'
  | 'heartbeat-interruption'
  | 'witness-outage';

export type RunOutcome =
  | 'PREVENTED'
  | 'DETECTED'
  | 'SUSPICIOUS'
  | 'ACCEPTED'
  | 'PENDING'
  | 'INCONCLUSIVE'
  | 'SERVICE_UNAVAILABLE';

export type RunStatus = 'RUNNING' | 'COMPLETED' | 'FAILED' | 'ABANDONED';

export type ActorSource = 'UI' | 'CLI' | 'TEST';

export type StepStatus = 'RUNNING' | 'PASSED' | 'FAILED' | 'INFO' | 'SKIPPED';

export interface RunStep {
  index: number;
  key: string;
  title: string;
  status: StepStatus;
  startedAt: string;
  finishedAt: string | null;
  detail: string;
  data?: Record<string, unknown> | undefined;
}

/** One real HTTP exchange with a service, with response body bounded and request secrets omitted. */
export interface HttpExchange {
  target: 'PRIMARY' | 'WITNESS';
  method: 'GET' | 'POST';
  endpoint: string;
  status: number | null;
  ok: boolean;
  code: string | null;
  message: string | null;
  requestId: string | null;
  body: unknown;
  networkError: string | null;
  durationMs: number;
}

export interface ScenarioDefinition {
  id: ScenarioId;
  letter: string;
  name: string;
  description: string;
  threatCategory: string;
  mechanismTested: string;
  expectedResponse: string;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
  /** Disruptive scenarios (they change demo sensor state or isolate a delivery path) need explicit confirmation. */
  requiresConfirmation: boolean;
  /** Scenarios that use the dedicated demo identities provisioned by `npm run demo:provision`. */
  requiresDemoIdentities: boolean;
  estimatedDurationSeconds: number;
  evidenceLinks: Array<{ label: string; path: string }>;
}

export interface MlEvidence {
  status:
    | 'SUSPICIOUS'
    | 'CONSISTENT'
    | 'NOT_EVALUATED'
    | 'ML_NOT_ENABLED'
    | 'ML_UNAVAILABLE'
    | 'PENDING';
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

export interface ScenarioResult {
  outcome: RunOutcome;
  classification: string;
  summary: string;
  expectationMet: boolean;
  primaryOutcome: Record<string, unknown> | null;
  witnessOutcome: Record<string, unknown> | null;
  mlResult: MlEvidence | null;
  alertIds: string[];
  securityEventIds: { primary: string[]; witness: string[] };
  verificationEvidence: Record<string, unknown>;
}

export interface AttackLabRunRecord {
  id: string;
  scenarioId: ScenarioId;
  status: RunStatus;
  outcome: RunOutcome | null;
  classification: string | null;
  summary: string | null;
  expectationMet: boolean | null;
  actorUserId: string | null;
  actorLabel: string;
  actorSource: ActorSource;
  siteCode: string;
  startedAt: string;
  finishedAt: string | null;
  steps: RunStep[];
  primaryOutcome: Record<string, unknown> | null;
  witnessOutcome: Record<string, unknown> | null;
  mlResult: MlEvidence | null;
  alertIds: string[];
  securityEventIds: { primary: string[]; witness: string[] };
  verificationEvidence: Record<string, unknown>;
  error: string | null;
}

export interface RunActor {
  userId: string | null;
  label: string;
  source: ActorSource;
}

export class AttackLabError extends Error {
  constructor(
    public readonly code:
      | 'ATTACK_LAB_DISABLED'
      | 'ATTACK_LAB_MISCONFIGURED'
      | 'UNKNOWN_SCENARIO'
      | 'CONFIRMATION_REQUIRED'
      | 'RUN_IN_PROGRESS'
      | 'DEMO_IDENTITIES_MISSING'
      | 'NOT_AUTHORIZED',
    message: string,
    public readonly httpStatus: number,
    public readonly details?: unknown
  ) {
    super(message);
    this.name = 'AttackLabError';
  }
}
