import pg from 'pg';
import type { Pool } from 'pg';
import { MlClient } from '../services/ml-client.js';
import type { AttackLabConfig } from './config.js';
import { getScenarioDefinition, SCENARIO_CATALOG } from './catalog.js';
import { ScenarioContext, StepRecorder } from './context.js';
import { exchange } from './http.js';
import { AttackLabRunRepository } from './run.repository.js';
import { evaluateSafety, type SafetyReport } from './safety.js';
import {
  runIdentityKeyMismatch,
  runInvalidTamperSignal,
  runTelemetryTampering,
  runUnknownSigningKey,
} from './scenarios/rejection.js';
import { runReplayAttack } from './scenarios/replay.js';
import { runCompromisedSigningKey } from './scenarios/compromised.js';
import { runCheckpointHistoryTampering } from './scenarios/checkpoint.js';
import { runHeartbeatInterruption, runWitnessOutage } from './scenarios/availability.js';
import {
  AttackLabError,
  type AttackLabRunRecord,
  type RunActor,
  type ScenarioId,
  type ScenarioResult,
} from './types.js';

type ScenarioRunner = (ctx: ScenarioContext) => Promise<ScenarioResult>;

const RUNNERS: Record<ScenarioId, ScenarioRunner> = {
  'telemetry-tampering': runTelemetryTampering,
  'unknown-signing-key': runUnknownSigningKey,
  'invalid-tamper-signal': runInvalidTamperSignal,
  'replay-attack': runReplayAttack,
  'identity-key-mismatch': runIdentityKeyMismatch,
  'compromised-signing-key': runCompromisedSigningKey,
  'checkpoint-history-tampering': runCheckpointHistoryTampering,
  'heartbeat-interruption': runHeartbeatInterruption,
  'witness-outage': runWitnessOutage,
};

export interface LabServiceStatus {
  reachable: boolean;
  httpStatus: number | null;
  detail: string;
}

export interface AttackLabStatus {
  environmentLabel: 'DEMO ENVIRONMENT';
  siteCode: string;
  stationCode: string;
  safety: SafetyReport;
  services: {
    primary: LabServiceStatus;
    witness: LabServiceStatus & { witnessId: string | null; displayName: string | null };
    ml: LabServiceStatus & { enabledOnPrimary: boolean; ready: boolean | null; modelVersion: string | null; modelMode: string | null };
  };
  demoIdentities: Record<string, { ready: boolean; keyId: string | null }>;
  activeRun: { id: string; scenarioId: string; startedAt: string } | null;
}

/**
 * The Attack Simulation Engine shared by the API routes, CLI commands and integration tests.
 * It only executes catalogued scenarios against the configured local demo services.
 */
export class AttackLabEngine {
  readonly runs: AttackLabRunRepository;
  private readonly witnessPool: Pool;
  private readonly ownsWitnessPool: boolean;

  constructor(
    readonly config: AttackLabConfig,
    readonly primaryPool: Pool,
    witnessPool?: Pool
  ) {
    this.runs = new AttackLabRunRepository(primaryPool);
    this.ownsWitnessPool = !witnessPool;
    this.witnessPool =
      witnessPool ||
      new pg.Pool({ connectionString: config.witnessDatabaseUrl, max: 3, idleTimeoutMillis: 5000, connectionTimeoutMillis: 5000 });
    this.witnessPool.on('error', (err: Error) => console.error('[ATTACK_LAB] witness pool error:', err.message));
  }

  async close(): Promise<void> {
    if (this.ownsWitnessPool) await this.witnessPool.end();
  }

  catalog() {
    return SCENARIO_CATALOG;
  }

  /** A read-only evidence context (no run) for status probes and `demo:verify`. */
  evidenceContext(): ScenarioContext {
    return new ScenarioContext(this.config, this.primaryPool, this.witnessPool, 'evidence', new StepRecorder(async () => {}), new Date());
  }

  async safety(): Promise<SafetyReport> {
    return evaluateSafety(this.config, this.primaryPool, this.witnessPool);
  }

  async status(): Promise<AttackLabStatus> {
    const [safety, primary, witness, running] = await Promise.all([
      this.safety(),
      exchange('PRIMARY', this.config.primaryBaseUrl, '/api/v1/health', { method: 'GET', timeoutMs: 3000 }),
      exchange('WITNESS', this.config.witnessBaseUrl, '/witness/v1/health', { method: 'GET', timeoutMs: 3000 }),
      this.runs.getRunningRun(),
    ]);
    const pBody = (primary.body || {}) as Record<string, unknown>;
    const wBody = (witness.body || {}) as Record<string, unknown>;
    // Read-only status probe of the ML service (GET /health and /model/status); no telemetry is sent.
    const mlHealth = await new MlClient({
      baseUrl: this.config.mlBaseUrl,
      timeoutMs: Math.min(this.config.mlTimeoutMs, 3000),
      serviceToken: this.config.mlServiceToken,
    }).healthCheck();

    const probe = this.evidenceContext();
    const demoIdentities: AttackLabStatus['demoIdentities'] = {};
    for (const code of ['LAB-COD-901', 'LAB-COD-902']) {
      try {
        const s = await probe.labIdentityStatus(code);
        demoIdentities[code] = { ready: s.ready, keyId: s.keyId };
      } catch {
        demoIdentities[code] = { ready: false, keyId: null };
      }
    }

    return {
      environmentLabel: 'DEMO ENVIRONMENT',
      siteCode: this.config.siteCode,
      stationCode: this.config.stationCode,
      safety,
      services: {
        primary: {
          reachable: primary.ok,
          httpStatus: primary.status,
          detail: primary.ok ? `UP (environment ${String(pBody['environment'] ?? 'unknown')})` : primary.networkError || `HTTP ${primary.status}`,
        },
        witness: {
          reachable: witness.ok,
          httpStatus: witness.status,
          detail: witness.ok ? 'UP' : witness.networkError || `HTTP ${witness.status}`,
          witnessId: typeof wBody['witnessId'] === 'string' ? (wBody['witnessId'] as string) : null,
          displayName: typeof wBody['displayName'] === 'string' ? (wBody['displayName'] as string) : null,
        },
        ml: {
          reachable: mlHealth.reachable,
          httpStatus: null,
          detail: mlHealth.reachable ? 'FastAPI reachable' : mlHealth.error || 'unreachable',
          enabledOnPrimary: Boolean(pBody['mlEnabled']),
          ready: mlHealth.ready ?? null,
          modelVersion: mlHealth.modelVersion ?? null,
          modelMode: mlHealth.modelMode ?? null,
        },
      },
      demoIdentities,
      activeRun: running ? { id: running.id, scenarioId: running.scenarioId, startedAt: running.startedAt } : null,
    };
  }

  /**
   * Validates the request and safety gates, records the run, and starts execution.
   * `completion` resolves with the final persisted record (the API does not await it).
   */
  async startRun(
    scenarioId: string,
    actor: RunActor,
    options: { confirm?: boolean } = {}
  ): Promise<{ runId: string; completion: Promise<AttackLabRunRecord> }> {
    const definition = getScenarioDefinition(scenarioId);
    if (!definition) {
      throw new AttackLabError('UNKNOWN_SCENARIO', `Unknown scenario: ${scenarioId}`, 404);
    }
    if (definition.requiresConfirmation && options.confirm !== true) {
      throw new AttackLabError(
        'CONFIRMATION_REQUIRED',
        `Scenario ${definition.id} changes demo sensor state or isolates a delivery path; explicit confirmation is required.`,
        400
      );
    }
    const safety = await this.safety();
    if (!safety.ok) {
      throw new AttackLabError(
        'ATTACK_LAB_MISCONFIGURED',
        'Attack Lab safety checks failed; refusing to run scenarios.',
        503,
        safety.checks.filter((c) => !c.ok)
      );
    }

    const runId = await this.runs.createRun(definition.id, actor, this.config.siteCode);
    const recorder = new StepRecorder((steps) => this.runs.updateSteps(runId, steps));
    const ctx = new ScenarioContext(this.config, this.primaryPool, this.witnessPool, runId, recorder, new Date());
    const runner = RUNNERS[definition.id];

    const completion = (async () => {
      try {
        const result = await runner(ctx);
        await this.runs.completeRun(runId, recorder.steps, result);
      } catch (err) {
        console.error(`[ATTACK_LAB] Scenario ${definition.id} failed:`, (err as Error).message);
        await this.runs.failRun(runId, recorder.steps, (err as Error).message).catch(() => undefined);
      }
      const record = await this.runs.getRun(runId);
      if (!record) throw new Error(`Run ${runId} disappeared`);
      return record;
    })();

    return { runId, completion };
  }

  /** Runs a scenario to completion (CLI and tests). */
  async runScenario(scenarioId: string, actor: RunActor, options: { confirm?: boolean } = {}): Promise<AttackLabRunRecord> {
    const { completion } = await this.startRun(scenarioId, actor, options);
    return completion;
  }
}
