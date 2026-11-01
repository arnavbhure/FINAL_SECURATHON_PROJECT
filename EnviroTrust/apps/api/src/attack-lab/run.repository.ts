import type { Pool, QueryResultRow } from 'pg';
import type {
  ActorSource,
  AttackLabRunRecord,
  RunActor,
  RunStep,
  ScenarioId,
  ScenarioResult,
} from './types.js';
import { AttackLabError } from './types.js';

interface RunRow extends QueryResultRow {
  id: string;
  scenario_id: ScenarioId;
  status: AttackLabRunRecord['status'];
  outcome: AttackLabRunRecord['outcome'];
  classification: string | null;
  summary: string | null;
  expectation_met: boolean | null;
  actor_user_id: string | null;
  actor_label: string;
  actor_source: ActorSource;
  site_code: string;
  started_at: Date;
  finished_at: Date | null;
  steps: RunStep[];
  primary_outcome: Record<string, unknown> | null;
  witness_outcome: Record<string, unknown> | null;
  ml_result: AttackLabRunRecord['mlResult'];
  alert_ids: string[];
  security_event_ids: AttackLabRunRecord['securityEventIds'] | string[];
  verification_evidence: Record<string, unknown>;
  error: string | null;
}

function toRecord(row: RunRow): AttackLabRunRecord {
  const sec = row.security_event_ids;
  return {
    id: row.id,
    scenarioId: row.scenario_id,
    status: row.status,
    outcome: row.outcome,
    classification: row.classification,
    summary: row.summary,
    expectationMet: row.expectation_met,
    actorUserId: row.actor_user_id,
    actorLabel: row.actor_label,
    actorSource: row.actor_source,
    siteCode: row.site_code,
    startedAt: row.started_at.toISOString(),
    finishedAt: row.finished_at ? row.finished_at.toISOString() : null,
    steps: row.steps || [],
    primaryOutcome: row.primary_outcome,
    witnessOutcome: row.witness_outcome,
    mlResult: row.ml_result,
    alertIds: row.alert_ids || [],
    securityEventIds: Array.isArray(sec) ? { primary: sec, witness: [] } : sec || { primary: [], witness: [] },
    verificationEvidence: row.verification_evidence || {},
    error: row.error,
  };
}

/** Demo-run evidence store. Kept in its own table; never mixed with trusted telemetry. */
export class AttackLabRunRepository {
  constructor(private readonly pool: Pool) {}

  async createRun(scenarioId: ScenarioId, actor: RunActor, siteCode: string): Promise<string> {
    // Runs left RUNNING by a crashed process must not block the lab forever.
    await this.pool.query(
      `UPDATE attack_lab_runs
       SET status = 'ABANDONED', finished_at = now(), error = 'Run did not finish (process stopped or crashed)'
       WHERE status = 'RUNNING' AND started_at < now() - interval '15 minutes'`
    );
    try {
      const res = await this.pool.query<{ id: string }>(
        `INSERT INTO attack_lab_runs (scenario_id, status, actor_user_id, actor_label, actor_source, site_code)
         VALUES ($1, 'RUNNING', $2, $3, $4, $5)
         RETURNING id`,
        [scenarioId, actor.userId, actor.label, actor.source, siteCode]
      );
      const id = res.rows[0]?.id;
      if (!id) throw new Error('Failed to create attack lab run');
      return id;
    } catch (err) {
      if ((err as { code?: string }).code === '23505') {
        const running = await this.getRunningRun();
        throw new AttackLabError(
          'RUN_IN_PROGRESS',
          'Another Attack Lab scenario is currently running. Wait for it to finish.',
          409,
          running ? { runId: running.id, scenarioId: running.scenarioId } : undefined
        );
      }
      throw err;
    }
  }

  async updateSteps(runId: string, steps: RunStep[]): Promise<void> {
    await this.pool.query('UPDATE attack_lab_runs SET steps = $1 WHERE id = $2', [JSON.stringify(steps), runId]);
  }

  async completeRun(runId: string, steps: RunStep[], result: ScenarioResult): Promise<void> {
    await this.pool.query(
      `UPDATE attack_lab_runs
       SET status = 'COMPLETED', finished_at = now(), steps = $2, outcome = $3, classification = $4,
           summary = $5, expectation_met = $6, primary_outcome = $7, witness_outcome = $8, ml_result = $9,
           alert_ids = $10, security_event_ids = $11, verification_evidence = $12
       WHERE id = $1`,
      [
        runId,
        JSON.stringify(steps),
        result.outcome,
        result.classification,
        result.summary,
        result.expectationMet,
        result.primaryOutcome ? JSON.stringify(result.primaryOutcome) : null,
        result.witnessOutcome ? JSON.stringify(result.witnessOutcome) : null,
        result.mlResult ? JSON.stringify(result.mlResult) : null,
        JSON.stringify(result.alertIds),
        JSON.stringify(result.securityEventIds),
        JSON.stringify(result.verificationEvidence),
      ]
    );
  }

  async failRun(runId: string, steps: RunStep[], error: string): Promise<void> {
    await this.pool.query(
      `UPDATE attack_lab_runs
       SET status = 'FAILED', finished_at = now(), steps = $2, outcome = 'INCONCLUSIVE',
           summary = 'Inconclusive — scenario execution failed', expectation_met = false, error = $3
       WHERE id = $1`,
      [runId, JSON.stringify(steps), error.slice(0, 2000)]
    );
  }

  async getRun(runId: string): Promise<AttackLabRunRecord | null> {
    if (!/^[0-9a-f-]{36}$/i.test(runId)) return null;
    const res = await this.pool.query<RunRow>('SELECT * FROM attack_lab_runs WHERE id = $1', [runId]);
    return res.rows[0] ? toRecord(res.rows[0]) : null;
  }

  async getRunningRun(): Promise<AttackLabRunRecord | null> {
    const res = await this.pool.query<RunRow>(
      "SELECT * FROM attack_lab_runs WHERE status = 'RUNNING' ORDER BY started_at DESC LIMIT 1"
    );
    return res.rows[0] ? toRecord(res.rows[0]) : null;
  }

  /**
   * Run history. Runs recorded by automated tests (which may use mocks) are excluded unless requested,
   * so they are never presented as live demonstrations.
   */
  async listRuns(
    options: { siteCodes?: string[]; scenarioId?: string; limit?: number; includeTestRuns?: boolean } = {}
  ): Promise<AttackLabRunRecord[]> {
    const conditions: string[] = options.includeTestRuns ? [] : ["actor_source <> 'TEST'"];
    const params: unknown[] = [];
    if (options.siteCodes) {
      params.push(options.siteCodes);
      conditions.push(`site_code = ANY($${params.length})`);
    }
    if (options.scenarioId) {
      params.push(options.scenarioId);
      conditions.push(`scenario_id = $${params.length}`);
    }
    params.push(Math.min(Math.max(options.limit ?? 25, 1), 100));
    const res = await this.pool.query<RunRow>(
      `SELECT * FROM attack_lab_runs
       ${conditions.length ? `WHERE ${conditions.join(' AND ')}` : ''}
       ORDER BY started_at DESC
       LIMIT $${params.length}`,
      params
    );
    return res.rows.map(toRecord);
  }

  /** Latest completed live (UI/CLI) run per scenario (used by `npm run demo:verify`). */
  async latestCompletedPerScenario(): Promise<AttackLabRunRecord[]> {
    const res = await this.pool.query<RunRow>(
      `SELECT DISTINCT ON (scenario_id) *
       FROM attack_lab_runs
       WHERE status = 'COMPLETED' AND actor_source <> 'TEST'
       ORDER BY scenario_id, started_at DESC`
    );
    return res.rows.map(toRecord);
  }
}
