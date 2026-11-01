import fs from 'node:fs';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { LAB_COMPROMISED_SENSOR_CODE, LAB_SENSOR_CODE } from './config.js';
import type { AttackLabEngine } from './engine.js';
import { AttackLabError, type AttackLabRunRecord } from './types.js';

export interface MaintenanceCheck {
  ok: boolean;
  label: string;
}

/**
 * Restores the demo environment for the next demonstration without deleting evidence.
 * It never deletes telemetry, audit events, witness records, security events, alerts or run evidence.
 */
export async function restoreDemoEnvironment(
  engine: AttackLabEngine,
  options: { confirm: boolean }
): Promise<{ actions: string[] }> {
  if (options.confirm !== true) {
    throw new AttackLabError('CONFIRMATION_REQUIRED', 'Refusing to restore the demo environment without explicit confirmation (--confirm).', 400);
  }
  const safety = await engine.safety();
  if (!safety.ok) {
    throw new AttackLabError('ATTACK_LAB_MISCONFIGURED', 'Safety checks failed; refusing to modify any database.', 503, safety.checks.filter((c) => !c.ok));
  }
  const running = await engine.runs.getRunningRun();
  if (running) {
    throw new AttackLabError('RUN_IN_PROGRESS', 'A scenario is running; restore after it finishes.', 409, { runId: running.id });
  }

  const pool = engine.primaryPool;
  const actions: string[] = [];

  const deactivated = await pool.query(
    "UPDATE sensors SET status = 'INACTIVE' WHERE is_demo_identity = TRUE AND status <> 'INACTIVE'"
  );
  actions.push(`Demo identity sensors set INACTIVE: ${deactivated.rowCount ?? 0}`);

  const demoAvailability = await pool.query(
    `UPDATE alerts SET status = 'RESOLVED', resolved_at = now(),
            resolution_note = 'Attack Lab demo restore: demo sensor taken out of service'
     WHERE status IN ('OPEN', 'ACKNOWLEDGED')
       AND alert_type IN ('SENSOR_STALE', 'SENSOR_OFFLINE')
       AND sensor_id IN (SELECT id FROM sensors WHERE is_demo_identity = TRUE)`
  );
  actions.push(`Open availability incidents on demo sensors resolved: ${demoAvailability.rowCount ?? 0}`);

  const labAlerts = await pool.query(
    `UPDATE alerts SET status = 'RESOLVED', resolved_at = now(),
            resolution_note = 'Attack Lab demo restore: alert raised by a recorded Attack Lab run (evidence retained)'
     WHERE status IN ('OPEN', 'ACKNOWLEDGED')
       AND id::text IN (SELECT jsonb_array_elements_text(alert_ids) FROM attack_lab_runs)`
  );
  actions.push(`Open alerts linked to recorded Attack Lab runs resolved (records kept): ${labAlerts.rowCount ?? 0}`);

  const outboxDir = path.join(engine.config.labSecretsDir, 'outbox');
  if (fs.existsSync(outboxDir)) {
    const files = fs.readdirSync(outboxDir).filter((f) => f.endsWith('.json'));
    for (const f of files) fs.unlinkSync(path.join(outboxDir, f));
    actions.push(`Attack Lab outbox entries cleared: ${files.length} (the sensor stream outbox is untouched)`);
  }
  if (fs.existsSync(engine.config.workDir)) {
    fs.rmSync(engine.config.workDir, { recursive: true, force: true });
    actions.push(`Temporary checkpoint export copies removed from ${engine.config.workDir}`);
  }
  return { actions };
}

function verifierVerdict(engine: AttackLabEngine, file: string, fingerprint: string): string | null {
  const tsxCli = path.join(engine.config.repoRoot, 'node_modules', 'tsx', 'dist', 'cli.mjs');
  const res = spawnSync(
    process.execPath,
    [tsxCli, path.join(engine.config.repoRoot, 'scripts', 'verify-checkpoint.ts'), `--file=${file}`, `--pinned-fingerprint=${fingerprint}`, '--json'],
    { cwd: engine.config.repoRoot, encoding: 'utf-8', timeout: 120000 }
  );
  const line = (res.stdout || '').trim().split('\n').reverse().find((l) => l.startsWith('{'));
  if (!line) return null;
  try {
    return (JSON.parse(line) as { overallStatus: string }).overallStatus;
  } catch {
    return null;
  }
}

/**
 * Re-checks persisted evidence of recorded runs against the live databases and services
 * (used by `npm run demo:verify`).
 */
export async function verifyRecordedRun(engine: AttackLabEngine, run: AttackLabRunRecord): Promise<MaintenanceCheck[]> {
  const ctx = engine.evidenceContext();
  const ev = run.verificationEvidence as Record<string, unknown>;
  const checks: MaintenanceCheck[] = [];
  const pool = engine.primaryPool;

  const existsIn = async (table: 'security_events' | 'alerts', ids: string[]) => {
    if (ids.length === 0) return 0;
    const r = await pool.query<{ n: string }>(`SELECT count(*)::text AS n FROM ${table} WHERE id = ANY($1::uuid[])`, [ids]);
    return Number(r.rows[0]?.n || 0);
  };

  checks.push({ ok: run.expectationMet === true, label: `Recorded outcome ${run.outcome} (${run.classification}); expectation met: ${run.expectationMet}` });

  switch (run.scenarioId) {
    case 'telemetry-tampering':
    case 'unknown-signing-key':
    case 'identity-key-mismatch': {
      const messageId = String(ev['messageId'] ?? '');
      const primaryCount = await ctx.primaryReadingCount(messageId);
      const witness = await ctx.witnessEvent(messageId);
      checks.push({ ok: primaryCount === 0, label: `Rejected message ${messageId} absent from trusted telemetry (${primaryCount})` });
      checks.push({ ok: !witness.found, label: `Rejected message absent from witness (HTTP ${witness.httpStatus})` });
      break;
    }
    case 'invalid-tamper-signal': {
      const eventId = String(ev['eventId'] ?? '');
      const r = await pool.query<{ n: string }>('SELECT count(*)::text AS n FROM tamper_events WHERE event_id = $1', [eventId]);
      const a = await pool.query<{ n: string }>('SELECT count(*)::text AS n FROM alerts WHERE deduplication_key = $1', [`tamper:${eventId}`]);
      checks.push({ ok: Number(r.rows[0]?.n || 0) === 0, label: `Forged tamper event ${eventId} absent from tamper_events` });
      checks.push({ ok: Number(a.rows[0]?.n || 0) === 0, label: 'No PHYSICAL_TAMPER alert exists for the forged event' });
      break;
    }
    case 'replay-attack': {
      const captured = String(ev['capturedMessageId'] ?? '');
      const rollback = String(ev['rollbackMessageId'] ?? '');
      const c1 = await ctx.primaryReadingCount(captured);
      const a1 = await ctx.primaryAuditEventCount(captured);
      const c2 = await ctx.primaryReadingCount(rollback);
      const w2 = await ctx.witnessEvent(rollback);
      checks.push({ ok: c1 === 1 && a1 === 1, label: `Captured message still has exactly one record (${c1}) and one ingestion audit event (${a1})` });
      checks.push({ ok: c2 === 0 && !w2.found, label: 'Rolled-back message absent from Primary and Witness' });
      break;
    }
    case 'compromised-signing-key': {
      const messageId = String(ev['messageId'] ?? '');
      checks.push({ ok: (await ctx.primaryReadingCount(messageId)) === 1, label: 'Compromised-key reading stored once (crypto cannot reject it)' });
      const arId = run.mlResult?.anomalyResultId;
      if (arId) {
        const r = await pool.query<{ status: string }>('SELECT status FROM anomaly_results WHERE id = $1', [arId]);
        checks.push({ ok: r.rows[0]?.status === run.mlResult?.status, label: `Persisted anomaly result ${arId} status ${r.rows[0]?.status ?? 'missing'}` });
      }
      break;
    }
    case 'checkpoint-history-tampering': {
      const original = ev['originalExport'] as { path?: string; sha256?: string } | undefined;
      const modified = ev['modifiedExport'] as { path?: string } | undefined;
      const fingerprint = String(ev['trustedFingerprint'] ?? '');
      if (original?.path && fs.existsSync(original.path) && modified?.path && fs.existsSync(modified.path)) {
        checks.push({ ok: verifierVerdict(engine, original.path, fingerprint) === 'PASS', label: 'Untouched export still verifies (PASS)' });
        checks.push({ ok: verifierVerdict(engine, modified.path, fingerprint) === 'FAIL', label: 'Modified export still fails verification (FAIL)' });
      } else {
        checks.push({ ok: true, label: 'Export copies were removed by demo:restore; re-run scenario G to regenerate' });
      }
      const target = String(ev['targetMessageId'] ?? '');
      const w = await ctx.witnessEvent(target);
      checks.push({ ok: w.found, label: `Target witness record still present (sequence ${w.event?.witnessSequence ?? 'n/a'})` });
      break;
    }
    case 'heartbeat-interruption': {
      checks.push({ ok: (await existsIn('alerts', run.alertIds)) === run.alertIds.length, label: `Availability alerts persisted: ${run.alertIds.length}` });
      break;
    }
    case 'witness-outage': {
      const messageId = String(ev['messageId'] ?? '');
      const w = await ctx.witnessEvent(messageId);
      checks.push({ ok: (await ctx.primaryReadingCount(messageId)) === 1, label: 'Outage reading stored once in Primary' });
      checks.push({ ok: w.found, label: `Outage reading present in Witness after retry (sequence ${w.event?.witnessSequence ?? 'n/a'})` });
      break;
    }
  }

  if (run.securityEventIds.primary.length > 0) {
    const n = await existsIn('security_events', run.securityEventIds.primary);
    checks.push({ ok: n === run.securityEventIds.primary.length, label: `Primary security events persisted: ${n}/${run.securityEventIds.primary.length}` });
  }
  if (run.alertIds.length > 0 && run.scenarioId !== 'heartbeat-interruption') {
    const n = await existsIn('alerts', run.alertIds);
    checks.push({ ok: n === run.alertIds.length, label: `Linked alerts persisted: ${n}/${run.alertIds.length}` });
  }
  return checks;
}

export const DEMO_IDENTITY_CODES = [LAB_SENSOR_CODE, LAB_COMPROMISED_SENSOR_CODE];
