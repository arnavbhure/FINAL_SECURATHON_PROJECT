import type { AttackLabStatus, AttackMlEvidence, AttackRun, AttackRunOutcome, AttackScenario } from '../types/index.js';

export type Tone = 'success' | 'info' | 'warning' | 'danger' | 'neutral';

/** Visual tone per outcome. DETECTED/SUSPICIOUS are detections, never shown as "safe". */
export function outcomeTone(outcome: AttackRunOutcome | null | undefined): Tone {
  switch (outcome) {
    case 'PREVENTED':
      return 'success';
    case 'DETECTED':
      return 'info';
    case 'SUSPICIOUS':
      return 'warning';
    case 'ACCEPTED':
      return 'danger';
    default:
      return 'neutral';
  }
}

export function outcomeLabel(outcome: AttackRunOutcome | null | undefined): string {
  return outcome ? outcome.replace(/_/g, ' ') : 'RUNNING';
}

export const TONE_STYLES: Record<Tone, { color: string; background: string; border: string }> = {
  success: { color: 'var(--color-success)', background: 'var(--color-success-bg)', border: 'var(--color-success-border)' },
  info: { color: 'var(--air-force-blue)', background: 'var(--air-force-blue-light)', border: 'var(--air-force-blue-border)' },
  warning: { color: 'var(--amber-gold)', background: 'var(--amber-gold-light)', border: 'var(--amber-gold-border)' },
  danger: { color: 'var(--brick-red)', background: 'var(--brick-red-light)', border: 'var(--brick-red-border)' },
  neutral: { color: 'var(--text-muted)', background: 'var(--bg-surface-accent)', border: 'var(--border-subtle)' },
};

/**
 * Lines shown for an ML result. Only values actually returned by the model are shown;
 * the anomaly score is never presented as a COD prediction.
 */
export function mlResultLines(ml: AttackMlEvidence | null | undefined): Array<{ label: string; value: string }> {
  if (!ml) return [];
  const lines: Array<{ label: string; value: string }> = [{ label: 'Classification', value: ml.status.replace(/_/g, ' ') }];
  if (ml.anomalyScore !== null && ml.anomalyScore !== undefined) lines.push({ label: 'Anomaly score', value: String(ml.anomalyScore) });
  if (ml.anomalyThreshold !== null && ml.anomalyThreshold !== undefined) lines.push({ label: 'Decision threshold', value: String(ml.anomalyThreshold) });
  if (ml.isAnomaly !== null && ml.isAnomaly !== undefined) lines.push({ label: 'Model anomaly flag', value: ml.isAnomaly ? 'true' : 'false' });
  if (ml.detectionSources && ml.detectionSources.length > 0) lines.push({ label: 'Detection sources', value: ml.detectionSources.join(', ') });
  if (ml.modelVersion) lines.push({ label: 'Model version', value: ml.modelVersion });
  if (ml.evaluatedAt) lines.push({ label: 'Evaluated at', value: new Date(ml.evaluatedAt).toLocaleString() });
  return lines;
}

export function canRunScenario(
  status: AttackLabStatus | null,
  scenario: AttackScenario
): { allowed: boolean; reason: string | null } {
  if (!status) return { allowed: false, reason: 'Lab status unavailable' };
  if (!status.canExecute) return { allowed: false, reason: 'Read-only: only authorized demo administrators can run scenarios' };
  if (!status.safety.ok) return { allowed: false, reason: 'Safety checks failed on the server' };
  if (status.activeRun) return { allowed: false, reason: 'Another scenario is running' };
  if (!status.services.primary.reachable || !status.services.witness.reachable) {
    return { allowed: false, reason: 'Primary API or Witness unreachable' };
  }
  if (scenario.requiresDemoIdentities && Object.values(status.demoIdentities).some((d) => !d.ready)) {
    return { allowed: false, reason: 'Demo identities not provisioned (npm run demo:provision)' };
  }
  return { allowed: true, reason: null };
}

export function runDurationSeconds(run: Pick<AttackRun, 'startedAt' | 'finishedAt'>, now = Date.now()): number {
  const end = run.finishedAt ? Date.parse(run.finishedAt) : now;
  return Math.max(0, Math.round((end - Date.parse(run.startedAt)) / 1000));
}
