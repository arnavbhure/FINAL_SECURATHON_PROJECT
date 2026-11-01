import { MlClient } from '../../services/ml-client.js';
import { MlAssessmentRepository } from '../../repositories/ml-assessment.repository.js';
import { classifyCompromisedKey, summaryFor } from '../classify.js';
import { LAB_COMPROMISED_SENSOR_CODE } from '../config.js';
import { sleep, type ScenarioContext } from '../context.js';
import type { MlEvidence, ScenarioResult } from '../types.js';
import { exchangeSummary, preflight } from './rejection.js';

function num(v: unknown): number | null {
  if (v === null || v === undefined) return null;
  const n = Number(v);
  return Number.isFinite(n) ? n : null;
}

/** Waits for the genuine assessment pipeline (worker → FastAPI → anomaly_results) to evaluate the reading. */
async function awaitMlAssessment(ctx: ScenarioContext, readingId: string, mlEnabled: boolean): Promise<MlEvidence> {
  if (!mlEnabled) {
    return {
      status: 'ML_NOT_ENABLED',
      detail:
        'ML_ENABLED=false on the Primary API, so the queued assessment job is not sent to the FastAPI service. Enable ML (see JUDGE_DEMO_RUNBOOK) to obtain a real model result.',
    };
  }

  const deadline = Date.now() + ctx.config.mlWaitSeconds * 1000;
  let lastJob: { status: string | null; lastError: string | null } = { status: null, lastError: null };
  while (Date.now() < deadline) {
    const res = await ctx.primaryPool.query<{
      ar_id: string | null;
      status: string | null;
      processing_status: string | null;
      anomaly_score: string | null;
      anomaly_threshold: string | null;
      is_anomaly: boolean | null;
      detection_sources: string[] | null;
      model_version: string | null;
      evaluated_at: Date | null;
      reasons: string[] | null;
      job_status: string | null;
      last_error: string | null;
    }>(
      `SELECT ar.id AS ar_id, ar.status, ar.processing_status, ar.anomaly_score, ar.anomaly_threshold,
              ar.is_anomaly, ar.detection_sources, ar.model_version, ar.evaluated_at, ar.reasons,
              j.status AS job_status, j.last_error
       FROM telemetry_readings tr
       LEFT JOIN anomaly_results ar ON ar.reading_id = tr.id
       LEFT JOIN ml_assessment_jobs j ON j.reading_id = tr.id
       WHERE tr.id = $1`,
      [readingId]
    );
    const row = res.rows[0];
    lastJob = { status: row?.job_status ?? null, lastError: row?.last_error ?? null };
    if (row?.ar_id) {
      const base = {
        anomalyResultId: row.ar_id,
        anomalyScore: num(row.anomaly_score),
        anomalyThreshold: num(row.anomaly_threshold),
        isAnomaly: row.is_anomaly,
        detectionSources: row.detection_sources,
        modelVersion: row.model_version,
        evaluatedAt: row.evaluated_at ? row.evaluated_at.toISOString() : null,
        reasons: row.reasons || [],
      };
      if (row.status === 'SUSPICIOUS' || row.status === 'CONSISTENT') {
        return {
          ...base,
          status: row.status,
          detail:
            base.anomalyScore === null
              ? `Model returned ${row.status} without a raw anomaly score (legacy result schema).`
              : `ML service returned ${row.status}${base.detectionSources?.length ? ` (detection source: ${base.detectionSources.join(', ')})` : ''}; Isolation Forest anomaly score ${base.anomalyScore} vs decision threshold ${base.anomalyThreshold}${base.anomalyThreshold !== null && base.anomalyScore < base.anomalyThreshold ? ' (below threshold)' : ' (at or above threshold)'}.`,
        };
      }
      if (row.status === 'ERROR') {
        return { ...base, status: 'ML_UNAVAILABLE', detail: `ML processing failed: ${(row.reasons || []).join('; ')}` };
      }
      return { ...base, status: 'NOT_EVALUATED', detail: (row.reasons || []).join('; ') || 'Model did not evaluate the reading' };
    }
    if (row?.job_status === 'FAILED') {
      return { status: 'ML_UNAVAILABLE', detail: `Assessment job failed: ${row.last_error || 'unknown error'}` };
    }
    await sleep(2000);
  }
  return {
    status: 'PENDING',
    detail: `No model result within ${ctx.config.mlWaitSeconds}s (job status ${lastJob.status ?? 'unknown'}${lastJob.lastError ? `: ${lastJob.lastError}` : ''}).`,
  };
}

/** F — a dedicated demo identity legitimately signs a manipulated COD value. */
export async function runCompromisedSigningKey(ctx: ScenarioContext): Promise<ScenarioResult> {
  const unavailable = await preflight(ctx);
  if (unavailable) return unavailable;

  const idStep = await ctx.steps.begin('identity', 'SIMULATED COMPROMISED KEY — load the dedicated demo identity');
  const identity = await ctx.labIdentityStatus(LAB_COMPROMISED_SENSOR_CODE);
  if (!identity.ready) {
    await ctx.steps.finish(idStep, 'FAILED', `Demo identity ${LAB_COMPROMISED_SENSOR_CODE} is not provisioned in both registries (${JSON.stringify(identity)}). Run: npm run demo:provision`);
    return {
      outcome: 'INCONCLUSIVE',
      classification: 'DEMO_IDENTITY_MISSING',
      summary: 'Inconclusive — demo identity not provisioned (npm run demo:provision)',
      expectationMet: false,
      primaryOutcome: null,
      witnessOutcome: null,
      mlResult: null,
      alertIds: [],
      securityEventIds: { primary: [], witness: [] },
      verificationEvidence: { identity },
    };
  }
  await ctx.steps.finish(idStep, 'PASSED', `${LAB_COMPROMISED_SENSOR_CODE} / ${identity.keyId}: explicitly marked demo identity, ACTIVE in Primary and Witness registries. Private key stays server-side.`, {
    sensorId: LAB_COMPROMISED_SENSOR_CODE,
    keyId: identity.keyId,
    label: 'SIMULATED COMPROMISED KEY',
  });

  // ML readiness snapshot (read-only status probes; no telemetry is sent here).
  const mlStep = await ctx.steps.begin('ml-readiness', 'Check ML pipeline readiness');
  const health = await ctx.healthCheck();
  const mlEnabled = Boolean((health.primary.body as Record<string, unknown> | null)?.['mlEnabled']);
  const mlHealth = await new MlClient({
    baseUrl: ctx.config.mlBaseUrl,
    timeoutMs: Math.min(ctx.config.mlTimeoutMs, 4000),
    serviceToken: ctx.config.mlServiceToken,
  }).healthCheck();
  await ctx.steps.finish(
    mlStep,
    mlEnabled && mlHealth.reachable ? 'PASSED' : 'INFO',
    `Primary ML_ENABLED=${mlEnabled}; FastAPI ${mlHealth.reachable ? `reachable (model ${mlHealth.modelVersion ?? 'unknown'}, ready=${String(mlHealth.ready ?? 'unknown')})` : `unreachable (${mlHealth.error ?? 'no response'})`}`,
    { mlEnabled, mlReachable: mlHealth.reachable, modelVersion: mlHealth.modelVersion ?? null, ready: mlHealth.ready ?? null }
  );

  // Matching verified OPS-001 operating context
  const ctxStep = await ctx.steps.begin('context', 'Provide matching verified OPS-001 operating context');
  const measuredAt = new Date(Date.now() - 2000);
  const siteRes = await ctx.primaryPool.query<{ id: string }>('SELECT id FROM sites WHERE site_code = $1', [ctx.config.siteCode]);
  const siteUuid = siteRes.rows[0]?.id;
  const mlRepo = new MlAssessmentRepository(ctx.primaryPool);
  let opsContext = siteUuid ? await mlRepo.findMatchingOpsContext(siteUuid, measuredAt) : null;
  let opsSource = 'existing verified OPS-001 record';
  let opsDelivery: Record<string, unknown> | null = null;
  if (!opsContext) {
    const [p, w] = await Promise.all([
      ctx.primaryPool.query<{ n: string }>("SELECT last_sequence_no::text AS n FROM operations_sequence_cursors WHERE source_id = 'OPS-001'"),
      ctx.witnessPool.query<{ n: string }>("SELECT last_sequence::text AS n FROM witness_operations_cursors WHERE source_id = 'OPS-001'"),
    ]);
    const nextSeq = Math.max(Number(p.rows[0]?.n || 0), Number(w.rows[0]?.n || 0)) + 1;
    const ops = ctx.opsSimulator(nextSeq).generateContext({ mode: 'HIGH_LOAD', intervalDurationMinutes: 5, intervalEnd: new Date() });
    const delivered = await ctx.submitDual('ops', ops);
    opsDelivery = { primary: exchangeSummary(delivered.primary), witness: exchangeSummary(delivered.witness) };
    opsSource = `new OPS-001 record signed with the OPS-001 key (sequence ${nextSeq}; ${ctx.describe(delivered.primary)}, ${ctx.describe(delivered.witness)})`;
    opsContext = siteUuid ? await mlRepo.findMatchingOpsContext(siteUuid, measuredAt) : null;
  }
  await ctx.steps.finish(
    ctxStep,
    opsContext ? 'PASSED' : 'FAILED',
    opsContext
      ? `Using ${opsSource}: mode ${opsContext.operating_mode}, production ${opsContext.production_rate}, flow ${opsContext.wastewater_flow}, interval ${opsContext.interval_start.toISOString()} → ${opsContext.interval_end.toISOString()}`
      : 'No verified OPS-001 context matches the measurement time; the model will report insufficient context.',
    { opsContextId: opsContext?.id ?? null, opsMessageId: opsContext?.message_id ?? null, opsDelivery }
  );

  // Legitimately signed, intentionally manipulated value
  const sign = await ctx.steps.begin('sign', 'Sign an intentionally manipulated COD value with the compromised demo key');
  const device = ctx.labDevice(LAB_COMPROMISED_SENSOR_CODE, { bootId: `LAB-F-${ctx.runId.slice(0, 8)}`, initialTelemetrySequence: 1 });
  const envelope = device.generateReading({ overrideValue: ctx.config.compromisedCodValue, measuredAt: measuredAt.toISOString() });
  await ctx.steps.finish(
    sign,
    'PASSED',
    `Reported COD ${envelope.payload.value} mg/L for ${envelope.payload.sensorId} — far below the ${opsContext ? `${opsContext.operating_mode} ` : ''}process range this outlet normally shows (an insider under-reporting). Signature is genuine for this key.`,
    { messageId: envelope.payload.messageId, reportedValue: envelope.payload.value }
  );

  const submit = await ctx.steps.begin('submit', 'Submit to Primary and Witness and record the cryptographic result');
  const { primary, witness } = await ctx.submitDual('telemetry', envelope);
  const readingId = (primary.body as Record<string, unknown> | null)?.['readingId'];
  const witnessLookup = await ctx.witnessEvent(envelope.payload.messageId);
  await ctx.steps.finish(
    submit,
    primary.ok && witness.ok ? 'PASSED' : 'FAILED',
    `${ctx.describe(primary)} signatureStatus=${String((primary.body as Record<string, unknown> | null)?.['signatureStatus'] ?? 'n/a')}; ${ctx.describe(witness)}. Cryptography cannot tell a legitimately signed false value from a true one.`,
    { primary: exchangeSummary(primary), witness: exchangeSummary(witness) }
  );

  const evalStep = await ctx.steps.begin('ml', 'Await the genuine FastAPI ML assessment');
  const ml =
    primary.ok && typeof readingId === 'string'
      ? await awaitMlAssessment(ctx, readingId, mlEnabled)
      : { status: 'PENDING' as const, detail: 'Reading was not accepted by the Primary API, so no assessment was queued.' };
  await ctx.steps.finish(
    evalStep,
    ml.status === 'SUSPICIOUS' || ml.status === 'CONSISTENT' ? 'PASSED' : 'INFO',
    `${ml.status}: ${ml.detail}${ml.modelVersion ? ` Model version ${ml.modelVersion}.` : ''} The anomaly score is not a COD prediction.`,
    { ml }
  );

  // Control sample: how the same model classified genuine readings from this site in the same window.
  let control: { evaluated: number; flagged: number; windowMinutes: number } | undefined;
  if ((ml.status === 'SUSPICIOUS' || ml.status === 'CONSISTENT') && ml.modelVersion && siteUuid) {
    const c = await ctx.primaryPool.query<{ evaluated: string; flagged: string }>(
      `SELECT count(*)::text AS evaluated,
              count(*) FILTER (WHERE ar.status = 'SUSPICIOUS')::text AS flagged
       FROM anomaly_results ar
       JOIN telemetry_readings tr ON tr.id = ar.reading_id
       JOIN sensors s ON s.id = tr.sensor_id
       WHERE ar.site_id = $1
         AND ar.model_version = $2
         AND ar.status IN ('SUSPICIOUS', 'CONSISTENT')
         AND s.sensor_code <> $3
         AND ar.evaluated_at > now() - interval '30 minutes'`,
      [siteUuid, ml.modelVersion, LAB_COMPROMISED_SENSOR_CODE]
    );
    control = { evaluated: Number(c.rows[0]?.evaluated || 0), flagged: Number(c.rows[0]?.flagged || 0), windowMinutes: 30 };
    await ctx.steps.record(
      'ml-control',
      'Compare with the same model’s verdicts on genuine readings (control sample)',
      'INFO',
      `${control.flagged} of ${control.evaluated} genuine readings from ${ctx.config.siteCode} evaluated by ${ml.modelVersion} in the last ${control.windowMinutes} min were flagged SUSPICIOUS.`,
      { control }
    );
  }

  const assessment = classifyCompromisedKey({ primaryAccepted: primary.ok, witnessAccepted: witness.ok, ml, ...(control ? { control } : {}) });
  return {
    outcome: assessment.outcome,
    classification: assessment.classification,
    summary:
      assessment.classification === 'ML_FLAG_NOT_SPECIFIC'
        ? `Not a specific detection: ${assessment.reason}`
        : `${summaryFor(assessment.outcome, 'attack')}: ${assessment.reason}`,
    expectationMet: assessment.expectationMet,
    primaryOutcome: { ...exchangeSummary(primary), readingId: typeof readingId === 'string' ? readingId : null },
    witnessOutcome: { ...exchangeSummary(witness), recordFound: witnessLookup.found, witnessSequence: witnessLookup.event?.witnessSequence ?? null },
    mlResult: ml,
    alertIds: [],
    securityEventIds: { primary: [], witness: [] },
    verificationEvidence: {
      label: 'SIMULATED COMPROMISED KEY',
      sensorId: LAB_COMPROMISED_SENSOR_CODE,
      keyId: identity.keyId,
      messageId: envelope.payload.messageId,
      reportedValue: envelope.payload.value,
      opsContextId: opsContext?.id ?? null,
      opsContextSource: opsSource,
      mlEnabled,
      mlServiceReachable: mlHealth.reachable,
      mlControlSample: control ?? null,
      note: 'Detection is not guaranteed for compromised-key attacks; an anomaly flag is not proof of fraud.',
    },
  };
}
