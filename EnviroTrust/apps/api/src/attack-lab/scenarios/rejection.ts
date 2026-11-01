import crypto from 'node:crypto';
import { generateEd25519KeyPair, signPayload, canonicalizePayload } from '@envirotrust/crypto';
import {
  validateSignedTelemetryEnvelope,
  type SignedTamperEnvelope,
  type SignedTelemetryEnvelope,
  type TelemetryPayload,
} from '@envirotrust/contracts';
import { classifyRejection, summaryFor } from '../classify.js';
import type { ScenarioContext } from '../context.js';
import type { HttpExchange, ScenarioResult } from '../types.js';

function sha256Hex(text: string): string {
  return crypto.createHash('sha256').update(text, 'utf-8').digest('hex');
}

function exchangeSummary(ex: HttpExchange): Record<string, unknown> {
  return {
    endpoint: ex.endpoint,
    httpStatus: ex.status,
    code: ex.code,
    message: ex.message,
    requestId: ex.requestId,
    networkError: ex.networkError,
    durationMs: ex.durationMs,
  };
}

/** Shared tail for scenarios where both services must reject one attack message. */
async function finishRejection(
  ctx: ScenarioContext,
  input: {
    messageId: string;
    expectedCode: string;
    classification: string;
    primary: HttpExchange;
    witness: HttpExchange;
    extraEvidence?: Record<string, unknown>;
    extraChecks?: Array<{ ok: boolean; label: string }>;
  }
): Promise<ScenarioResult> {
  const step = await ctx.steps.begin('evidence', 'Verify persisted evidence in Primary and Witness databases');
  const ev = await ctx.collectRejectionEvidence(input.messageId, input.primary, input.witness);
  const assessment = classifyRejection({
    expectedCode: input.expectedCode,
    primary: input.primary,
    witness: input.witness,
    primaryTrustedRecords: ev.primaryRecords,
    witnessTrustedRecordFound: ev.witnessLookup.found,
  });

  const securityEventRecorded = ev.primaryEvents.some((e) => e.reasonCode === input.expectedCode);
  const checks = [
    { ok: ev.primaryRecords === 0, label: `Primary trusted records for message: ${ev.primaryRecords}` },
    { ok: !ev.witnessLookup.found, label: `Witness record lookup: HTTP ${ev.witnessLookup.httpStatus ?? 'n/a'} (${ev.witnessLookup.found ? 'FOUND' : 'not stored'})` },
    { ok: securityEventRecorded, label: `Primary security events for request: ${ev.primaryEvents.map((e) => e.reasonCode).join(', ') || 'none'}` },
    { ok: ev.witnessEvents.length > 0, label: `Witness security events for request: ${ev.witnessEvents.map((e) => e.reasonCode).join(', ') || 'none'}` },
    { ok: ev.alerts.length > 0, label: `Security alert linked: ${ev.alerts.map((a) => `${a.severity} ${a.status} (x${a.occurrenceCount})`).join(', ') || 'none'}` },
    ...(input.extraChecks || []),
  ];
  const allChecks = checks.every((c) => c.ok);
  await ctx.steps.finish(step, allChecks ? 'PASSED' : 'FAILED', checks.map((c) => `${c.ok ? '✓' : '✗'} ${c.label}`).join('\n'), {
    checks,
  });

  const expectationMet = assessment.expectationMet && allChecks;
  const outcome = assessment.outcome === 'PREVENTED' && !allChecks ? 'INCONCLUSIVE' : assessment.outcome;
  return {
    outcome,
    classification: outcome === 'PREVENTED' ? input.classification : `${input.classification}_NOT_CONFIRMED`,
    summary: `${summaryFor(outcome, 'attack')}: ${assessment.reason}`,
    expectationMet,
    primaryOutcome: { ...exchangeSummary(input.primary), trustedRecords: ev.primaryRecords },
    witnessOutcome: {
      ...exchangeSummary(input.witness),
      recordFound: ev.witnessLookup.found,
      lookupHttpStatus: ev.witnessLookup.httpStatus,
    },
    mlResult: null,
    alertIds: ev.alerts.map((a) => a.id),
    securityEventIds: { primary: ev.primaryEvents.map((e) => e.id), witness: ev.witnessEvents.map((e) => e.id) },
    verificationEvidence: {
      checks,
      messageId: input.messageId,
      primarySecurityEvents: ev.primaryEvents,
      witnessSecurityEvents: ev.witnessEvents,
      securityAlerts: ev.alerts,
      ...input.extraEvidence,
    },
  };
}

async function preflight(ctx: ScenarioContext): Promise<ScenarioResult | null> {
  const step = await ctx.steps.begin('preflight', 'Check Primary API and Witness are reachable');
  const health = await ctx.healthCheck();
  const ok = health.primary.ok && health.witness.ok;
  await ctx.steps.finish(step, ok ? 'PASSED' : 'FAILED', `${ctx.describe(health.primary)}; ${ctx.describe(health.witness)}`);
  if (ok) return null;
  return {
    outcome: 'SERVICE_UNAVAILABLE',
    classification: 'SERVICE_UNAVAILABLE',
    summary: summaryFor('SERVICE_UNAVAILABLE', 'attack'),
    expectationMet: false,
    primaryOutcome: exchangeSummary(health.primary),
    witnessOutcome: exchangeSummary(health.witness),
    mlResult: null,
    alertIds: [],
    securityEventIds: { primary: [], witness: [] },
    verificationEvidence: {},
  };
}

/** A — value changed after signing, original signature kept. */
export async function runTelemetryTampering(ctx: ScenarioContext): Promise<ScenarioResult> {
  const unavailable = await preflight(ctx);
  if (unavailable) return unavailable;

  const sign = await ctx.steps.begin('sign', 'Generate a genuine COD reading signed with the registered COD-OUT-001 key');
  const device = ctx.device({
    sensorId: 'COD-OUT-001',
    keyDir: ctx.sensorKeyDir('COD-OUT-001'),
    bootId: `LAB-A-${ctx.runId.slice(0, 8)}`,
  });
  const genuine = device.generateReading();
  const originalValue = genuine.payload.value;
  const originalHash = sha256Hex(canonicalizePayload(genuine.payload));
  await ctx.steps.finish(sign, 'PASSED', `Signed ${originalValue} mg/L with key ${genuine.payload.keyId} (payload SHA-256 ${originalHash.slice(0, 16)}…). The genuine envelope is never sent.`, {
    keyId: genuine.payload.keyId,
    originalValue,
    originalPayloadHash: originalHash,
  });

  const tamperStep = await ctx.steps.begin('tamper', 'Modify the COD value after signing, keeping the original signature');
  const tamperedValue = (Number(originalValue) * 0.4).toFixed(2);
  const tampered: SignedTelemetryEnvelope = {
    payload: { ...genuine.payload, value: tamperedValue },
    signature: genuine.signature,
  };
  const tamperedHash = sha256Hex(canonicalizePayload(tampered.payload));
  const schemaValid = validateSignedTelemetryEnvelope(tampered).valid;
  await ctx.steps.finish(tamperStep, 'PASSED', `value ${originalValue} → ${tamperedValue} mg/L; payload SHA-256 now ${tamperedHash.slice(0, 16)}…; envelope still schema-valid: ${schemaValid}`, {
    tamperedValue,
    tamperedPayloadHash: tamperedHash,
    schemaValid,
  });

  const submit = await ctx.steps.begin('submit', 'Send the same modified envelope to Primary and Witness');
  const { primary, witness } = await ctx.submitDual('telemetry', tampered);
  await ctx.steps.finish(submit, 'INFO', `${ctx.describe(primary)}; ${ctx.describe(witness)}`, {
    primary: exchangeSummary(primary),
    witness: exchangeSummary(witness),
  });

  const physicalTamperAlerts = await ctx.physicalTamperAlertCountSince(ctx.startedAt);
  return finishRejection(ctx, {
    messageId: tampered.payload.messageId,
    expectedCode: 'INVALID_SIGNATURE',
    classification: 'INVALID_SIGNATURE',
    primary,
    witness,
    extraEvidence: { originalValue, tamperedValue, originalPayloadHash: originalHash, tamperedPayloadHash: tamperedHash },
    extraChecks: [{ ok: physicalTamperAlerts === 0, label: `PHYSICAL_TAMPER alerts created during run: ${physicalTamperAlerts}` }],
  });
}

/** B — correctly signed by a key that was never enrolled. */
export async function runUnknownSigningKey(ctx: ScenarioContext): Promise<ScenarioResult> {
  const unavailable = await preflight(ctx);
  if (unavailable) return unavailable;

  const sign = await ctx.steps.begin('sign', 'Generate an ephemeral attacker Ed25519 key in memory and sign a valid-looking envelope');
  let attacker: { privateKeyPem: string; publicKeyPem: string; fingerprint: string } | null = generateEd25519KeyPair();
  const keyId = `ATTACKER-EPHEMERAL-${crypto.randomBytes(4).toString('hex').toUpperCase()}`;
  const payload: TelemetryPayload = {
    schemaVersion: 1,
    eventType: 'TELEMETRY',
    messageId: crypto.randomUUID(),
    sensorId: 'COD-OUT-001',
    keyId,
    siteId: ctx.config.siteCode,
    stationId: ctx.config.stationCode,
    parameter: 'COD',
    value: '96.50',
    unit: 'mg/L',
    measuredAt: new Date().toISOString(),
    sequence: 1,
    bootId: `LAB-B-${ctx.runId.slice(0, 8)}`,
    calibrationRecordId: null,
  };
  const envelope: SignedTelemetryEnvelope = { payload, signature: signPayload(payload, attacker.privateKeyPem) };
  const fingerprint = attacker.fingerprint;
  // The attacker private key exists only in this scope and is dropped before any network call.
  attacker = null;
  const schemaValid = validateSignedTelemetryEnvelope(envelope).valid;
  await ctx.steps.finish(sign, 'PASSED', `keyId ${keyId}; attacker public-key fingerprint ${fingerprint.slice(0, 16)}…; envelope schema-valid: ${schemaValid}. Private key held in memory only and discarded.`, {
    keyId,
    attackerPublicKeyFingerprint: fingerprint,
    schemaValid,
    privateKeyPersisted: false,
  });

  const submit = await ctx.steps.begin('submit', 'Send the envelope to Primary and Witness');
  const { primary, witness } = await ctx.submitDual('telemetry', envelope);
  await ctx.steps.finish(submit, 'INFO', `${ctx.describe(primary)}; ${ctx.describe(witness)}`, {
    primary: exchangeSummary(primary),
    witness: exchangeSummary(witness),
  });

  return finishRejection(ctx, {
    messageId: payload.messageId,
    expectedCode: 'UNKNOWN_KEY',
    classification: 'UNKNOWN_KEY',
    primary,
    witness,
    extraEvidence: { attackerKeyId: keyId, attackerPublicKeyFingerprint: fingerprint, attackerPrivateKeyPersisted: false },
  });
}

/** C — tamper event with a corrupted signature, submitted to the existing tamper ingestion routes. */
export async function runInvalidTamperSignal(ctx: ScenarioContext): Promise<ScenarioResult> {
  const unavailable = await preflight(ctx);
  if (unavailable) return unavailable;

  const gen = await ctx.steps.begin('sign', 'Create a COD-OUT-001 physical-tamper event and sign it with the registered key');
  const lastSeqRes = await ctx.primaryPool.query<{ n: string | null }>(
    `SELECT max(te.sequence_no)::text AS n FROM tamper_events te JOIN sensors s ON s.id = te.sensor_id WHERE s.sensor_code = 'COD-OUT-001'`
  );
  const device = ctx.device({
    sensorId: 'COD-OUT-001',
    keyDir: ctx.sensorKeyDir('COD-OUT-001'),
    bootId: `LAB-C-${ctx.runId.slice(0, 8)}`,
    initialTamperSequence: Number(lastSeqRes.rows[0]?.n || 0) + 1,
  });
  const genuine = device.generateTamperEvent({
    eventType: 'ENCLOSURE_OPENED',
    tamperSource: 'SIMULATED',
    metadata: { simulatedDemo: true, attackLab: 'invalid-tamper-signal' },
  });
  await ctx.steps.finish(gen, 'PASSED', `eventId ${genuine.payload.eventId}, sequence ${genuine.payload.sequence}. The validly signed event is never sent.`);

  const corrupt = await ctx.steps.begin('corrupt', 'Corrupt the signature bytes (encoding stays valid)');
  const sigBytes = Buffer.from(genuine.signature, 'base64');
  sigBytes[10] = (sigBytes[10] ?? 0) ^ 0xff;
  sigBytes[40] = (sigBytes[40] ?? 0) ^ 0x5a;
  const forged: SignedTamperEnvelope = { payload: genuine.payload, signature: sigBytes.toString('base64') };
  await ctx.steps.finish(corrupt, 'PASSED', 'Two signature bytes flipped; length and Base64 encoding unchanged.');

  const submit = await ctx.steps.begin('submit', 'Submit to the existing tamper ingestion endpoints of Primary and Witness');
  const { primary, witness } = await ctx.submitDual('tamper', forged);
  await ctx.steps.finish(submit, 'INFO', `${ctx.describe(primary)}; ${ctx.describe(witness)}`, {
    primary: exchangeSummary(primary),
    witness: exchangeSummary(witness),
  });

  const evStep = await ctx.steps.begin('evidence', 'Verify no tamper record and no PHYSICAL_TAMPER alert exist');
  const [primaryTamper, witnessTamper, tamperAlert, primaryEvents, witnessEvents] = await Promise.all([
    ctx.primaryPool.query<{ n: string }>('SELECT count(*)::text AS n FROM tamper_events WHERE event_id = $1', [genuine.payload.eventId]),
    ctx.witnessPool.query<{ n: string }>('SELECT count(*)::text AS n FROM witness_tamper_events WHERE event_id = $1', [genuine.payload.eventId]),
    ctx.primaryPool.query<{ n: string }>('SELECT count(*)::text AS n FROM alerts WHERE deduplication_key = $1', [`tamper:${genuine.payload.eventId}`]),
    ctx.primarySecurityEvents(primary.requestId),
    ctx.witnessSecurityEvents(witness.requestId),
  ]);
  const alerts = await ctx.securityAlertsForEvents(primaryEvents.map((e) => e.id));
  const primaryRecords = Number(primaryTamper.rows[0]?.n || 0);
  const witnessRecords = Number(witnessTamper.rows[0]?.n || 0);
  const tamperAlerts = Number(tamperAlert.rows[0]?.n || 0);
  const assessment = classifyRejection({
    expectedCode: 'INVALID_SIGNATURE',
    primary,
    witness,
    primaryTrustedRecords: primaryRecords,
    witnessTrustedRecordFound: witnessRecords > 0,
  });
  const checks = [
    { ok: primaryRecords === 0, label: `Primary tamper_events rows for eventId: ${primaryRecords}` },
    { ok: witnessRecords === 0, label: `Witness witness_tamper_events rows for eventId: ${witnessRecords}` },
    { ok: tamperAlerts === 0, label: `Verified PHYSICAL_TAMPER alerts for eventId: ${tamperAlerts}` },
    { ok: primaryEvents.some((e) => e.reasonCode === 'INVALID_SIGNATURE'), label: `Primary security events: ${primaryEvents.map((e) => `${e.eventType}/${e.reasonCode}`).join(', ') || 'none'}` },
    { ok: witnessEvents.length > 0, label: `Witness security events: ${witnessEvents.map((e) => e.reasonCode).join(', ') || 'none'}` },
    { ok: alerts.length > 0, label: `SECURITY_EVENT alert linked: ${alerts.map((a) => `${a.severity} ${a.status}`).join(', ') || 'none'}` },
  ];
  const allChecks = checks.every((c) => c.ok);
  await ctx.steps.finish(evStep, allChecks ? 'PASSED' : 'FAILED', checks.map((c) => `${c.ok ? '✓' : '✗'} ${c.label}`).join('\n'), { checks });

  const outcome = assessment.outcome === 'PREVENTED' && !allChecks ? 'INCONCLUSIVE' : assessment.outcome;
  return {
    outcome,
    classification: outcome === 'PREVENTED' ? 'INVALID_TAMPER_SIGNATURE_REJECTED' : 'INVALID_TAMPER_SIGNATURE_NOT_CONFIRMED',
    summary: `${summaryFor(outcome, 'attack')}: ${assessment.reason}. A rejected tamper signal is a security event, not a verified physical-tamper alert.`,
    expectationMet: assessment.expectationMet && allChecks,
    primaryOutcome: { ...exchangeSummary(primary), tamperRecords: primaryRecords },
    witnessOutcome: { ...exchangeSummary(witness), tamperRecords: witnessRecords },
    mlResult: null,
    alertIds: alerts.map((a) => a.id),
    securityEventIds: { primary: primaryEvents.map((e) => e.id), witness: witnessEvents.map((e) => e.id) },
    verificationEvidence: { checks, eventId: genuine.payload.eventId, primarySecurityEvents: primaryEvents, witnessSecurityEvents: witnessEvents, securityAlerts: alerts },
  };
}

/** E — payload claims COD-OUT-001 but is signed with (and names) the registered PH-OUT-001 key. */
export async function runIdentityKeyMismatch(ctx: ScenarioContext): Promise<ScenarioResult> {
  const unavailable = await preflight(ctx);
  if (unavailable) return unavailable;

  const sign = await ctx.steps.begin('sign', 'Sign a COD-OUT-001 reading with the registered PH-OUT-001 key');
  const device = ctx.device({
    sensorId: 'COD-OUT-001',
    keyDir: ctx.sensorKeyDir('PH-OUT-001'),
    profile: ctx.codProfile('COD-OUT-001'),
    bootId: `LAB-E-${ctx.runId.slice(0, 8)}`,
  });
  const envelope = device.generateReading();
  await ctx.steps.finish(sign, 'PASSED', `sensorId=${envelope.payload.sensorId}, keyId=${envelope.payload.keyId} (registered to PH-OUT-001), parameter=${envelope.payload.parameter}, value=${envelope.payload.value}`, {
    claimedSensorId: envelope.payload.sensorId,
    keyId: envelope.payload.keyId,
  });

  const submit = await ctx.steps.begin('submit', 'Send through the normal ingestion routes of Primary and Witness');
  const { primary, witness } = await ctx.submitDual('telemetry', envelope);
  await ctx.steps.finish(submit, 'INFO', `${ctx.describe(primary)}; ${ctx.describe(witness)}`, {
    primary: exchangeSummary(primary),
    witness: exchangeSummary(witness),
  });

  return finishRejection(ctx, {
    messageId: envelope.payload.messageId,
    expectedCode: 'KEY_SENSOR_MISMATCH',
    classification: 'IDENTITY_BINDING_FAILURE',
    primary,
    witness,
    extraEvidence: { claimedSensorId: envelope.payload.sensorId, signingKeyId: envelope.payload.keyId },
  });
}

export { exchangeSummary, preflight };
