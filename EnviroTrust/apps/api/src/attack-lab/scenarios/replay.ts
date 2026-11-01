import crypto from 'node:crypto';
import type { SignedTelemetryEnvelope, TelemetryPayload } from '@envirotrust/contracts';
import { classifyRejection, summaryFor } from '../classify.js';
import type { ScenarioContext } from '../context.js';
import type { ScenarioResult } from '../types.js';
import { exchangeSummary, preflight } from './rejection.js';

interface CapturedReading {
  messageId: string;
  envelope: SignedTelemetryEnvelope;
  bootId: string;
  sequence: number;
}

/**
 * Finds the newest accepted COD-OUT-001 reading that belongs to the sensor's current boot session
 * and that the witness also holds. Its exact signed envelope is what an eavesdropper could capture.
 */
async function findCapturedReading(ctx: ScenarioContext): Promise<CapturedReading | null> {
  const res = await ctx.primaryPool.query<{
    message_id: string;
    original_payload: TelemetryPayload;
    signature_base64: string;
    boot_id: string;
    sequence_no: string;
  }>(
    `SELECT tr.message_id, tr.original_payload, tr.signature_base64, tr.boot_id, tr.sequence_no
     FROM telemetry_readings tr
     JOIN sensors s ON s.id = tr.sensor_id
     JOIN sensor_sequence_cursors c ON c.sensor_id = s.id AND c.boot_id = tr.boot_id
     WHERE s.sensor_code = 'COD-OUT-001'
     ORDER BY tr.received_at DESC
     LIMIT 10`
  );
  for (const row of res.rows) {
    const lookup = await ctx.witnessEvent(row.message_id);
    if (lookup.found) {
      return {
        messageId: row.message_id,
        envelope: { payload: row.original_payload, signature: row.signature_base64 },
        bootId: row.boot_id,
        sequence: Number(row.sequence_no),
      };
    }
  }
  return null;
}

export async function runReplayAttack(ctx: ScenarioContext): Promise<ScenarioResult> {
  const unavailable = await preflight(ctx);
  if (unavailable) return unavailable;

  // ---------------------------------------------------------------------------
  // Case 1 — identical duplicate delivery of a captured envelope
  // ---------------------------------------------------------------------------
  const capture = await ctx.steps.begin('capture', 'Case 1: obtain an accepted COD-OUT-001 envelope (as captured in transit)');
  let captured = await findCapturedReading(ctx);
  let bootstrapped = false;
  if (!captured) {
    // No live COD history yet: produce one genuine reading so there is something to replay.
    const device = ctx.device({
      sensorId: 'COD-OUT-001',
      keyDir: ctx.sensorKeyDir('COD-OUT-001'),
      bootId: `LAB-D-${ctx.runId.slice(0, 8)}`,
    });
    const genuine = device.generateReading();
    const delivered = await ctx.submitDual('telemetry', genuine);
    if (delivered.primary.ok && delivered.witness.ok) {
      bootstrapped = true;
      captured = {
        messageId: genuine.payload.messageId,
        envelope: genuine,
        bootId: genuine.payload.bootId,
        sequence: genuine.payload.sequence,
      };
    }
  }
  if (!captured) {
    await ctx.steps.finish(capture, 'FAILED', 'No accepted COD-OUT-001 reading held by both services could be found or created.');
    return {
      outcome: 'INCONCLUSIVE',
      classification: 'NO_REPLAY_TARGET',
      summary: summaryFor('INCONCLUSIVE', 'attack'),
      expectationMet: false,
      primaryOutcome: null,
      witnessOutcome: null,
      mlResult: null,
      alertIds: [],
      securityEventIds: { primary: [], witness: [] },
      verificationEvidence: {},
    };
  }
  await ctx.steps.finish(
    capture,
    'PASSED',
    `${bootstrapped ? 'Bootstrapped one genuine reading' : 'Captured live reading'} ${captured.messageId} (boot ${captured.bootId}, sequence ${captured.sequence}, value ${captured.envelope.payload.value} mg/L)`,
    { messageId: captured.messageId, bootId: captured.bootId, sequence: captured.sequence, bootstrapped }
  );

  const before = {
    primaryRecords: await ctx.primaryReadingCount(captured.messageId),
    primaryAuditEvents: await ctx.primaryAuditEventCount(captured.messageId),
    witness: await ctx.witnessEvent(captured.messageId),
  };

  const dup = await ctx.steps.begin('duplicate', 'Case 1: re-deliver the identical envelope (same message ID, payload and signature)');
  const dupDelivery = await ctx.submitDual('telemetry', captured.envelope);
  const primaryDupBody = dupDelivery.primary.body as Record<string, unknown> | null;
  const witnessDupBody = dupDelivery.witness.body as Record<string, unknown> | null;
  await ctx.steps.finish(
    dup,
    'INFO',
    `${ctx.describe(dupDelivery.primary)} isDuplicate=${String(primaryDupBody?.['isDuplicate'] ?? false)}; ${ctx.describe(dupDelivery.witness)} isDuplicate=${String(witnessDupBody?.['isDuplicate'] ?? false)}`,
    { primary: exchangeSummary(dupDelivery.primary), witness: exchangeSummary(dupDelivery.witness) }
  );

  const idemStep = await ctx.steps.begin('idempotency', 'Case 1: verify no second trusted record and no duplicate audit-chain event');
  const after = {
    primaryRecords: await ctx.primaryReadingCount(captured.messageId),
    primaryAuditEvents: await ctx.primaryAuditEventCount(captured.messageId),
    witness: await ctx.witnessEvent(captured.messageId),
  };
  const idempotencyChecks = [
    { ok: dupDelivery.primary.status === 200 && primaryDupBody?.['isDuplicate'] === true, label: `Primary idempotent response: ${ctx.describe(dupDelivery.primary)}` },
    { ok: dupDelivery.witness.status === 200 && witnessDupBody?.['isDuplicate'] === true, label: `Witness idempotent response: ${ctx.describe(dupDelivery.witness)}` },
    { ok: before.primaryRecords === 1 && after.primaryRecords === 1, label: `Primary trusted records: ${before.primaryRecords} → ${after.primaryRecords}` },
    { ok: after.primaryAuditEvents === before.primaryAuditEvents, label: `Primary ingestion audit-chain events for message: ${before.primaryAuditEvents} → ${after.primaryAuditEvents}` },
    {
      ok: Boolean(before.witness.event && after.witness.event && before.witness.event.eventHash === after.witness.event.eventHash),
      label: `Witness record unchanged (sequence ${after.witness.event?.witnessSequence ?? 'n/a'}, hash ${after.witness.event?.eventHash.slice(0, 12) ?? 'n/a'}…)`,
    },
  ];
  const idempotent = idempotencyChecks.every((c) => c.ok);
  await ctx.steps.finish(idemStep, idempotent ? 'PASSED' : 'FAILED', idempotencyChecks.map((c) => `${c.ok ? '✓' : '✗'} ${c.label}`).join('\n'), {
    checks: idempotencyChecks,
  });

  // ---------------------------------------------------------------------------
  // Case 2 — sequence rollback: new message ID, consumed sequence, same boot, correctly signed
  // ---------------------------------------------------------------------------
  const rb = await ctx.steps.begin('rollback-sign', 'Case 2: sign a NEW message that reuses the consumed sequence for the same boot session');
  const device = ctx.device({
    sensorId: 'COD-OUT-001',
    keyDir: ctx.sensorKeyDir('COD-OUT-001'),
    bootId: captured.bootId,
  });
  const rollback = device.generateReading({
    overrideSequence: captured.sequence,
    overrideMessageId: crypto.randomUUID(),
  });
  await ctx.steps.finish(
    rb,
    'PASSED',
    `messageId ${rollback.payload.messageId} (new), boot ${rollback.payload.bootId}, sequence ${rollback.payload.sequence} (already consumed by ${captured.messageId}); signed with the registered COD key`,
    { messageId: rollback.payload.messageId, bootId: rollback.payload.bootId, sequence: rollback.payload.sequence }
  );

  const submit = await ctx.steps.begin('rollback-submit', 'Case 2: send the rolled-back message to Primary and Witness');
  const { primary, witness } = await ctx.submitDual('telemetry', rollback);
  await ctx.steps.finish(submit, 'INFO', `${ctx.describe(primary)}; ${ctx.describe(witness)}`, {
    primary: exchangeSummary(primary),
    witness: exchangeSummary(witness),
  });

  const evStep = await ctx.steps.begin('evidence', 'Case 2: verify rejection evidence in both databases');
  const ev = await ctx.collectRejectionEvidence(rollback.payload.messageId, primary, witness);
  const assessment = classifyRejection({
    expectedCode: 'REPLAYED_SEQUENCE',
    primary,
    witness,
    primaryTrustedRecords: ev.primaryRecords,
    witnessTrustedRecordFound: ev.witnessLookup.found,
  });
  const rollbackChecks = [
    { ok: ev.primaryRecords === 0, label: `Primary trusted records for rolled-back message: ${ev.primaryRecords}` },
    { ok: !ev.witnessLookup.found, label: `Witness record for rolled-back message: ${ev.witnessLookup.found ? 'FOUND' : 'not stored'}` },
    { ok: ev.primaryEvents.some((e) => e.reasonCode === 'REPLAYED_SEQUENCE'), label: `Primary security events: ${ev.primaryEvents.map((e) => e.reasonCode).join(', ') || 'none'}` },
    { ok: ev.witnessEvents.some((e) => e.reasonCode === 'REPLAYED_SEQUENCE'), label: `Witness security events: ${ev.witnessEvents.map((e) => e.reasonCode).join(', ') || 'none'}` },
    { ok: ev.alerts.length > 0, label: `Security alert linked: ${ev.alerts.map((a) => `${a.severity} ${a.status} (x${a.occurrenceCount})`).join(', ') || 'none'}` },
  ];
  const rollbackOk = rollbackChecks.every((c) => c.ok);
  await ctx.steps.finish(evStep, rollbackOk ? 'PASSED' : 'FAILED', rollbackChecks.map((c) => `${c.ok ? '✓' : '✗'} ${c.label}`).join('\n'), {
    checks: rollbackChecks,
  });

  let outcome = assessment.outcome;
  if (outcome === 'PREVENTED' && !(rollbackOk && idempotent)) outcome = 'INCONCLUSIVE';
  const expectationMet = assessment.expectationMet && rollbackOk && idempotent;

  return {
    outcome,
    classification: outcome === 'PREVENTED' ? 'REPLAYED_SEQUENCE' : 'REPLAY_PROTECTION_NOT_CONFIRMED',
    summary:
      `${summaryFor(outcome, 'attack')}: ${assessment.reason}. ` +
      (idempotent
        ? 'A byte-identical re-delivery was acknowledged idempotently without a second record (legitimate retry semantics).'
        : 'Idempotent duplicate handling was NOT confirmed.'),
    expectationMet,
    primaryOutcome: {
      duplicateDelivery: exchangeSummary(dupDelivery.primary),
      rollbackDelivery: exchangeSummary(primary),
      trustedRecordsForCapturedMessage: after.primaryRecords,
      trustedRecordsForRollbackMessage: ev.primaryRecords,
    },
    witnessOutcome: {
      duplicateDelivery: exchangeSummary(dupDelivery.witness),
      rollbackDelivery: exchangeSummary(witness),
      rollbackRecordFound: ev.witnessLookup.found,
    },
    mlResult: null,
    alertIds: ev.alerts.map((a) => a.id),
    securityEventIds: { primary: ev.primaryEvents.map((e) => e.id), witness: ev.witnessEvents.map((e) => e.id) },
    verificationEvidence: {
      capturedMessageId: captured.messageId,
      rollbackMessageId: rollback.payload.messageId,
      bootId: captured.bootId,
      reusedSequence: captured.sequence,
      idempotencyChecks,
      rollbackChecks,
      primarySecurityEvents: ev.primaryEvents,
      witnessSecurityEvents: ev.witnessEvents,
    },
  };
}
