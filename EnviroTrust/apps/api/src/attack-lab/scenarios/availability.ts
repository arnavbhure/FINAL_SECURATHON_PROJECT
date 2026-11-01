import net from 'node:net';
import type { QueryResultRow } from 'pg';
import { OutboxManager } from '@envirotrust/crypto';
import { SensorAvailabilityService } from '../../services/sensor-availability.service.js';
import { AlertRepository } from '../../repositories/alert.repository.js';
import { summaryFor } from '../classify.js';
import { LAB_SENSOR_CODE } from '../config.js';
import { sleep, type ScenarioContext } from '../context.js';
import type { ScenarioResult } from '../types.js';
import { preflight } from './rejection.js';

interface AlertSnapshot extends QueryResultRow {
  id: string;
  alert_type: string;
  severity: string;
  status: string;
  created_at: Date;
  resolved_at: Date | null;
}

async function alertsForSensorSince(ctx: ScenarioContext, sensorUuid: string, since: Date): Promise<AlertSnapshot[]> {
  const res = await ctx.primaryPool.query<AlertSnapshot>(
    `SELECT id, alert_type, severity, status, created_at, resolved_at
     FROM alerts
     WHERE sensor_id = $1 AND created_at >= $2
       AND alert_type IN ('SENSOR_STALE', 'SENSOR_OFFLINE', 'SENSOR_RECOVERED')
     ORDER BY created_at ASC`,
    [sensorUuid, since]
  );
  return res.rows;
}

function notProvisioned(identity: unknown): ScenarioResult {
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

/** H — stop signed heartbeats from the demo sensor and observe the availability engine. */
export async function runHeartbeatInterruption(ctx: ScenarioContext): Promise<ScenarioResult> {
  const unavailable = await preflight(ctx);
  if (unavailable) return unavailable;

  const identity = await ctx.labIdentityStatus(LAB_SENSOR_CODE);
  if (!identity.ready) {
    await ctx.steps.record('identity', `Load demo sensor ${LAB_SENSOR_CODE}`, 'FAILED', 'Not provisioned — run npm run demo:provision');
    return notProvisioned(identity);
  }
  const sensorRes = await ctx.primaryPool.query<{ id: string }>('SELECT id FROM sensors WHERE sensor_code = $1', [LAB_SENSOR_CODE]);
  const sensorUuid = sensorRes.rows[0]!.id;
  const availability = new SensorAvailabilityService(ctx.primaryPool);
  const alertRepo = new AlertRepository(ctx.primaryPool);
  const device = ctx.labDevice(LAB_SENSOR_CODE, { bootId: `LAB-H-${ctx.runId.slice(0, 8)}`, initialHeartbeatSequence: 1 });
  const since = new Date();
  const observed: Record<string, string | null> = { online: null, stale: null, offline: null, recovered: null };

  try {
    // Leftover incidents from an interrupted earlier run would suppress new alerts via deduplication.
    const leftovers = await alertRepo.resolveActiveAlertsForSensor(
      sensorUuid,
      ['SENSOR_STALE', 'SENSOR_OFFLINE'],
      'Attack Lab pre-run reset of demo sensor incidents'
    );

    // Phase 1: stream heartbeats (sent before the sensor is put in service so it is never seen as silent)
    const online = await ctx.steps.begin('stream', `Stream signed heartbeats from ${LAB_SENSOR_CODE} and confirm ONLINE`);
    const deliveries: string[] = [];
    for (let i = 0; i < 3; i++) {
      const r = await device.sendHeartbeatDual(ctx.primaryUrl('heartbeat'), ctx.witnessUrl('heartbeat'), {
        witnessToken: ctx.config.witnessIngestionToken,
        retryCount: 1,
      });
      deliveries.push(`#${r.envelope.payload.heartbeatSequence}: ${r.primary.status}/${r.witness.status}`);
      if (i === 0) await ctx.setDemoSensorStatus(LAB_SENSOR_CODE, 'ACTIVE');
      await sleep(2000);
    }
    const s1 = await availability.getSensorAvailability(LAB_SENSOR_CODE);
    if (s1?.currentStatus === 'ONLINE') observed['online'] = new Date().toISOString();
    await ctx.steps.finish(online, s1?.currentStatus === 'ONLINE' ? 'PASSED' : 'FAILED', `Heartbeats ${deliveries.join(', ')} → availability ${s1?.currentStatus} (${s1?.explanation})`, {
      leftoverIncidentsResolved: leftovers.length,
    });

    // Phase 2: stop and observe STALE then OFFLINE (the API's availability evaluator runs every 5 s)
    const stop = await ctx.steps.begin('interrupt', 'Stop heartbeats and observe STALE, then OFFLINE');
    const stoppedAt = Date.now();
    while (Date.now() - stoppedAt < 60000) {
      const s = await availability.getSensorAvailability(LAB_SENSOR_CODE);
      const alerts = await alertsForSensorSince(ctx, sensorUuid, since);
      if (s?.currentStatus === 'STALE' && !observed['stale']) observed['stale'] = new Date().toISOString();
      if (s?.currentStatus === 'OFFLINE' && !observed['offline']) observed['offline'] = new Date().toISOString();
      const hasOfflineAlert = alerts.some((a) => a.alert_type === 'SENSOR_OFFLINE');
      if (observed['offline'] && hasOfflineAlert) break;
      await sleep(2000);
    }
    const afterStop = await alertsForSensorSince(ctx, sensorUuid, since);
    const staleAlert = afterStop.find((a) => a.alert_type === 'SENSOR_STALE');
    const offlineAlert = afterStop.find((a) => a.alert_type === 'SENSOR_OFFLINE');
    await ctx.steps.finish(
      stop,
      observed['stale'] && observed['offline'] && staleAlert && offlineAlert ? 'PASSED' : 'FAILED',
      `STALE observed ${observed['stale'] ? `after ${Math.round((Date.parse(observed['stale']) - stoppedAt) / 1000)}s` : 'NO'}, OFFLINE observed ${observed['offline'] ? `after ${Math.round((Date.parse(observed['offline']) - stoppedAt) / 1000)}s` : 'NO'}; alerts: ${afterStop.map((a) => `${a.alert_type}/${a.severity}/${a.status}`).join(', ') || 'none'}`,
      { alerts: afterStop }
    );

    // Phase 3: repeated evaluations must not duplicate the incident
    const dedup = await ctx.steps.begin('dedup', 'Let the evaluator run repeatedly and check for duplicate alerts');
    await sleep(11000);
    const afterDedup = await alertsForSensorSince(ctx, sensorUuid, since);
    const staleCount = afterDedup.filter((a) => a.alert_type === 'SENSOR_STALE').length;
    const offlineCount = afterDedup.filter((a) => a.alert_type === 'SENSOR_OFFLINE').length;
    await ctx.steps.finish(dedup, staleCount === 1 && offlineCount === 1 ? 'PASSED' : 'FAILED', `After ≥2 more evaluation cycles: SENSOR_STALE=${staleCount}, SENSOR_OFFLINE=${offlineCount}`);

    // Phase 4: restore and observe recovery
    const restore = await ctx.steps.begin('restore', 'Restore heartbeats and observe recovery');
    const restoredAt = Date.now();
    let recovery: AlertSnapshot | undefined;
    let offlineResolved = false;
    while (Date.now() - restoredAt < 30000) {
      await device.sendHeartbeatDual(ctx.primaryUrl('heartbeat'), ctx.witnessUrl('heartbeat'), {
        witnessToken: ctx.config.witnessIngestionToken,
        retryCount: 1,
      });
      await sleep(2000);
      const s = await availability.getSensorAvailability(LAB_SENSOR_CODE);
      const alerts = await alertsForSensorSince(ctx, sensorUuid, since);
      recovery = alerts.find((a) => a.alert_type === 'SENSOR_RECOVERED');
      offlineResolved = alerts.some((a) => a.alert_type === 'SENSOR_OFFLINE' && a.status === 'RESOLVED');
      if (s?.currentStatus === 'ONLINE' && !observed['recovered']) observed['recovered'] = new Date().toISOString();
      if (observed['recovered'] && recovery && offlineResolved) break;
    }
    await ctx.steps.finish(
      restore,
      observed['recovered'] && recovery && offlineResolved ? 'PASSED' : 'FAILED',
      `Availability ONLINE ${observed['recovered'] ? 'observed' : 'NOT observed'}; SENSOR_RECOVERED event ${recovery ? recovery.id : 'missing'}; OFFLINE incident resolved: ${offlineResolved}`
    );

    const finalAlerts = await alertsForSensorSince(ctx, sensorUuid, since);
    const ok = Boolean(
      observed['online'] && observed['stale'] && observed['offline'] && staleAlert && offlineAlert &&
        offlineAlert.severity === 'HIGH' && staleAlert.severity === 'WARNING' &&
        staleCount === 1 && offlineCount === 1 && recovery && offlineResolved
    );
    return {
      outcome: ok ? 'DETECTED' : 'INCONCLUSIVE',
      classification: ok ? 'COMMUNICATION_LOSS_INCIDENT' : 'AVAILABILITY_RESPONSE_NOT_CONFIRMED',
      summary: ok
        ? `${summaryFor('DETECTED', 'operational')}: STALE (WARNING) → OFFLINE (HIGH) → RECOVERED, no duplicates. Communication loss does not prove intentional tampering.`
        : `${summaryFor('INCONCLUSIVE', 'operational')}: not every expected availability transition/alert was observed.`,
      expectationMet: ok,
      primaryOutcome: { availabilityTransitions: observed },
      witnessOutcome: { note: 'Heartbeats were dual-delivered; witness heartbeat receipt is independent of availability status.' },
      mlResult: null,
      alertIds: finalAlerts.map((a) => a.id),
      securityEventIds: { primary: [], witness: [] },
      verificationEvidence: {
        sensorId: LAB_SENSOR_CODE,
        transitions: observed,
        alerts: finalAlerts,
        staleAlertCount: staleCount,
        offlineAlertCount: offlineCount,
        note: 'Communication loss is an operational incident; it does not prove intentional tampering.',
      },
    };
  } finally {
    await ctx.setDemoSensorStatus(LAB_SENSOR_CODE, 'INACTIVE').catch(() => undefined);
  }
}

/** Returns a loopback URL whose port refuses connections (a cut delivery path). */
async function isolatedWitnessBase(): Promise<string> {
  const server = net.createServer();
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', () => resolve()));
  const port = (server.address() as net.AddressInfo).port;
  await new Promise<void>((resolve) => server.close(() => resolve()));
  return `http://127.0.0.1:${port}`;
}

/** I — witness delivery path isolated, durable outbox, restore, retry of the original envelope. */
export async function runWitnessOutage(ctx: ScenarioContext): Promise<ScenarioResult> {
  const unavailable = await preflight(ctx);
  if (unavailable) return unavailable;

  const identity = await ctx.labIdentityStatus(LAB_SENSOR_CODE);
  if (!identity.ready) {
    await ctx.steps.record('identity', `Load demo sensor ${LAB_SENSOR_CODE}`, 'FAILED', 'Not provisioned — run npm run demo:provision');
    return notProvisioned(identity);
  }

  const outbox = new OutboxManager(ctx.labOutboxDir);
  outbox.clearAll();
  const device = ctx.labDevice(LAB_SENSOR_CODE, {
    bootId: `LAB-I-${ctx.runId.slice(0, 8)}`,
    initialTelemetrySequence: 1,
    initialHeartbeatSequence: 1,
  });
  const availability = new SensorAvailabilityService(ctx.primaryPool);
  const witnessToken = ctx.config.witnessIngestionToken;

  try {
    // 1. Baseline dual delivery
    const base = await ctx.steps.begin('baseline', 'Verify successful dual delivery (Primary + Witness)');
    await device.sendHeartbeatDual(ctx.primaryUrl('heartbeat'), ctx.witnessUrl('heartbeat'), { witnessToken, retryCount: 1 });
    await ctx.setDemoSensorStatus(LAB_SENSOR_CODE, 'ACTIVE');
    const r1 = await device.sendReadingDual(ctx.primaryUrl('telemetry'), ctx.witnessUrl('telemetry'), { witnessToken, retryCount: 1 });
    const baselineOk = r1.primary.status === 'PRIMARY_ACCEPTED' && r1.witness.status === 'WITNESS_ACCEPTED';
    await ctx.steps.finish(base, baselineOk ? 'PASSED' : 'FAILED', `Reading ${r1.envelope.payload.messageId}: ${r1.primary.status} (HTTP ${r1.primary.httpStatus}), ${r1.witness.status} (HTTP ${r1.witness.httpStatus})`);

    // 2. Isolate the witness path
    const iso = await ctx.steps.begin('isolate', 'Isolate the demo sensor’s delivery path to the witness');
    const isolatedBase = await isolatedWitnessBase();
    await ctx.steps.finish(
      iso,
      'INFO',
      `Witness deliveries from ${LAB_SENSOR_CODE} now go to a closed loopback port (simulated network partition). The shared witness process keeps serving other sensors; it is not stopped.`,
      { method: 'SIMULATED_NETWORK_PARTITION' }
    );

    // 3. New signed reading during the outage
    const outage = await ctx.steps.begin('outage-delivery', 'Send a new signed reading while the witness is unreachable');
    const r2 = await device.sendReadingDual(ctx.primaryUrl('telemetry'), `${isolatedBase}/witness/v1/ingestion/readings`, {
      witnessToken,
      retryCount: 2,
      retryBaseMs: 200,
    });
    const hb = await device.sendHeartbeatDual(ctx.primaryUrl('heartbeat'), `${isolatedBase}/witness/v1/ingestion/heartbeats`, {
      witnessToken,
      retryCount: 0,
    });
    const messageId = r2.envelope.payload.messageId;
    const originalSignature = r2.envelope.signature;
    await ctx.steps.finish(
      outage,
      r2.primary.status === 'PRIMARY_ACCEPTED' && r2.witness.status === 'WITNESS_FAILED' ? 'PASSED' : 'FAILED',
      `Reading ${messageId}: Primary ${r2.primary.status} (HTTP ${r2.primary.httpStatus}); Witness ${r2.witness.status} (${r2.witness.error}). Heartbeat: Primary ${hb.primary.status}, Witness ${hb.witness.status}.`
    );

    // 4. Durable outbox + independent status
    const check = await ctx.steps.begin('outbox', 'Check the durable outbox and independent delivery status');
    const entry = outbox.getEntry<typeof r2.envelope>(messageId);
    const primaryCount = await ctx.primaryReadingCount(messageId);
    const witnessBefore = await ctx.witnessEvent(messageId);
    const avail = await availability.getSensorAvailability(LAB_SENSOR_CODE);
    const outboxChecks = [
      { ok: primaryCount === 1, label: `Primary trusted records: ${primaryCount}` },
      { ok: !witnessBefore.found, label: `Witness record: ${witnessBefore.found ? 'FOUND' : 'missing (expected during outage)'}` },
      { ok: Boolean(entry && entry.primary.status === 'ACCEPTED' && entry.witness.status === 'FAILED'), label: `Outbox entry: primary=${entry?.primary.status ?? 'none'}, witness=${entry?.witness.status ?? 'none'} (${entry?.witness.error ?? ''})` },
      { ok: entry?.envelope.signature === originalSignature, label: 'Outbox holds the original signed envelope (same signature)' },
      { ok: avail?.currentStatus === 'ONLINE', label: `Sensor availability: ${avail?.currentStatus} — not marked OFFLINE because of the witness failure` },
    ];
    const outboxOk = outboxChecks.every((c) => c.ok);
    await ctx.steps.finish(check, outboxOk ? 'PASSED' : 'FAILED', outboxChecks.map((c) => `${c.ok ? '✓' : '✗'} ${c.label}`).join('\n'), { checks: outboxChecks });

    // 5. Restore and retry the original envelope (no new signature)
    const retry = await ctx.steps.begin('retry', 'Restore the witness path and retry the stored envelope');
    const flush = await device.flushOutbox(ctx.primaryUrl('telemetry'), ctx.primaryUrl('heartbeat'), ctx.witnessUrl('telemetry'), ctx.witnessUrl('heartbeat'), {
      witnessToken,
    });
    const witnessAfter = await ctx.witnessEvent(messageId);
    const primaryAfter = await ctx.primaryReadingCount(messageId);
    const payloadRow = await ctx.primaryPool.query<{ payload_hash: string; signature_base64: string }>(
      'SELECT payload_hash, signature_base64 FROM telemetry_readings WHERE message_id = $1',
      [messageId]
    );
    const retryChecks = [
      { ok: witnessAfter.found, label: `Witness record after retry: ${witnessAfter.found ? `sequence ${witnessAfter.event!.witnessSequence}` : 'missing'}` },
      { ok: witnessAfter.event?.signature === originalSignature, label: 'Witness stored the original signature (no re-signing)' },
      { ok: witnessAfter.event?.payloadHash === payloadRow.rows[0]?.payload_hash, label: 'Witness payload hash matches the Primary record' },
      { ok: primaryAfter === 1, label: `Primary trusted records still ${primaryAfter} (no duplicate from retry)` },
      { ok: outbox.getEntry(messageId) === null, label: `Outbox entry cleared (flushed ${flush.flushed}, remaining ${flush.remaining})` },
    ];
    const retryOk = retryChecks.every((c) => c.ok);
    await ctx.steps.finish(retry, retryOk ? 'PASSED' : 'FAILED', retryChecks.map((c) => `${c.ok ? '✓' : '✗'} ${c.label}`).join('\n'), { checks: retryChecks });

    const ok = baselineOk && outboxOk && retryOk;
    return {
      outcome: ok ? 'DETECTED' : 'INCONCLUSIVE',
      classification: ok ? 'WITNESS_DELIVERY_FAILURE_RECOVERED' : 'OUTAGE_HANDLING_NOT_CONFIRMED',
      summary: ok
        ? 'Evidence verified: Primary stayed functional during the witness outage, the failed witness delivery was kept in the durable outbox and the original envelope was accepted on retry.'
        : `${summaryFor('INCONCLUSIVE', 'operational')}: not every outage/recovery check passed.`,
      expectationMet: ok,
      primaryOutcome: { duringOutage: r2.primary.status, httpStatus: r2.primary.httpStatus ?? null, trustedRecords: primaryAfter },
      witnessOutcome: {
        duringOutage: r2.witness.status,
        outageError: r2.witness.error ?? null,
        afterRetry: witnessAfter.found ? 'WITNESS_ACCEPTED' : 'MISSING',
        witnessSequence: witnessAfter.event?.witnessSequence ?? null,
      },
      mlResult: null,
      alertIds: [],
      securityEventIds: { primary: [], witness: [] },
      verificationEvidence: {
        messageId,
        isolationMethod: 'SIMULATED_NETWORK_PARTITION (sensor → witness path only)',
        outboxChecks,
        retryChecks,
        sensorAvailabilityDuringOutage: avail?.currentStatus ?? null,
      },
    };
  } finally {
    await ctx.setDemoSensorStatus(LAB_SENSOR_CODE, 'INACTIVE').catch(() => undefined);
  }
}
