import fs from 'node:fs';
import path from 'node:path';
import type { Pool } from 'pg';
import { SensorDevice, SENSOR_PROFILES, type SensorProfile } from '@envirotrust/sensor-simulator';
import { OpsContextSimulator } from '@envirotrust/ops-simulator';
import type { AttackLabConfig } from './config.js';
import { exchange, describeExchange } from './http.js';
import type { HttpExchange, RunStep, StepStatus } from './types.js';

export type EnvelopeKind = 'telemetry' | 'heartbeat' | 'tamper' | 'ops';

const PRIMARY_ENDPOINTS: Record<EnvelopeKind, string> = {
  telemetry: '/api/v1/ingestion/readings',
  heartbeat: '/api/v1/ingestion/heartbeats',
  tamper: '/api/v1/tamper/events',
  ops: '/api/v1/ingestion/operations-context',
};

const WITNESS_ENDPOINTS: Record<EnvelopeKind, string> = {
  telemetry: '/witness/v1/ingestion/readings',
  heartbeat: '/witness/v1/ingestion/heartbeats',
  tamper: '/witness/v1/tamper/events',
  ops: '/witness/v1/ingestion/operations-context',
};

export class StepRecorder {
  readonly steps: RunStep[] = [];

  constructor(private readonly persist: (steps: RunStep[]) => Promise<void>) {}

  async begin(key: string, title: string, detail = ''): Promise<RunStep> {
    const step: RunStep = {
      index: this.steps.length + 1,
      key,
      title,
      status: 'RUNNING',
      startedAt: new Date().toISOString(),
      finishedAt: null,
      detail,
    };
    this.steps.push(step);
    await this.persist(this.steps);
    return step;
  }

  async finish(step: RunStep, status: StepStatus, detail: string, data?: Record<string, unknown>): Promise<void> {
    step.status = status;
    step.detail = detail;
    step.finishedAt = new Date().toISOString();
    if (data) step.data = data;
    await this.persist(this.steps);
  }

  async record(
    key: string,
    title: string,
    status: StepStatus,
    detail: string,
    data?: Record<string, unknown>
  ): Promise<RunStep> {
    const step = await this.begin(key, title, detail);
    await this.finish(step, status, detail, data);
    return step;
  }
}

export interface SecurityEventEvidence {
  id: string;
  eventType: string;
  reasonCode: string;
  occurredAt: string;
}

export interface WitnessEventLookup {
  found: boolean;
  httpStatus: number | null;
  event: {
    witnessSequence: number;
    eventHash: string;
    payloadHash: string;
    signature: string;
    messageId: string;
    witnessReceivedAt: string;
  } | null;
}

/**
 * Everything a scenario needs: real HTTP delivery to the configured demo services, evidence queries
 * against both databases, and the simulated device identities (keys stay inside SensorDevice /
 * OpsContextSimulator and are never serialized).
 */
export class ScenarioContext {
  constructor(
    readonly config: AttackLabConfig,
    readonly primaryPool: Pool,
    readonly witnessPool: Pool,
    readonly runId: string,
    readonly steps: StepRecorder,
    readonly startedAt: Date
  ) {}

  get labOutboxDir(): string {
    return path.join(this.config.labSecretsDir, 'outbox');
  }

  primaryUrl(kind: EnvelopeKind): string {
    return `${this.config.primaryBaseUrl}${PRIMARY_ENDPOINTS[kind]}`;
  }

  witnessUrl(kind: EnvelopeKind): string {
    return `${this.config.witnessBaseUrl}${WITNESS_ENDPOINTS[kind]}`;
  }

  async submitToPrimary(kind: EnvelopeKind, envelope: unknown): Promise<HttpExchange> {
    return exchange('PRIMARY', this.config.primaryBaseUrl, PRIMARY_ENDPOINTS[kind], { body: envelope });
  }

  async submitToWitness(kind: EnvelopeKind, envelope: unknown): Promise<HttpExchange> {
    return exchange('WITNESS', this.config.witnessBaseUrl, WITNESS_ENDPOINTS[kind], {
      body: envelope,
      headers: { 'X-Witness-Token': this.config.witnessIngestionToken },
    });
  }

  /** Sends the exact same envelope (one signature) to both services, as a sensor does. */
  async submitDual(kind: EnvelopeKind, envelope: unknown): Promise<{ primary: HttpExchange; witness: HttpExchange }> {
    const [primary, witness] = await Promise.all([
      this.submitToPrimary(kind, envelope),
      this.submitToWitness(kind, envelope),
    ]);
    return { primary, witness };
  }

  async healthCheck(): Promise<{ primary: HttpExchange; witness: HttpExchange }> {
    const [primary, witness] = await Promise.all([
      exchange('PRIMARY', this.config.primaryBaseUrl, '/api/v1/health', { method: 'GET', timeoutMs: 3000 }),
      exchange('WITNESS', this.config.witnessBaseUrl, '/witness/v1/health', { method: 'GET', timeoutMs: 3000 }),
    ]);
    return { primary, witness };
  }

  describe(ex: HttpExchange): string {
    return describeExchange(ex);
  }

  // ---------------------------------------------------------------------------
  // Evidence (read-only queries)
  // ---------------------------------------------------------------------------

  async primaryReadingCount(messageId: string): Promise<number> {
    const res = await this.primaryPool.query<{ n: string }>(
      'SELECT count(*)::text AS n FROM telemetry_readings WHERE message_id = $1',
      [messageId]
    );
    return Number(res.rows[0]?.n || 0);
  }

  /** Ingestion audit-chain events for a message (later ML assessment events share the message ID). */
  async primaryAuditEventCount(messageId: string): Promise<number> {
    const res = await this.primaryPool.query<{ n: string }>(
      "SELECT count(*)::text AS n FROM audit_events WHERE message_id = $1 AND event_type = 'TELEMETRY_INGESTION'",
      [messageId]
    );
    return Number(res.rows[0]?.n || 0);
  }

  async primarySecurityEvents(requestId: string | null): Promise<SecurityEventEvidence[]> {
    if (!requestId) return [];
    const res = await this.primaryPool.query<{ id: string; event_type: string; reason_code: string; occurred_at: Date }>(
      `SELECT id, event_type, reason_code, occurred_at
       FROM security_events
       WHERE sanitized_metadata->>'requestId' = $1
       ORDER BY occurred_at ASC`,
      [requestId]
    );
    return res.rows.map((r) => ({
      id: r.id,
      eventType: r.event_type,
      reasonCode: r.reason_code,
      occurredAt: r.occurred_at.toISOString(),
    }));
  }

  async witnessSecurityEvents(requestId: string | null): Promise<SecurityEventEvidence[]> {
    if (!requestId) return [];
    const res = await this.witnessPool.query<{ id: string; event_type: string; reason_code: string; occurred_at: Date }>(
      `SELECT id, event_type, reason_code, occurred_at
       FROM witness_security_events
       WHERE sanitized_metadata->>'requestId' = $1
       ORDER BY occurred_at ASC`,
      [requestId]
    );
    return res.rows.map((r) => ({
      id: r.id,
      eventType: r.event_type,
      reasonCode: r.reason_code,
      occurredAt: r.occurred_at.toISOString(),
    }));
  }

  /** Security alerts that link the given primary security events (created by the ingestion pipeline). */
  async securityAlertsForEvents(
    securityEventIds: string[]
  ): Promise<Array<{ id: string; severity: string; title: string; status: string; occurrenceCount: number }>> {
    if (securityEventIds.length === 0) return [];
    const res = await this.primaryPool.query<{
      id: string;
      severity: string;
      title: string;
      status: string;
      metadata: Record<string, unknown>;
    }>(
      `SELECT id, severity, title, status, metadata
       FROM alerts
       WHERE alert_type = 'SECURITY_EVENT'
         AND (source_event_id = ANY($1::uuid[]) OR metadata->'recentSecurityEventIds' ?| $2::text[])
       ORDER BY created_at DESC`,
      [securityEventIds, securityEventIds]
    );
    return res.rows.map((r) => ({
      id: r.id,
      severity: r.severity,
      title: r.title,
      status: r.status,
      occurrenceCount: Number(r.metadata?.['occurrenceCount'] || 1),
    }));
  }

  async physicalTamperAlertCountSince(since: Date): Promise<number> {
    const res = await this.primaryPool.query<{ n: string }>(
      `SELECT count(*)::text AS n FROM alerts WHERE alert_type = 'PHYSICAL_TAMPER' AND created_at >= $1`,
      [since]
    );
    return Number(res.rows[0]?.n || 0);
  }

  /** Looks up a witness record through the witness's own authenticated read API. */
  async witnessEvent(messageId: string): Promise<WitnessEventLookup> {
    const ex = await exchange('WITNESS', this.config.witnessBaseUrl, `/witness/v1/events/${encodeURIComponent(messageId)}`, {
      method: 'GET',
      headers: { 'X-Witness-Token': this.config.witnessServiceToken },
      timeoutMs: 4000,
    });
    const body = ex.body as { event?: Record<string, unknown> } | null;
    if (ex.status === 200 && body?.event) {
      const e = body.event;
      return {
        found: true,
        httpStatus: ex.status,
        event: {
          witnessSequence: Number(e['witnessSequence']),
          eventHash: String(e['eventHash']),
          payloadHash: String(e['payloadHash']),
          signature: String(e['signature']),
          messageId: String(e['messageId']),
          witnessReceivedAt: String(e['witnessReceivedAt']),
        },
      };
    }
    return { found: false, httpStatus: ex.status, event: null };
  }

  /** Common post-rejection evidence for one attack message. */
  async collectRejectionEvidence(messageId: string, primary: HttpExchange, witness: HttpExchange) {
    const [primaryRecords, witnessLookup, primaryEvents, witnessEvents] = await Promise.all([
      this.primaryReadingCount(messageId),
      this.witnessEvent(messageId),
      this.primarySecurityEvents(primary.requestId),
      this.witnessSecurityEvents(witness.requestId),
    ]);
    const alerts = await this.securityAlertsForEvents(primaryEvents.map((e) => e.id));
    return { primaryRecords, witnessLookup, primaryEvents, witnessEvents, alerts };
  }

  // ---------------------------------------------------------------------------
  // Simulated device identities
  // ---------------------------------------------------------------------------

  sensorKeyDir(sensorCode: string): string {
    return path.join(this.config.secretsDir, 'sensor-keys', sensorCode);
  }

  labIdentityDir(sensorCode: string): string {
    return path.join(this.config.labSecretsDir, 'identities', sensorCode);
  }

  codProfile(sensorId: string): SensorProfile {
    const base = SENSOR_PROFILES['COD-OUT-001'];
    if (!base) throw new Error('COD sensor profile missing from simulator configuration');
    return { ...base, sensorId };
  }

  /** A simulated sensor device. The private key is loaded inside SensorDevice and never leaves it. */
  device(options: {
    sensorId: string;
    keyDir: string;
    profile?: SensorProfile;
    bootId?: string;
    initialTelemetrySequence?: number;
    initialHeartbeatSequence?: number;
    initialTamperSequence?: number;
  }): SensorDevice {
    return new SensorDevice({
      sensorId: options.sensorId,
      keyDir: options.keyDir,
      profile: options.profile,
      bootId: options.bootId,
      initialTelemetrySequence: options.initialTelemetrySequence,
      initialHeartbeatSequence: options.initialHeartbeatSequence,
      initialTamperSequence: options.initialTamperSequence,
      outboxDir: this.labOutboxDir,
    });
  }

  labDevice(sensorCode: string, options: { bootId: string; initialTelemetrySequence?: number; initialHeartbeatSequence?: number }): SensorDevice {
    return this.device({
      sensorId: sensorCode,
      keyDir: this.labIdentityDir(sensorCode),
      profile: this.codProfile(sensorCode),
      bootId: options.bootId,
      ...(options.initialTelemetrySequence !== undefined ? { initialTelemetrySequence: options.initialTelemetrySequence } : {}),
      ...(options.initialHeartbeatSequence !== undefined ? { initialHeartbeatSequence: options.initialHeartbeatSequence } : {}),
    });
  }

  opsSimulator(initialSequence: number): OpsContextSimulator {
    return new OpsContextSimulator({
      keyDir: path.join(this.config.secretsDir, 'ops-keys', 'OPS-001'),
      initialSequence,
    });
  }

  /** Checks that a dedicated demo identity has key material and is registered in both registries. */
  async labIdentityStatus(sensorCode: string): Promise<{
    ready: boolean;
    keyId: string | null;
    keyFiles: boolean;
    primaryKeyActive: boolean;
    witnessKeyActive: boolean;
    sensorIsDemoIdentity: boolean;
  }> {
    const dir = this.labIdentityDir(sensorCode);
    const metaPath = path.join(dir, 'metadata.json');
    const keyFiles = fs.existsSync(metaPath) && fs.existsSync(path.join(dir, 'private.pem'));
    const keyId = keyFiles ? (JSON.parse(fs.readFileSync(metaPath, 'utf-8')) as { keyId: string }).keyId : null;
    let primaryKeyActive = false;
    let witnessKeyActive = false;
    let sensorIsDemoIdentity = false;
    if (keyId) {
      const p = await this.primaryPool.query<{ status: string; is_demo_identity: boolean; sensor_code: string }>(
        `SELECT dk.status, s.is_demo_identity, s.sensor_code
         FROM device_keys dk JOIN sensors s ON s.id = dk.sensor_id
         WHERE dk.key_id = $1`,
        [keyId]
      );
      primaryKeyActive = p.rows[0]?.status === 'ACTIVE' && p.rows[0]?.sensor_code === sensorCode;
      sensorIsDemoIdentity = p.rows[0]?.is_demo_identity === true;
      const w = await this.witnessPool.query<{ status: string; sensor_code: string }>(
        'SELECT status, sensor_code FROM witness_sensor_keys WHERE key_id = $1',
        [keyId]
      );
      witnessKeyActive = w.rows[0]?.status === 'ACTIVE' && w.rows[0]?.sensor_code === sensorCode;
    }
    return {
      ready: keyFiles && primaryKeyActive && witnessKeyActive && sensorIsDemoIdentity,
      keyId,
      keyFiles,
      primaryKeyActive,
      witnessKeyActive,
      sensorIsDemoIdentity,
    };
  }

  /** Puts a dedicated demo sensor in or out of service. Refuses to touch any non-demo sensor. */
  async setDemoSensorStatus(sensorCode: string, status: 'ACTIVE' | 'INACTIVE'): Promise<void> {
    const res = await this.primaryPool.query(
      'UPDATE sensors SET status = $1 WHERE sensor_code = $2 AND is_demo_identity = TRUE',
      [status, sensorCode]
    );
    if (res.rowCount !== 1) {
      throw new Error(`Refusing to change status of ${sensorCode}: not a registered demo identity`);
    }
  }
}

export function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}
