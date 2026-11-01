import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { loadPrivateKey, signPayload, OutboxManager } from '@envirotrust/crypto';
import {
  validateTelemetryPayload,
  validateSignedTelemetryEnvelope,
  validateHeartbeatPayload,
  validateSignedHeartbeatEnvelope,
  validateTamperPayload,
  validateSignedTamperEnvelope,
  type TelemetryPayload,
  type SignedTelemetryEnvelope,
  type HeartbeatPayload,
  type SignedHeartbeatEnvelope,
  type TamperEventPayload,
  type SignedTamperEnvelope,
  type TamperEventType,
} from '@envirotrust/contracts';
import { SENSOR_PROFILES, DEMO_SITE_ID, DEMO_STATION_ID, type SensorProfile } from './config.js';

export interface SensorDeviceOptions {
  /** One of the built-in demo sensors, or any registered sensor code when `profile` is supplied. */
  sensorId: string;
  keyDir: string;
  /** Measurement profile for sensors outside SENSOR_PROFILES (e.g. dedicated Attack Lab demo identities). */
  profile?: SensorProfile | undefined;
  initialTelemetrySequence?: number | undefined;
  initialHeartbeatSequence?: number | undefined;
  initialTamperSequence?: number | undefined;
  bootId?: string | undefined;
  outboxDir?: string | undefined;
  outboxManager?: OutboxManager | undefined;
}

export interface DualDeliveryResult<TEnvelope> {
  envelope: TEnvelope;
  primary: {
    status: 'PRIMARY_ACCEPTED' | 'PRIMARY_FAILED';
    httpStatus?: number | undefined;
    data?: unknown;
    error?: string | undefined;
  };
  witness: {
    status: 'WITNESS_ACCEPTED' | 'WITNESS_FAILED';
    httpStatus?: number | undefined;
    data?: unknown;
    error?: string | undefined;
  };
}

export class SensorDevice {
  public readonly sensorId: string;
  public readonly profile: SensorProfile;
  public readonly keyId: string;
  public readonly bootId: string;

  private readonly privateKeyPem: string;
  private readonly outbox: OutboxManager;
  private telemetrySequence: number;
  private heartbeatSequence: number;
  private tamperSequence: number;

  constructor(options: SensorDeviceOptions) {
    this.sensorId = options.sensorId;
    const profile = options.profile || SENSOR_PROFILES[this.sensorId];
    if (!profile) {
      throw new Error(`Unknown sensorId: ${options.sensorId}`);
    }
    this.profile = profile;

    // Load key metadata
    const metadataPath = path.join(options.keyDir, 'metadata.json');
    if (!fs.existsSync(metadataPath)) {
      throw new Error(`Sensor metadata not found at ${metadataPath}. Run 'npm run keys:provision' first.`);
    }

    const metadata = JSON.parse(fs.readFileSync(metadataPath, 'utf-8')) as { keyId: string };
    this.keyId = metadata.keyId;

    // Load private key strictly into process memory (never exported or logged)
    const privateKeyPath = path.join(options.keyDir, 'private.pem');
    this.privateKeyPem = loadPrivateKey(privateKeyPath);

    // Boot ID unique to this session
    this.bootId = options.bootId || `BOOT-${crypto.randomUUID().slice(0, 8)}`;
    this.telemetrySequence = options.initialTelemetrySequence || 1;
    this.heartbeatSequence = options.initialHeartbeatSequence || 1;
    this.tamperSequence = options.initialTamperSequence || 1;
    this.outbox = options.outboxManager || new OutboxManager(options.outboxDir);
  }

  public getOutboxManager(): OutboxManager {
    return this.outbox;
  }

  public getTelemetrySequence(): number {
    return this.telemetrySequence;
  }

  public getHeartbeatSequence(): number {
    return this.heartbeatSequence;
  }

  /**
   * Generates a signed telemetry reading according to synthetic normal values.
   */
  public generateReading(
    options: {
      overrideValue?: string;
      measuredAt?: string;
      overrideSequence?: number;
      overrideMessageId?: string;
    } = {}
  ): SignedTelemetryEnvelope {
    let valueStr: string;

    if (options.overrideValue !== undefined) {
      valueStr = options.overrideValue;
    } else {
      // Deterministic synthetic sampling within safe normal range
      const { nominalMin, nominalMax, decimals } = this.profile;
      const rawVal = nominalMin + Math.random() * (nominalMax - nominalMin);
      valueStr = rawVal.toFixed(decimals);
    }

    const currentSequence =
      options.overrideSequence !== undefined ? options.overrideSequence : this.telemetrySequence++;
    const messageId = options.overrideMessageId || crypto.randomUUID();
    const measuredAt = options.measuredAt || new Date().toISOString();

    const payload: TelemetryPayload = {
      schemaVersion: 1,
      eventType: 'TELEMETRY',
      messageId,
      sensorId: this.sensorId,
      keyId: this.keyId,
      siteId: DEMO_SITE_ID,
      stationId: DEMO_STATION_ID,
      parameter: this.profile.parameter,
      value: valueStr,
      unit: this.profile.unit,
      measuredAt,
      sequence: currentSequence,
      bootId: this.bootId,
      calibrationRecordId: null,
    };

    // 1. Validate payload against strict contract
    const payloadValidation = validateTelemetryPayload(payload);
    if (!payloadValidation.valid) {
      throw new Error(`Generated telemetry payload failed contract validation: ${JSON.stringify(payloadValidation.errors)}`);
    }

    // 2. Sign canonicalized payload
    const signature = signPayload(payload, this.privateKeyPem);

    const envelope: SignedTelemetryEnvelope = {
      payload,
      signature,
    };

    // 3. Validate resulting envelope against wire contract
    const envValidation = validateSignedTelemetryEnvelope(envelope);
    if (!envValidation.valid) {
      throw new Error(`Generated telemetry envelope failed contract validation: ${JSON.stringify(envValidation.errors)}`);
    }

    return envelope;
  }

  /**
   * Generates a signed heartbeat envelope.
   */
  public generateHeartbeat(options: { sentAt?: string } = {}): SignedHeartbeatEnvelope {
    const currentSequence = this.heartbeatSequence++;
    const messageId = crypto.randomUUID();
    const sentAt = options.sentAt || new Date().toISOString();

    const payload: HeartbeatPayload = {
      schemaVersion: 1,
      eventType: 'HEARTBEAT',
      messageId,
      sensorId: this.sensorId,
      keyId: this.keyId,
      siteId: DEMO_SITE_ID,
      stationId: DEMO_STATION_ID,
      bootId: this.bootId,
      heartbeatSequence: currentSequence,
      sentAt,
    };

    // 1. Validate payload against contract
    const payloadValidation = validateHeartbeatPayload(payload);
    if (!payloadValidation.valid) {
      throw new Error(`Generated heartbeat payload failed contract validation: ${JSON.stringify(payloadValidation.errors)}`);
    }

    // 2. Sign canonicalized payload
    const signature = signPayload(payload, this.privateKeyPem);

    const envelope: SignedHeartbeatEnvelope = {
      payload,
      signature,
    };

    // 3. Validate envelope against contract
    const envValidation = validateSignedHeartbeatEnvelope(envelope);
    if (!envValidation.valid) {
      throw new Error(`Generated heartbeat envelope failed contract validation: ${JSON.stringify(envValidation.errors)}`);
    }

    return envelope;
  }

  /**
   * Dispatches a signed telemetry envelope to an HTTP ingestion target.
   * Employs exponential backoff retry with the EXACT same envelope (messageId, sequence, signature).
   */
  public async sendReading(
    targetUrl: string,
    providedEnvelope?: SignedTelemetryEnvelope,
    retryCount = 3,
    retryBaseMs = 500
  ): Promise<{ ok: boolean; status: number; data: unknown; envelope: SignedTelemetryEnvelope }> {
    const envelope = providedEnvelope || this.generateReading();
    let attempt = 0;
    let lastError: Error | null = null;

    while (attempt <= retryCount) {
      attempt++;
      try {
        const response = await fetch(targetUrl, {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            'Accept': 'application/json',
          },
          body: JSON.stringify(envelope),
        });

        const responseData = await response.json().catch(() => ({}));
        return {
          ok: response.ok,
          status: response.status,
          data: responseData,
          envelope,
        };
      } catch (err) {
        lastError = err as Error;
        if (attempt <= retryCount) {
          const delayMs = retryBaseMs * Math.pow(2, attempt - 1);
          await new Promise((resolve) => setTimeout(resolve, delayMs));
        }
      }
    }

    throw new Error(
      `Failed to dispatch sensor reading for ${this.sensorId} to ${targetUrl} after ${retryCount} retries: ${lastError?.message}`
    );
  }

  /**
   * Dispatches a signed heartbeat envelope to an HTTP ingestion target.
   */
  public async sendHeartbeat(
    targetUrl: string,
    providedEnvelope?: SignedHeartbeatEnvelope,
    retryCount = 3,
    retryBaseMs = 500
  ): Promise<{ ok: boolean; status: number; data: unknown; envelope: SignedHeartbeatEnvelope }> {
    const envelope = providedEnvelope || this.generateHeartbeat();
    let attempt = 0;
    let lastError: Error | null = null;

    while (attempt <= retryCount) {
      attempt++;
      try {
        const response = await fetch(targetUrl, {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            'Accept': 'application/json',
          },
          body: JSON.stringify(envelope),
        });

        const responseData = await response.json().catch(() => ({}));
        return {
          ok: response.ok,
          status: response.status,
          data: responseData,
          envelope,
        };
      } catch (err) {
        lastError = err as Error;
        if (attempt <= retryCount) {
          const delayMs = retryBaseMs * Math.pow(2, attempt - 1);
          await new Promise((resolve) => setTimeout(resolve, delayMs));
        }
      }
    }

    throw new Error(
      `Failed to dispatch sensor heartbeat for ${this.sensorId} to ${targetUrl} after ${retryCount} retries: ${lastError?.message}`
    );
  }

  /**
   * Direct dual-delivery of a single signed telemetry reading to both primary and witness APIs.
   * - Uses a SINGLE signature computation (identical messageId, payload, signature).
   * - Concurrently delivers using Promise.allSettled.
   * - Retries ONLY failed destinations independently using the exact same signed envelope.
   */
  public async sendReadingDual(
    primaryUrl: string,
    witnessUrl: string,
    options: {
      providedEnvelope?: SignedTelemetryEnvelope;
      witnessToken?: string;
      apiKey?: string;
      retryCount?: number;
      retryBaseMs?: number;
    } = {}
  ): Promise<DualDeliveryResult<SignedTelemetryEnvelope>> {
    const envelope = options.providedEnvelope || this.generateReading();
    const witnessToken =
      options.witnessToken ||
      process.env['WITNESS_INGESTION_TOKEN'] ||
      'witness_ingestion_internal_token_secret_98765';

    const postPrimary = async () => {
      const headers: Record<string, string> = {
        'Content-Type': 'application/json',
        'Accept': 'application/json',
      };
      if (options.apiKey) headers['X-API-Key'] = options.apiKey;

      const res = await fetch(primaryUrl, {
        method: 'POST',
        headers,
        body: JSON.stringify(envelope),
      });
      const data = await res.json().catch(() => ({}));
      return { ok: res.ok, status: res.status, data };
    };

    const postWitness = async () => {
      const headers: Record<string, string> = {
        'Content-Type': 'application/json',
        'Accept': 'application/json',
        'X-Witness-Token': witnessToken,
      };

      const res = await fetch(witnessUrl, {
        method: 'POST',
        headers,
        body: JSON.stringify(envelope),
      });
      const data = await res.json().catch(() => ({}));
      return { ok: res.ok, status: res.status, data };
    };

    // Initial concurrent dispatch
    const [primarySettled, witnessSettled] = await Promise.allSettled([
      postPrimary(),
      postWitness(),
    ]);

    let primaryResult: DualDeliveryResult<SignedTelemetryEnvelope>['primary'] =
      primarySettled.status === 'fulfilled' && primarySettled.value.ok
        ? { status: 'PRIMARY_ACCEPTED', httpStatus: primarySettled.value.status, data: primarySettled.value.data }
        : {
            status: 'PRIMARY_FAILED',
            httpStatus: primarySettled.status === 'fulfilled' ? primarySettled.value.status : undefined,
            data: primarySettled.status === 'fulfilled' ? primarySettled.value.data : undefined,
            error: primarySettled.status === 'rejected' ? primarySettled.reason?.message : `HTTP ${primarySettled.value.status}`,
          };

    let witnessResult: DualDeliveryResult<SignedTelemetryEnvelope>['witness'] =
      witnessSettled.status === 'fulfilled' && witnessSettled.value.ok
        ? { status: 'WITNESS_ACCEPTED', httpStatus: witnessSettled.value.status, data: witnessSettled.value.data }
        : {
            status: 'WITNESS_FAILED',
            httpStatus: witnessSettled.status === 'fulfilled' ? witnessSettled.value.status : undefined,
            data: witnessSettled.status === 'fulfilled' ? witnessSettled.value.data : undefined,
            error: witnessSettled.status === 'rejected' ? witnessSettled.reason?.message : `HTTP ${witnessSettled.value.status}`,
          };

    // Bounded retries for only the failed destination(s)
    const maxRetries = options.retryCount ?? 3;
    const baseMs = options.retryBaseMs ?? 200;

    for (let attempt = 1; attempt <= maxRetries; attempt++) {
      if (primaryResult.status === 'PRIMARY_ACCEPTED' && witnessResult.status === 'WITNESS_ACCEPTED') {
        break;
      }

      const delayMs = baseMs * Math.pow(2, attempt - 1);
      await new Promise((resolve) => setTimeout(resolve, delayMs));

      const retryPromises: Promise<void>[] = [];

      if (primaryResult.status === 'PRIMARY_FAILED') {
        retryPromises.push(
          postPrimary()
            .then((res) => {
              if (res.ok) {
                primaryResult = { status: 'PRIMARY_ACCEPTED', httpStatus: res.status, data: res.data };
              } else {
                primaryResult = { status: 'PRIMARY_FAILED', httpStatus: res.status, data: res.data, error: `HTTP ${res.status}` };
              }
            })
            .catch((err) => {
              primaryResult = { status: 'PRIMARY_FAILED', error: err.message };
            })
        );
      }

      if (witnessResult.status === 'WITNESS_FAILED') {
        retryPromises.push(
          postWitness()
            .then((res) => {
              if (res.ok) {
                witnessResult = { status: 'WITNESS_ACCEPTED', httpStatus: res.status, data: res.data };
              } else {
                witnessResult = { status: 'WITNESS_FAILED', httpStatus: res.status, data: res.data, error: `HTTP ${res.status}` };
              }
            })
            .catch((err) => {
              witnessResult = { status: 'WITNESS_FAILED', error: err.message };
            })
        );
      }

      await Promise.allSettled(retryPromises);
    }

    // Outbox durability handling for telemetry
    if (primaryResult.status === 'PRIMARY_ACCEPTED' && witnessResult.status === 'WITNESS_ACCEPTED') {
      this.outbox.removeEntry(envelope.payload.messageId);
    } else {
      this.outbox.saveEntry({
        id: envelope.payload.messageId,
        envelopeType: 'TELEMETRY',
        envelope,
        primary: {
          url: primaryUrl,
          status: primaryResult.status === 'PRIMARY_ACCEPTED' ? 'ACCEPTED' : 'FAILED',
          httpStatus: primaryResult.httpStatus,
          error: primaryResult.error,
          lastAttemptAt: new Date().toISOString(),
        },
        witness: {
          url: witnessUrl,
          status: witnessResult.status === 'WITNESS_ACCEPTED' ? 'ACCEPTED' : 'FAILED',
          httpStatus: witnessResult.httpStatus,
          error: witnessResult.error,
          lastAttemptAt: new Date().toISOString(),
        },
        createdAt: envelope.payload.measuredAt,
        attempts: 1,
      });
    }

    return {
      envelope,
      primary: primaryResult,
      witness: witnessResult,
    };
  }

  /**
   * Direct dual-delivery of a single signed heartbeat to both primary and witness APIs.
   * - Uses a SINGLE signature computation (identical messageId, sequence, signature).
   * - Concurrently delivers using Promise.allSettled.
   * - Tracks primary and witness acceptance independently.
   * - If any destination fails, persists to durable outbox.
   */
  public async sendHeartbeatDual(
    primaryUrl: string,
    witnessUrl: string,
    options: {
      providedEnvelope?: SignedHeartbeatEnvelope;
      witnessToken?: string;
      apiKey?: string;
      retryCount?: number;
      retryBaseMs?: number;
    } = {}
  ): Promise<DualDeliveryResult<SignedHeartbeatEnvelope>> {
    const envelope = options.providedEnvelope || this.generateHeartbeat();
    const witnessToken =
      options.witnessToken ||
      process.env['WITNESS_INGESTION_TOKEN'] ||
      'witness_ingestion_internal_token_secret_98765';

    const postPrimary = async () => {
      const headers: Record<string, string> = {
        'Content-Type': 'application/json',
        'Accept': 'application/json',
      };
      if (options.apiKey) headers['X-API-Key'] = options.apiKey;

      const res = await fetch(primaryUrl, {
        method: 'POST',
        headers,
        body: JSON.stringify(envelope),
      });
      const data = await res.json().catch(() => ({}));
      return { ok: res.ok, status: res.status, data };
    };

    const postWitness = async () => {
      const headers: Record<string, string> = {
        'Content-Type': 'application/json',
        'Accept': 'application/json',
        'X-Witness-Token': witnessToken,
      };

      const res = await fetch(witnessUrl, {
        method: 'POST',
        headers,
        body: JSON.stringify(envelope),
      });
      const data = await res.json().catch(() => ({}));
      return { ok: res.ok, status: res.status, data };
    };

    // Initial concurrent dispatch
    const [primarySettled, witnessSettled] = await Promise.allSettled([
      postPrimary(),
      postWitness(),
    ]);

    let primaryResult: DualDeliveryResult<SignedHeartbeatEnvelope>['primary'] =
      primarySettled.status === 'fulfilled' && primarySettled.value.ok
        ? { status: 'PRIMARY_ACCEPTED', httpStatus: primarySettled.value.status, data: primarySettled.value.data }
        : {
            status: 'PRIMARY_FAILED',
            httpStatus: primarySettled.status === 'fulfilled' ? primarySettled.value.status : undefined,
            data: primarySettled.status === 'fulfilled' ? primarySettled.value.data : undefined,
            error: primarySettled.status === 'rejected' ? primarySettled.reason?.message : `HTTP ${primarySettled.value.status}`,
          };

    let witnessResult: DualDeliveryResult<SignedHeartbeatEnvelope>['witness'] =
      witnessSettled.status === 'fulfilled' && witnessSettled.value.ok
        ? { status: 'WITNESS_ACCEPTED', httpStatus: witnessSettled.value.status, data: witnessSettled.value.data }
        : {
            status: 'WITNESS_FAILED',
            httpStatus: witnessSettled.status === 'fulfilled' ? witnessSettled.value.status : undefined,
            data: witnessSettled.status === 'fulfilled' ? witnessSettled.value.data : undefined,
            error: witnessSettled.status === 'rejected' ? witnessSettled.reason?.message : `HTTP ${witnessSettled.value.status}`,
          };

    // Bounded retries for only failed destination(s)
    const maxRetries = options.retryCount ?? 3;
    const baseMs = options.retryBaseMs ?? 200;

    for (let attempt = 1; attempt <= maxRetries; attempt++) {
      if (primaryResult.status === 'PRIMARY_ACCEPTED' && witnessResult.status === 'WITNESS_ACCEPTED') {
        break;
      }

      const delayMs = baseMs * Math.pow(2, attempt - 1);
      await new Promise((resolve) => setTimeout(resolve, delayMs));

      const retryPromises: Promise<void>[] = [];

      if (primaryResult.status === 'PRIMARY_FAILED') {
        retryPromises.push(
          postPrimary()
            .then((res) => {
              if (res.ok) {
                primaryResult = { status: 'PRIMARY_ACCEPTED', httpStatus: res.status, data: res.data };
              } else {
                primaryResult = { status: 'PRIMARY_FAILED', httpStatus: res.status, data: res.data, error: `HTTP ${res.status}` };
              }
            })
            .catch((err) => {
              primaryResult = { status: 'PRIMARY_FAILED', error: err.message };
            })
        );
      }

      if (witnessResult.status === 'WITNESS_FAILED') {
        retryPromises.push(
          postWitness()
            .then((res) => {
              if (res.ok) {
                witnessResult = { status: 'WITNESS_ACCEPTED', httpStatus: res.status, data: res.data };
              } else {
                witnessResult = { status: 'WITNESS_FAILED', httpStatus: res.status, data: res.data, error: `HTTP ${res.status}` };
              }
            })
            .catch((err) => {
              witnessResult = { status: 'WITNESS_FAILED', error: err.message };
            })
        );
      }

      await Promise.allSettled(retryPromises);
    }

    // Outbox durability handling for heartbeat
    if (primaryResult.status === 'PRIMARY_ACCEPTED' && witnessResult.status === 'WITNESS_ACCEPTED') {
      this.outbox.removeEntry(envelope.payload.messageId);
    } else {
      this.outbox.saveEntry({
        id: envelope.payload.messageId,
        envelopeType: 'HEARTBEAT',
        envelope,
        primary: {
          url: primaryUrl,
          status: primaryResult.status === 'PRIMARY_ACCEPTED' ? 'ACCEPTED' : 'FAILED',
          httpStatus: primaryResult.httpStatus,
          error: primaryResult.error,
          lastAttemptAt: new Date().toISOString(),
        },
        witness: {
          url: witnessUrl,
          status: witnessResult.status === 'WITNESS_ACCEPTED' ? 'ACCEPTED' : 'FAILED',
          httpStatus: witnessResult.httpStatus,
          error: witnessResult.error,
          lastAttemptAt: new Date().toISOString(),
        },
        createdAt: envelope.payload.sentAt,
        attempts: 1,
      });
    }

    return {
      envelope,
      primary: primaryResult,
      witness: witnessResult,
    };
  }

  /**
   * Retries all pending envelopes stored in the durable outbox.
   * Only sends to destinations that have not yet accepted the envelope.
   */
  public async flushOutbox(
    primaryTelemetryUrl: string,
    primaryHeartbeatUrl: string,
    witnessTelemetryUrl: string,
    witnessHeartbeatUrl: string,
    options: {
      witnessToken?: string;
      apiKey?: string;
    } = {}
  ): Promise<{ flushed: number; remaining: number }> {
    const pending = this.outbox.listPendingEntries<SignedTelemetryEnvelope | SignedHeartbeatEnvelope>();
    let flushedCount = 0;
    const witnessToken =
      options.witnessToken ||
      process.env['WITNESS_INGESTION_TOKEN'] ||
      'witness_ingestion_internal_token_secret_98765';

    for (const entry of pending) {
      const isHeartbeat = entry.envelopeType === 'HEARTBEAT';
      const targetPrimaryUrl = isHeartbeat ? primaryHeartbeatUrl : primaryTelemetryUrl;
      const targetWitnessUrl = isHeartbeat ? witnessHeartbeatUrl : witnessTelemetryUrl;

      // Primary retry if not yet accepted
      if (entry.primary.status !== 'ACCEPTED') {
        try {
          const headers: Record<string, string> = {
            'Content-Type': 'application/json',
            'Accept': 'application/json',
          };
          if (options.apiKey) headers['X-API-Key'] = options.apiKey;

          const res = await fetch(targetPrimaryUrl, {
            method: 'POST',
            headers,
            body: JSON.stringify(entry.envelope),
          });
          if (res.ok) {
            this.outbox.markDestinationAccepted(entry.id, 'primary', res.status);
          } else {
            this.outbox.markDestinationFailed(entry.id, 'primary', `HTTP ${res.status}`, res.status);
          }
        } catch (err: any) {
          this.outbox.markDestinationFailed(entry.id, 'primary', err.message);
        }
      }

      // Witness retry if not yet accepted
      if (entry.witness.status !== 'ACCEPTED') {
        try {
          const res = await fetch(targetWitnessUrl, {
            method: 'POST',
            headers: {
              'Content-Type': 'application/json',
              'Accept': 'application/json',
              'X-Witness-Token': witnessToken,
            },
            body: JSON.stringify(entry.envelope),
          });
          if (res.ok) {
            this.outbox.markDestinationAccepted(entry.id, 'witness', res.status);
          } else {
            this.outbox.markDestinationFailed(entry.id, 'witness', `HTTP ${res.status}`, res.status);
          }
        } catch (err: any) {
          this.outbox.markDestinationFailed(entry.id, 'witness', err.message);
        }
      }

      const updated = this.outbox.getEntry(entry.id);
      if (!updated || (updated.primary.status === 'ACCEPTED' && updated.witness.status === 'ACCEPTED')) {
        flushedCount++;
      }
    }

    const remaining = this.outbox.listPendingEntries().length;
    return { flushed: flushedCount, remaining };
  }

  public getTamperSequence(): number {
    return this.tamperSequence;
  }

  /**
   * Generates a signed tamper event payload and cryptographic Ed25519 envelope.
   * Explicitly marks simulated demonstration events with tamperSource = 'SIMULATED'.
   */
  public generateTamperEvent(
    options: {
      eventType?: TamperEventType | undefined;
      tamperSource?: string | undefined;
      eventTimestamp?: string | undefined;
      overrideSequence?: number | undefined;
      overrideEventId?: string | undefined;
      metadata?: Record<string, unknown> | undefined;
    } = {}
  ): SignedTamperEnvelope {
    const seq = options.overrideSequence !== undefined ? options.overrideSequence : this.tamperSequence++;
    const payload: TamperEventPayload = {
      schemaVersion: 1,
      eventId: options.overrideEventId || crypto.randomUUID(),
      sensorId: this.sensorId,
      siteId: DEMO_SITE_ID,
      stationId: DEMO_STATION_ID,
      eventType: options.eventType || 'ENCLOSURE_OPENED',
      eventTimestamp: options.eventTimestamp || new Date().toISOString(),
      keyId: this.keyId,
      tamperSource: options.tamperSource || 'SIMULATED',
      sequence: seq,
      metadata: options.metadata || { simulatedDemo: true },
    };

    const validation = validateTamperPayload(payload);
    if (!validation.valid) {
      throw new Error(`Generated tamper payload failed schema validation: ${JSON.stringify(validation.errors)}`);
    }

    const signature = signPayload(payload, this.privateKeyPem);
    const envelope: SignedTamperEnvelope = { payload, signature };

    const envValidation = validateSignedTamperEnvelope(envelope);
    if (!envValidation.valid) {
      throw new Error(`Signed tamper envelope failed validation: ${JSON.stringify(envValidation.errors)}`);
    }

    return envelope;
  }

  /**
   * Direct concurrent dual-delivery of a single signed tamper event to both primary and witness APIs.
   */
  public async sendTamperEventDual(
    primaryUrl: string,
    witnessUrl: string,
    options: {
      providedEnvelope?: SignedTamperEnvelope | undefined;
      witnessToken?: string | undefined;
    } = {}
  ): Promise<DualDeliveryResult<SignedTamperEnvelope>> {
    const envelope = options.providedEnvelope || this.generateTamperEvent();
    const witnessToken =
      options.witnessToken ||
      process.env['WITNESS_INGESTION_TOKEN'] ||
      'witness_ingestion_internal_token_secret_98765';

    const postPrimary = async () => {
      const res = await fetch(primaryUrl, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Accept': 'application/json',
        },
        body: JSON.stringify(envelope),
      });
      const data = await res.json().catch(() => ({}));
      return { ok: res.ok, status: res.status, data };
    };

    const postWitness = async () => {
      const res = await fetch(witnessUrl, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Accept': 'application/json',
          'X-Witness-Token': witnessToken,
        },
        body: JSON.stringify(envelope),
      });
      const data = await res.json().catch(() => ({}));
      return { ok: res.ok, status: res.status, data };
    };

    const [primarySettled, witnessSettled] = await Promise.allSettled([
      postPrimary(),
      postWitness(),
    ]);

    const primaryResult: DualDeliveryResult<SignedTamperEnvelope>['primary'] =
      primarySettled.status === 'fulfilled' && primarySettled.value.ok
        ? { status: 'PRIMARY_ACCEPTED', httpStatus: primarySettled.value.status, data: primarySettled.value.data }
        : {
            status: 'PRIMARY_FAILED',
            httpStatus: primarySettled.status === 'fulfilled' ? primarySettled.value.status : undefined,
            data: primarySettled.status === 'fulfilled' ? primarySettled.value.data : undefined,
            error: primarySettled.status === 'rejected' ? primarySettled.reason?.message : `HTTP ${primarySettled.status === 'fulfilled' ? primarySettled.value.status : 500}`,
          };

    const witnessResult: DualDeliveryResult<SignedTamperEnvelope>['witness'] =
      witnessSettled.status === 'fulfilled' && witnessSettled.value.ok
        ? { status: 'WITNESS_ACCEPTED', httpStatus: witnessSettled.value.status, data: witnessSettled.value.data }
        : {
            status: 'WITNESS_FAILED',
            httpStatus: witnessSettled.status === 'fulfilled' ? witnessSettled.value.status : undefined,
            data: witnessSettled.status === 'fulfilled' ? witnessSettled.value.data : undefined,
            error: witnessSettled.status === 'rejected' ? witnessSettled.reason?.message : `HTTP ${witnessSettled.status === 'fulfilled' ? witnessSettled.value.status : 500}`,
          };

    return {
      envelope,
      primary: primaryResult,
      witness: witnessResult,
    };
  }
}
