import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { loadPrivateKey, signPayload } from '@envirotrust/crypto';
import {
  validateOpsContextPayload,
  validateSignedOpsContextEnvelope,
  type OpsContextPayload,
  type SignedOpsContextEnvelope,
  type OperatingMode,
} from '@envirotrust/contracts';
import {
  DEMO_SITE_ID,
  DEMO_STATION_ID,
  OPS_SOURCE_ID,
  OPS_SCENARIOS,
} from './config.js';

export interface OpsSimulatorOptions {
  keyDir: string;
  initialSequence?: number;
}

export interface DualDeliveryOpsResult {
  envelope: SignedOpsContextEnvelope;
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

export class OpsContextSimulator {
  public readonly sourceId = OPS_SOURCE_ID;
  public readonly keyId: string;

  private readonly privateKeyPem: string;
  private sequence: number;

  constructor(options: OpsSimulatorOptions) {
    const metadataPath = path.join(options.keyDir, 'metadata.json');
    if (!fs.existsSync(metadataPath)) {
      throw new Error(`OPS metadata not found at ${metadataPath}. Run 'npm run keys:provision' first.`);
    }

    const metadata = JSON.parse(fs.readFileSync(metadataPath, 'utf-8')) as { keyId: string };
    this.keyId = metadata.keyId;

    const privateKeyPath = path.join(options.keyDir, 'private.pem');
    this.privateKeyPem = loadPrivateKey(privateKeyPath);

    this.sequence = options.initialSequence || 1;
  }

  public getSequence(): number {
    return this.sequence;
  }

  /**
   * Generates a signed operations-context envelope.
   */
  public generateContext(options: {
    mode?: OperatingMode;
    intervalDurationMinutes?: number;
    intervalEnd?: Date;
    overrides?: Partial<OpsContextPayload>;
  } = {}): SignedOpsContextEnvelope {
    const mode = options.mode || 'NORMAL';
    const scenario = OPS_SCENARIOS[mode];
    if (!scenario) {
      throw new Error(`Unknown operatingMode: ${mode}`);
    }

    const durationMin = options.intervalDurationMinutes || 10;
    const end = options.intervalEnd || new Date();
    const start = new Date(end.getTime() - durationMin * 60 * 1000);

    const randomInRange = (min: number, max: number): number => {
      return Number((min + Math.random() * (max - min)).toFixed(2));
    };

    const currentSequence = this.sequence++;
    const messageId = crypto.randomUUID();

    const payload: OpsContextPayload = {
      schemaVersion: 1,
      eventType: 'OPERATIONS_CONTEXT',
      messageId,
      sourceId: this.sourceId,
      keyId: this.keyId,
      siteId: DEMO_SITE_ID,
      stationId: DEMO_STATION_ID,
      sequence: currentSequence,
      intervalStart: start.toISOString(),
      intervalEnd: end.toISOString(),
      productionRate: randomInRange(...scenario.productionRateRange),
      wastewaterFlow: randomInRange(...scenario.wastewaterFlowRange),
      treatmentDose: randomInRange(...scenario.treatmentDoseRange),
      energyConsumption: randomInRange(...scenario.energyConsumptionRange),
      operatingMode: mode,
      ...options.overrides,
    };

    // 1. Validate payload against strict contract
    const payloadValidation = validateOpsContextPayload(payload);
    if (!payloadValidation.valid) {
      throw new Error(`Generated ops-context payload failed contract validation: ${JSON.stringify(payloadValidation.errors)}`);
    }

    // 2. Sign canonicalized payload with OPS-001 private key
    const signature = signPayload(payload, this.privateKeyPem);

    const envelope: SignedOpsContextEnvelope = {
      payload,
      signature,
    };

    // 3. Validate envelope against strict wire contract
    const envValidation = validateSignedOpsContextEnvelope(envelope);
    if (!envValidation.valid) {
      throw new Error(`Generated ops-context envelope failed contract validation: ${JSON.stringify(envValidation.errors)}`);
    }

    return envelope;
  }

  /**
   * Dispatches a signed operations-context envelope to an HTTP ingestion target.
   * Employs exponential backoff retry with the EXACT same envelope (messageId, sequence, signature).
   */
  public async sendOpsContext(
    targetUrl: string,
    providedEnvelope?: SignedOpsContextEnvelope,
    retryCount = 3,
    retryBaseMs = 500
  ): Promise<{ ok: boolean; status: number; data: unknown; envelope: SignedOpsContextEnvelope }> {
    const envelope = providedEnvelope || this.generateContext();
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
      `Failed to dispatch operations context to ${targetUrl} after ${retryCount} retries: ${lastError?.message}`
    );
  }

  /**
   * Direct dual-delivery of a single signed operations-context envelope to both primary and witness APIs.
   * - Uses a SINGLE signature computation (identical messageId, payload, signature).
   * - Concurrently delivers using Promise.allSettled.
   * - Retries ONLY failed destinations independently using the exact same signed envelope.
   */
  public async sendOpsContextDual(
    primaryUrl: string,
    witnessUrl: string,
    options: {
      providedEnvelope?: SignedOpsContextEnvelope;
      witnessToken?: string;
      apiKey?: string;
      retryCount?: number;
      retryBaseMs?: number;
    } = {}
  ): Promise<DualDeliveryOpsResult> {
    const envelope = options.providedEnvelope || this.generateContext();
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

    let primaryResult: DualDeliveryOpsResult['primary'] =
      primarySettled.status === 'fulfilled' && primarySettled.value.ok
        ? { status: 'PRIMARY_ACCEPTED', httpStatus: primarySettled.value.status, data: primarySettled.value.data }
        : {
            status: 'PRIMARY_FAILED',
            httpStatus: primarySettled.status === 'fulfilled' ? primarySettled.value.status : undefined,
            data: primarySettled.status === 'fulfilled' ? primarySettled.value.data : undefined,
            error: primarySettled.status === 'rejected' ? primarySettled.reason?.message : `HTTP ${primarySettled.value.status}`,
          };

    let witnessResult: DualDeliveryOpsResult['witness'] =
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

    return {
      envelope,
      primary: primaryResult,
      witness: witnessResult,
    };
  }
}
