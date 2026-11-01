import crypto from 'node:crypto';
import type { Pool } from 'pg';
import {
  validateSignedTelemetryEnvelope,
  validateSignedOpsContextEnvelope,
  validateSignedHeartbeatEnvelope,
  validateSignedTamperEnvelope,
  type SignedTelemetryEnvelope,
  type SignedOpsContextEnvelope,
  type SignedHeartbeatEnvelope,
  type SignedTamperEnvelope,
} from '@envirotrust/contracts';
import {
  canonicalizePayload,
  verifySignature,
  validateSignatureEncoding,
} from '@envirotrust/crypto';
import { WitnessKeyRepository } from '../repositories/witness-key.repository.js';
import { WitnessEventRepository, WitnessSequenceReplayError } from '../repositories/witness-event.repository.js';
import { CheckpointService } from './checkpoint.service.js';
import type { WitnessEnvironment } from '../env.js';

export interface WitnessIngestSuccess {
  success: true;
  status: 'ACCEPTED';
  witnessEventId: string;
  witnessSequence: number;
  witnessReceivedAt: string;
  eventHash: string;
  previousHash?: string;
  isDuplicate?: boolean;
  checkpointCreated?: {
    checkpointId: string;
    checkpointSequence: number;
    chainHeadHash: string;
    checkpointHash: string;
  } | null;
  requestId: string;
}

export class WitnessIngestionService {
  private readonly keyRepo: WitnessKeyRepository;
  private readonly eventRepo: WitnessEventRepository;
  private readonly checkpointService: CheckpointService;

  constructor(
    private readonly pool: Pool,
    private readonly env: WitnessEnvironment
  ) {
    this.keyRepo = new WitnessKeyRepository(pool);
    this.eventRepo = new WitnessEventRepository(pool);
    this.checkpointService = new CheckpointService(env.WITNESS_KEY_DIR);
  }

  getCheckpointService(): CheckpointService {
    return this.checkpointService;
  }

  getEventRepository(): WitnessEventRepository {
    return this.eventRepo;
  }

  /**
   * Constant-time comparison for transport token authentication.
   */
  public verifyToken(providedToken: string | undefined): boolean {
    if (!providedToken || typeof providedToken !== 'string') {
      return false;
    }

    const cleaned = providedToken.startsWith('Bearer ')
      ? providedToken.slice(7).trim()
      : providedToken.trim();

    const expected = this.env.WITNESS_INGESTION_TOKEN;
    const providedBuf = Buffer.from(cleaned, 'utf-8');
    const expectedBuf = Buffer.from(expected, 'utf-8');

    if (providedBuf.length !== expectedBuf.length) {
      return false;
    }

    return crypto.timingSafeEqual(providedBuf, expectedBuf);
  }

  /**
   * Ingests a signed telemetry reading independently from the primary backend.
   */
  async ingestTelemetry(
    body: unknown,
    tokenHeader: string | undefined,
    requestId: string
  ): Promise<{ status: number; body: Record<string, unknown> }> {
    // 1. Authentication
    if (!this.verifyToken(tokenHeader)) {
      await this.eventRepo.recordSecurityEvent('WITNESS_AUTH_FAILED', 'UNAUTHORIZED', {
        endpoint: '/witness/v1/ingestion/readings',
        requestId,
      });
      return {
        status: 401,
        body: {
          success: false,
          code: 'UNAUTHORIZED',
          message: 'Invalid or missing witness ingestion token.',
          requestId,
        },
      };
    }

    // 2. Schema Validation
    const validation = validateSignedTelemetryEnvelope(body);
    if (!validation.valid || !validation.data) {
      return {
        status: 400,
        body: {
          success: false,
          code: 'INVALID_SCHEMA',
          message: 'Telemetry payload does not match schema.',
          details: validation.errors,
          requestId,
        },
      };
    }

    const envelope: SignedTelemetryEnvelope = validation.data;
    const { payload, signature } = envelope;

    // 3. Approved Public Key Lookup
    const registeredKey = await this.keyRepo.getSensorKey(payload.keyId);
    if (!registeredKey) {
      await this.eventRepo.recordSecurityEvent('WITNESS_UNKNOWN_KEY', 'UNKNOWN_KEY', {
        keyId: payload.keyId,
        sensorId: payload.sensorId,
        requestId,
      });
      return {
        status: 401,
        body: {
          success: false,
          code: 'UNKNOWN_KEY',
          message: `Unknown or unregistered key ID: ${payload.keyId}`,
          requestId,
        },
      };
    }

    if (registeredKey.status !== 'ACTIVE') {
      await this.eventRepo.recordSecurityEvent('WITNESS_INACTIVE_KEY', 'KEY_NOT_ACTIVE', {
        keyId: payload.keyId,
        status: registeredKey.status,
        requestId,
      });
      return {
        status: 403,
        body: {
          success: false,
          code: 'KEY_NOT_ACTIVE',
          message: `Signing key is not active (current status: ${registeredKey.status})`,
          requestId,
        },
      };
    }

    // 4. Sensor/Key/Site/Station/Parameter Binding
    if (registeredKey.sensorCode !== payload.sensorId) {
      await this.eventRepo.recordSecurityEvent('WITNESS_KEY_BINDING_MISMATCH', 'KEY_SENSOR_MISMATCH', {
        keyId: payload.keyId,
        claimed: payload.sensorId,
        bound: registeredKey.sensorCode,
        messageId: payload.messageId,
        requestId,
      });
      return {
        status: 400,
        body: {
          success: false,
          code: 'KEY_SENSOR_MISMATCH',
          message: `Key ${payload.keyId} is bound to sensor ${registeredKey.sensorCode}, not ${payload.sensorId}`,
          requestId,
        },
      };
    }
    if (registeredKey.siteCode !== payload.siteId) {
      await this.eventRepo.recordSecurityEvent('WITNESS_KEY_BINDING_MISMATCH', 'KEY_SITE_MISMATCH', {
        keyId: payload.keyId,
        claimed: payload.siteId,
        bound: registeredKey.siteCode,
        messageId: payload.messageId,
        requestId,
      });
      return {
        status: 400,
        body: {
          success: false,
          code: 'KEY_SITE_MISMATCH',
          message: `Key is bound to site ${registeredKey.siteCode}, not ${payload.siteId}`,
          requestId,
        },
      };
    }
    if (registeredKey.stationCode !== payload.stationId) {
      await this.eventRepo.recordSecurityEvent('WITNESS_KEY_BINDING_MISMATCH', 'KEY_STATION_MISMATCH', {
        keyId: payload.keyId,
        claimed: payload.stationId,
        bound: registeredKey.stationCode,
        messageId: payload.messageId,
        requestId,
      });
      return {
        status: 400,
        body: {
          success: false,
          code: 'KEY_STATION_MISMATCH',
          message: `Key is bound to station ${registeredKey.stationCode}, not ${payload.stationId}`,
          requestId,
        },
      };
    }
    if (registeredKey.parameter !== payload.parameter) {
      await this.eventRepo.recordSecurityEvent('WITNESS_KEY_BINDING_MISMATCH', 'KEY_PARAMETER_MISMATCH', {
        keyId: payload.keyId,
        claimed: payload.parameter,
        bound: registeredKey.parameter,
        messageId: payload.messageId,
        requestId,
      });
      return {
        status: 400,
        body: {
          success: false,
          code: 'KEY_PARAMETER_MISMATCH',
          message: `Key is registered for parameter ${registeredKey.parameter}, not ${payload.parameter}`,
          requestId,
        },
      };
    }

    // 5. Signature Encoding Check
    const sigValidation = validateSignatureEncoding(signature);
    if (!sigValidation.valid) {
      await this.eventRepo.recordSecurityEvent('WITNESS_INVALID_SIGNATURE_ENCODING', 'INVALID_SIGNATURE_ENCODING', {
        keyId: payload.keyId,
        error: sigValidation.error,
        requestId,
      });
      return {
        status: 400,
        body: {
          success: false,
          code: 'INVALID_SIGNATURE_ENCODING',
          message: sigValidation.error || 'Invalid Base64 signature encoding',
          requestId,
        },
      };
    }

    // 6. Independent Ed25519 Signature Verification
    const canonicalPayload = canonicalizePayload(payload);
    const payloadHash = crypto.createHash('sha256').update(canonicalPayload, 'utf-8').digest('hex').toLowerCase();
    const signatureHash = crypto.createHash('sha256').update(signature, 'utf-8').digest('hex').toLowerCase();

    const verifyResult = verifySignature(payload, signature, registeredKey.publicKeyPem);
    if (!verifyResult.valid) {
      await this.eventRepo.recordSecurityEvent('WITNESS_SIGNATURE_VERIFICATION_FAILED', 'INVALID_SIGNATURE', {
        keyId: payload.keyId,
        messageId: payload.messageId,
        error: verifyResult.reason,
        requestId,
      });
      return {
        status: 401,
        body: {
          success: false,
          code: 'INVALID_SIGNATURE',
          message: 'Witness independent signature verification failed.',
          requestId,
        },
      };
    }

    // 7. Freshness check
    const measuredDate = new Date(payload.measuredAt);
    const nowMs = Date.now();
    const futureSkewSec = (measuredDate.getTime() - nowMs) / 1000;
    if (futureSkewSec > this.env.MAX_FUTURE_SKEW_SECONDS) {
      return {
        status: 400,
        body: {
          success: false,
          code: 'TIMESTAMP_FUTURE',
          message: `Timestamp is in the future beyond allowed skew limit (${Math.round(futureSkewSec)}s > ${this.env.MAX_FUTURE_SKEW_SECONDS}s)`,
          requestId,
        },
      };
    }

    // 8. Idempotency & Duplicate Envelope Check
    const dupCheck = await this.eventRepo.checkDuplicateMessage(payload.messageId);
    if (dupCheck.exists) {
      if (dupCheck.payloadHash === payloadHash && dupCheck.signatureBase64 === signature) {
        return {
          status: 200,
          body: {
            success: true,
            status: 'ACCEPTED',
            witnessEventId: dupCheck.eventId,
            witnessSequence: dupCheck.witnessSequence,
            witnessReceivedAt: dupCheck.witnessReceivedAt?.toISOString(),
            eventHash: dupCheck.eventHash,
            isDuplicate: true,
            requestId,
          },
        };
      } else {
        await this.eventRepo.recordSecurityEvent('WITNESS_DUPLICATE_MESSAGE_CONFLICT', 'DUPLICATE_MESSAGE', {
          messageId: payload.messageId,
          requestId,
        });
        return {
          status: 409,
          body: {
            success: false,
            code: 'DUPLICATE_MESSAGE',
            message: `Message ID ${payload.messageId} already exists in witness with differing payload content or signature`,
            requestId,
          },
        };
      }
    }

    // 9. Transactional append to witness hash chain & periodic checkpoints
    try {
      const appendResult = await this.eventRepo.appendWitnessEventTransaction({
        eventType: 'TELEMETRY',
        messageId: payload.messageId,
        siteCode: registeredKey.siteCode,
        stationCode: registeredKey.stationCode,
        identityType: 'SENSOR',
        identityCode: payload.sensorId,
        keyId: payload.keyId,
        bootId: payload.bootId ?? null,
        sourceSequence: payload.sequence,
        sourceTimestamp: measuredDate,
        payload: payload as unknown as Record<string, unknown>,
        signatureBase64: signature,
        payloadHash,
        signatureHash,
        checkpointService: this.checkpointService,
        checkpointInterval: this.env.WITNESS_CHECKPOINT_EVERY,
        enforceSourceSequenceUniqueness: true,
      });

      return {
        status: 201,
        body: {
          success: true,
          status: 'ACCEPTED',
          witnessEventId: appendResult.eventId,
          witnessSequence: appendResult.witnessSequence,
          witnessReceivedAt: appendResult.witnessReceivedAt.toISOString(),
          eventHash: appendResult.eventHash,
          previousHash: appendResult.previousHash,
          checkpointCreated: appendResult.checkpointCreated
            ? {
                checkpointId: appendResult.checkpointCreated.payload.checkpointId,
                checkpointSequence: appendResult.checkpointCreated.payload.checkpointSequence,
                chainHeadHash: appendResult.checkpointCreated.payload.chainHeadHash,
                checkpointHash: appendResult.checkpointCreated.checkpointHash,
              }
            : null,
          requestId,
        },
      };
    } catch (err: any) {
      if (err instanceof WitnessSequenceReplayError) {
        await this.eventRepo.recordSecurityEvent('WITNESS_REPLAYED_SEQUENCE', 'REPLAYED_SEQUENCE', {
          keyId: payload.keyId,
          sensorId: payload.sensorId,
          messageId: payload.messageId,
          bootId: payload.bootId,
          sequence: payload.sequence,
          previouslyWitnessedMessageId: err.existingMessageId,
          requestId,
        });
        return {
          status: 409,
          body: {
            success: false,
            code: 'REPLAYED_SEQUENCE',
            message: `Replay detected: sequence ${payload.sequence} for this sensor boot session was already witnessed under a different message ID`,
            requestId,
          },
        };
      }
      console.error('[WITNESS_INGESTION_ERROR]', err);
      return {
        status: 500,
        body: {
          success: false,
          code: 'INTERNAL_ERROR',
          message: 'Failed to append event to witness chain.',
          requestId,
        },
      };
    }
  }

  /**
   * Ingests a signed operations-context record independently from the primary backend.
   */
  async ingestOpsContext(
    body: unknown,
    tokenHeader: string | undefined,
    requestId: string
  ): Promise<{ status: number; body: Record<string, unknown> }> {
    // 1. Authentication
    if (!this.verifyToken(tokenHeader)) {
      await this.eventRepo.recordSecurityEvent('WITNESS_AUTH_FAILED', 'UNAUTHORIZED', {
        endpoint: '/witness/v1/ingestion/operations-context',
        requestId,
      });
      return {
        status: 401,
        body: {
          success: false,
          code: 'UNAUTHORIZED',
          message: 'Invalid or missing witness ingestion token.',
          requestId,
        },
      };
    }

    // 2. Schema Validation
    const validation = validateSignedOpsContextEnvelope(body);
    if (!validation.valid || !validation.data) {
      return {
        status: 400,
        body: {
          success: false,
          code: 'INVALID_SCHEMA',
          message: 'Operations context payload does not match schema.',
          details: validation.errors,
          requestId,
        },
      };
    }

    const envelope: SignedOpsContextEnvelope = validation.data;
    const { payload, signature } = envelope;

    // 3. Approved Public Key Lookup
    const registeredKey = await this.keyRepo.getOperationsKey(payload.keyId);
    if (!registeredKey) {
      await this.eventRepo.recordSecurityEvent('WITNESS_UNKNOWN_KEY', 'UNKNOWN_KEY', {
        keyId: payload.keyId,
        sourceId: payload.sourceId,
        requestId,
      });
      return {
        status: 401,
        body: {
          success: false,
          code: 'UNKNOWN_KEY',
          message: `Unknown or unregistered operations key ID: ${payload.keyId}`,
          requestId,
        },
      };
    }

    if (registeredKey.status !== 'ACTIVE') {
      await this.eventRepo.recordSecurityEvent('WITNESS_INACTIVE_KEY', 'KEY_NOT_ACTIVE', {
        keyId: payload.keyId,
        status: registeredKey.status,
        requestId,
      });
      return {
        status: 403,
        body: {
          success: false,
          code: 'KEY_NOT_ACTIVE',
          message: `Signing key is not active (current status: ${registeredKey.status})`,
          requestId,
        },
      };
    }

    // 4. Source Binding Check
    if (registeredKey.sourceId !== payload.sourceId) {
      await this.eventRepo.recordSecurityEvent('WITNESS_KEY_BINDING_MISMATCH', 'KEY_SOURCE_MISMATCH', {
        keyId: payload.keyId,
        claimed: payload.sourceId,
        bound: registeredKey.sourceId,
        messageId: payload.messageId,
        requestId,
      });
      return {
        status: 400,
        body: {
          success: false,
          code: 'KEY_SOURCE_MISMATCH',
          message: `Key is bound to source ${registeredKey.sourceId}, not ${payload.sourceId}`,
          requestId,
        },
      };
    }
    if (registeredKey.siteCode !== payload.siteId) {
      await this.eventRepo.recordSecurityEvent('WITNESS_KEY_BINDING_MISMATCH', 'KEY_SITE_MISMATCH', {
        keyId: payload.keyId,
        claimed: payload.siteId,
        bound: registeredKey.siteCode,
        messageId: payload.messageId,
        requestId,
      });
      return {
        status: 400,
        body: {
          success: false,
          code: 'KEY_SITE_MISMATCH',
          message: `Key is bound to site ${registeredKey.siteCode}, not ${payload.siteId}`,
          requestId,
        },
      };
    }
    if (registeredKey.stationCode !== payload.stationId) {
      await this.eventRepo.recordSecurityEvent('WITNESS_KEY_BINDING_MISMATCH', 'KEY_STATION_MISMATCH', {
        keyId: payload.keyId,
        claimed: payload.stationId,
        bound: registeredKey.stationCode,
        messageId: payload.messageId,
        requestId,
      });
      return {
        status: 400,
        body: {
          success: false,
          code: 'KEY_STATION_MISMATCH',
          message: `Key is bound to station ${registeredKey.stationCode}, not ${payload.stationId}`,
          requestId,
        },
      };
    }

    // 5. Signature Encoding Check
    const sigValidation = validateSignatureEncoding(signature);
    if (!sigValidation.valid) {
      return {
        status: 400,
        body: {
          success: false,
          code: 'INVALID_SIGNATURE_ENCODING',
          message: sigValidation.error || 'Invalid Base64 signature encoding',
          requestId,
        },
      };
    }

    // 6. Independent Ed25519 Signature Verification
    const canonicalPayload = canonicalizePayload(payload);
    const payloadHash = crypto.createHash('sha256').update(canonicalPayload, 'utf-8').digest('hex').toLowerCase();
    const signatureHash = crypto.createHash('sha256').update(signature, 'utf-8').digest('hex').toLowerCase();

    const verifyResult = verifySignature(payload, signature, registeredKey.publicKeyPem);
    if (!verifyResult.valid) {
      await this.eventRepo.recordSecurityEvent('WITNESS_SIGNATURE_VERIFICATION_FAILED', 'INVALID_SIGNATURE', {
        keyId: payload.keyId,
        messageId: payload.messageId,
        error: verifyResult.reason,
        requestId,
      });
      return {
        status: 401,
        body: {
          success: false,
          code: 'INVALID_SIGNATURE',
          message: 'Witness independent signature verification failed for operations context.',
          requestId,
        },
      };
    }

    // 7. Freshness Check
    const intervalEndDate = new Date(payload.intervalEnd);
    const nowMs = Date.now();
    const futureSkewSec = (intervalEndDate.getTime() - nowMs) / 1000;
    if (futureSkewSec > this.env.MAX_FUTURE_SKEW_SECONDS) {
      return {
        status: 400,
        body: {
          success: false,
          code: 'TIMESTAMP_FUTURE',
          message: `Interval end timestamp is in the future beyond allowed skew limit (${Math.round(futureSkewSec)}s > ${this.env.MAX_FUTURE_SKEW_SECONDS}s)`,
          requestId,
        },
      };
    }

    // 8. Idempotency Check
    const dupCheck = await this.eventRepo.checkDuplicateMessage(payload.messageId);
    if (dupCheck.exists) {
      if (dupCheck.payloadHash === payloadHash && dupCheck.signatureBase64 === signature) {
        return {
          status: 200,
          body: {
            success: true,
            status: 'ACCEPTED',
            witnessEventId: dupCheck.eventId,
            witnessSequence: dupCheck.witnessSequence,
            witnessReceivedAt: dupCheck.witnessReceivedAt?.toISOString(),
            eventHash: dupCheck.eventHash,
            isDuplicate: true,
            requestId,
          },
        };
      } else {
        await this.eventRepo.recordSecurityEvent('WITNESS_DUPLICATE_MESSAGE_CONFLICT', 'DUPLICATE_MESSAGE', {
          messageId: payload.messageId,
          requestId,
        });
        return {
          status: 409,
          body: {
            success: false,
            code: 'DUPLICATE_MESSAGE',
            message: `Message ID ${payload.messageId} already exists in witness with differing payload content or signature`,
            requestId,
          },
        };
      }
    }

    // 9. Transactional append with operations cursor check
    const client = await this.pool.connect();
    try {
      await client.query('BEGIN');

      const cursorCheck = await this.eventRepo.checkAndUpdateOperationsCursor(
        payload.sourceId,
        payload.sequence,
        intervalEndDate,
        client
      );

      if (!cursorCheck.valid) {
        await client.query('ROLLBACK');
        return {
          status: 409,
          body: {
            success: false,
            code: 'REPLAYED_SEQUENCE',
            message: cursorCheck.reason || 'Replayed operations context sequence',
            requestId,
          },
        };
      }

      const appendResult = await this.eventRepo.appendWitnessEventTransaction(
        {
          eventType: 'OPERATIONS_CONTEXT',
          messageId: payload.messageId,
          siteCode: registeredKey.siteCode,
          stationCode: registeredKey.stationCode,
          identityType: 'OPERATIONS_SOURCE',
          identityCode: payload.sourceId,
          keyId: payload.keyId,
          bootId: null,
          sourceSequence: payload.sequence,
          sourceTimestamp: intervalEndDate,
          payload: payload as unknown as Record<string, unknown>,
          signatureBase64: signature,
          payloadHash,
          signatureHash,
          checkpointService: this.checkpointService,
          checkpointInterval: this.env.WITNESS_CHECKPOINT_EVERY,
        },
        client
      );

      await client.query('COMMIT');

      return {
        status: 201,
        body: {
          success: true,
          status: 'ACCEPTED',
          witnessEventId: appendResult.eventId,
          witnessSequence: appendResult.witnessSequence,
          witnessReceivedAt: appendResult.witnessReceivedAt.toISOString(),
          eventHash: appendResult.eventHash,
          previousHash: appendResult.previousHash,
          checkpointCreated: appendResult.checkpointCreated
            ? {
                checkpointId: appendResult.checkpointCreated.payload.checkpointId,
                checkpointSequence: appendResult.checkpointCreated.payload.checkpointSequence,
                chainHeadHash: appendResult.checkpointCreated.payload.chainHeadHash,
                checkpointHash: appendResult.checkpointCreated.checkpointHash,
              }
            : null,
          requestId,
        },
      };
    } catch (err: any) {
      await client.query('ROLLBACK');
      console.error('[WITNESS_OPERATIONS_INGESTION_ERROR]', err);
      return {
        status: 500,
        body: {
          success: false,
          code: 'INTERNAL_ERROR',
          message: 'Failed to append operations event to witness chain.',
          requestId,
        },
      };
    } finally {
      client.release();
    }
  }

  /**
   * Ingests a signed heartbeat record independently from the primary backend.
   */
  async ingestHeartbeat(
    body: unknown,
    tokenHeader: string | undefined,
    requestId: string
  ): Promise<{ status: number; body: Record<string, unknown> }> {
    // 1. Authentication
    if (!this.verifyToken(tokenHeader)) {
      await this.eventRepo.recordSecurityEvent('WITNESS_AUTH_FAILED', 'UNAUTHORIZED', {
        endpoint: '/witness/v1/ingestion/heartbeats',
        requestId,
      });
      return {
        status: 401,
        body: {
          success: false,
          code: 'UNAUTHORIZED',
          message: 'Invalid or missing witness ingestion token.',
          requestId,
        },
      };
    }

    // 2. Schema Validation
    const validation = validateSignedHeartbeatEnvelope(body);
    if (!validation.valid || !validation.data) {
      return {
        status: 400,
        body: {
          success: false,
          code: 'INVALID_SCHEMA',
          message: 'Heartbeat payload does not match schema.',
          details: validation.errors,
          requestId,
        },
      };
    }

    const envelope: SignedHeartbeatEnvelope = validation.data;
    const { payload, signature } = envelope;

    // 3. Approved Public Key Lookup
    const registeredKey = await this.keyRepo.getSensorKey(payload.keyId);
    if (!registeredKey) {
      await this.eventRepo.recordSecurityEvent('WITNESS_UNKNOWN_KEY', 'UNKNOWN_KEY', {
        keyId: payload.keyId,
        sensorId: payload.sensorId,
        requestId,
      });
      return {
        status: 401,
        body: {
          success: false,
          code: 'UNKNOWN_KEY',
          message: `Unknown or unregistered key ID: ${payload.keyId}`,
          requestId,
        },
      };
    }

    if (registeredKey.status !== 'ACTIVE') {
      await this.eventRepo.recordSecurityEvent('WITNESS_INACTIVE_KEY', 'KEY_NOT_ACTIVE', {
        keyId: payload.keyId,
        status: registeredKey.status,
        requestId,
      });
      return {
        status: 403,
        body: {
          success: false,
          code: 'KEY_NOT_ACTIVE',
          message: `Signing key is not active (current status: ${registeredKey.status})`,
          requestId,
        },
      };
    }

    const sentDate = new Date(payload.sentAt);

    // 4. Sensor Identity Binding Check
    if (registeredKey.sensorCode !== payload.sensorId) {
      await this.eventRepo.recordSecurityEvent('WITNESS_KEY_BINDING_MISMATCH', 'KEY_SENSOR_MISMATCH', {
        keyId: payload.keyId,
        claimed: payload.sensorId,
        bound: registeredKey.sensorCode,
        messageId: payload.messageId,
        requestId,
      });
      return {
        status: 400,
        body: {
          success: false,
          code: 'KEY_SENSOR_MISMATCH',
          message: `Key ${payload.keyId} is bound to sensor ${registeredKey.sensorCode}, not ${payload.sensorId}`,
          requestId,
        },
      };
    }
    if (registeredKey.siteCode !== payload.siteId) {
      await this.eventRepo.recordSecurityEvent('WITNESS_KEY_BINDING_MISMATCH', 'KEY_SITE_MISMATCH', {
        keyId: payload.keyId,
        claimed: payload.siteId,
        bound: registeredKey.siteCode,
        messageId: payload.messageId,
        requestId,
      });
      return {
        status: 400,
        body: {
          success: false,
          code: 'KEY_SITE_MISMATCH',
          message: `Key is bound to site ${registeredKey.siteCode}, not ${payload.siteId}`,
          requestId,
        },
      };
    }
    if (registeredKey.stationCode !== payload.stationId) {
      await this.eventRepo.recordSecurityEvent('WITNESS_KEY_BINDING_MISMATCH', 'KEY_STATION_MISMATCH', {
        keyId: payload.keyId,
        claimed: payload.stationId,
        bound: registeredKey.stationCode,
        messageId: payload.messageId,
        requestId,
      });
      return {
        status: 400,
        body: {
          success: false,
          code: 'KEY_STATION_MISMATCH',
          message: `Key is bound to station ${registeredKey.stationCode}, not ${payload.stationId}`,
          requestId,
        },
      };
    }

    // 5. Signature Encoding Check
    const sigValidation = validateSignatureEncoding(signature);
    if (!sigValidation.valid) {
      return {
        status: 400,
        body: {
          success: false,
          code: 'INVALID_SIGNATURE_ENCODING',
          message: sigValidation.error || 'Invalid Base64 signature encoding',
          requestId,
        },
      };
    }

    // 6. Independent Ed25519 Signature Verification
    const canonicalPayload = canonicalizePayload(payload);
    const payloadHash = crypto.createHash('sha256').update(canonicalPayload, 'utf-8').digest('hex').toLowerCase();
    const signatureHash = crypto.createHash('sha256').update(signature, 'utf-8').digest('hex').toLowerCase();

    const verifyResult = verifySignature(payload, signature, registeredKey.publicKeyPem);
    if (!verifyResult.valid) {
      await this.eventRepo.recordSecurityEvent('WITNESS_SIGNATURE_VERIFICATION_FAILED', 'INVALID_SIGNATURE', {
        keyId: payload.keyId,
        messageId: payload.messageId,
        error: verifyResult.reason,
        requestId,
      });
      return {
        status: 401,
        body: {
          success: false,
          code: 'INVALID_SIGNATURE',
          message: 'Witness independent signature verification failed for heartbeat.',
          requestId,
        },
      };
    }

    // 7. Freshness Check
    const nowMs = Date.now();
    const futureSkewSec = (sentDate.getTime() - nowMs) / 1000;
    if (futureSkewSec > this.env.MAX_FUTURE_SKEW_SECONDS) {
      return {
        status: 400,
        body: {
          success: false,
          code: 'TIMESTAMP_FUTURE',
          message: `Heartbeat sentAt timestamp is in the future beyond allowed skew limit (${Math.round(futureSkewSec)}s > ${this.env.MAX_FUTURE_SKEW_SECONDS}s)`,
          requestId,
        },
      };
    }

    // 8. Idempotency Check
    const dupCheck = await this.eventRepo.checkDuplicateMessage(payload.messageId);
    if (dupCheck.exists) {
      if (dupCheck.payloadHash === payloadHash && dupCheck.signatureBase64 === signature) {
        return {
          status: 200,
          body: {
            success: true,
            status: 'ACCEPTED',
            witnessEventId: dupCheck.eventId,
            witnessSequence: dupCheck.witnessSequence,
            witnessReceivedAt: dupCheck.witnessReceivedAt?.toISOString(),
            eventHash: dupCheck.eventHash,
            isDuplicate: true,
            requestId,
          },
        };
      } else {
        await this.eventRepo.recordSecurityEvent('WITNESS_DUPLICATE_MESSAGE_CONFLICT', 'DUPLICATE_MESSAGE', {
          messageId: payload.messageId,
          requestId,
        });
        return {
          status: 409,
          body: {
            success: false,
            code: 'DUPLICATE_MESSAGE',
            message: `Message ID ${payload.messageId} already exists in witness with differing payload content or signature`,
            requestId,
          },
        };
      }
    }

    // 9. Transactional persistence & hash chain append
    const witnessReceivedAt = new Date();
    const client = await this.pool.connect();
    try {
      await client.query('BEGIN');

      // Heartbeat replay cursor check
      const cursorCheck = await this.eventRepo.checkAndUpdateHeartbeatCursor(
        payload.sensorId,
        payload.bootId,
        payload.heartbeatSequence,
        sentDate,
        witnessReceivedAt,
        client
      );

      if (!cursorCheck.valid) {
        await client.query('ROLLBACK');
        return {
          status: 409,
          body: {
            success: false,
            code: 'REPLAYED_SEQUENCE',
            message: cursorCheck.reason || 'Replayed heartbeat sequence',
            requestId,
          },
        };
      }

      // Insert into witness_heartbeats
      await this.eventRepo.insertHeartbeatRecord(
        {
          messageId: payload.messageId,
          sensorCode: payload.sensorId,
          siteCode: registeredKey.siteCode,
          stationCode: registeredKey.stationCode,
          keyId: payload.keyId,
          bootId: payload.bootId,
          heartbeatSequence: payload.heartbeatSequence,
          sentAt: sentDate,
          receivedAt: witnessReceivedAt,
          payload: payload as unknown as Record<string, unknown>,
          signatureBase64: signature,
          payloadHash,
          signatureHash,
        },
        client
      );

      // Append to witness hash chain
      const appendResult = await this.eventRepo.appendWitnessEventTransaction(
        {
          eventType: 'HEARTBEAT',
          messageId: payload.messageId,
          siteCode: registeredKey.siteCode,
          stationCode: registeredKey.stationCode,
          identityType: 'SENSOR',
          identityCode: payload.sensorId,
          keyId: payload.keyId,
          bootId: payload.bootId,
          sourceSequence: payload.heartbeatSequence,
          sourceTimestamp: sentDate,
          payload: payload as unknown as Record<string, unknown>,
          signatureBase64: signature,
          payloadHash,
          signatureHash,
          checkpointService: this.checkpointService,
          checkpointInterval: this.env.WITNESS_CHECKPOINT_EVERY,
        },
        client
      );

      await client.query('COMMIT');

      return {
        status: 201,
        body: {
          success: true,
          status: 'ACCEPTED',
          witnessEventId: appendResult.eventId,
          witnessSequence: appendResult.witnessSequence,
          witnessReceivedAt: appendResult.witnessReceivedAt.toISOString(),
          eventHash: appendResult.eventHash,
          previousHash: appendResult.previousHash,
          checkpointCreated: appendResult.checkpointCreated
            ? {
                checkpointId: appendResult.checkpointCreated.payload.checkpointId,
                checkpointSequence: appendResult.checkpointCreated.payload.checkpointSequence,
                chainHeadHash: appendResult.checkpointCreated.payload.chainHeadHash,
                checkpointHash: appendResult.checkpointCreated.checkpointHash,
              }
            : null,
          requestId,
        },
      };
    } catch (err: any) {
      await client.query('ROLLBACK');
      console.error('[WITNESS_HEARTBEAT_INGESTION_ERROR]', err);
      return {
        status: 500,
        body: {
          success: false,
          code: 'INTERNAL_ERROR',
          message: 'Failed to append heartbeat to witness chain.',
          requestId,
        },
      };
    } finally {
      client.release();
    }
  }

  /**
   * Ingests a signed tamper event independently from the primary backend.
   */
  async ingestTamper(
    body: unknown,
    tokenHeader: string | undefined,
    requestId: string
  ): Promise<{ status: number; body: Record<string, unknown> }> {
    // 1. Authentication
    if (!this.verifyToken(tokenHeader)) {
      await this.eventRepo.recordSecurityEvent('WITNESS_AUTH_FAILED', 'UNAUTHORIZED', {
        endpoint: '/witness/v1/tamper/events',
        requestId,
      });
      return {
        status: 401,
        body: {
          success: false,
          code: 'UNAUTHORIZED',
          message: 'Invalid or missing witness ingestion token.',
          requestId,
        },
      };
    }

    // 2. Schema Validation
    const validation = validateSignedTamperEnvelope(body);
    if (!validation.valid || !validation.data) {
      return {
        status: 400,
        body: {
          success: false,
          code: 'INVALID_SCHEMA',
          message: 'Tamper event payload does not match schema.',
          details: validation.errors,
          requestId,
        },
      };
    }

    const envelope: SignedTamperEnvelope = validation.data;
    const { payload, signature } = envelope;

    // 3. Key Registry Lookup
    const registeredKey = await this.keyRepo.getSensorKey(payload.keyId);
    if (!registeredKey) {
      await this.eventRepo.recordSecurityEvent('WITNESS_UNKNOWN_KEY', 'UNKNOWN_KEY', {
        keyId: payload.keyId,
        requestId,
      });
      return {
        status: 401,
        body: {
          success: false,
          code: 'UNKNOWN_KEY',
          message: `Witness key registry has no key registered for ID: ${payload.keyId}`,
          requestId,
        },
      };
    }

    if (registeredKey.status !== 'ACTIVE') {
      return {
        status: 403,
        body: {
          success: false,
          code: 'KEY_NOT_ACTIVE',
          message: `Signing key is ${registeredKey.status}`,
          requestId,
        },
      };
    }

    // 4. Sensor Identity Binding Verification
    if (registeredKey.sensorCode !== payload.sensorId) {
      await this.eventRepo.recordSecurityEvent('WITNESS_KEY_BINDING_MISMATCH', 'KEY_SENSOR_MISMATCH', {
        keyId: payload.keyId,
        claimed: payload.sensorId,
        bound: registeredKey.sensorCode,
        messageId: payload.eventId,
        requestId,
      });
      return {
        status: 400,
        body: {
          success: false,
          code: 'KEY_SENSOR_MISMATCH',
          message: `Key is bound to sensor ${registeredKey.sensorCode}, not ${payload.sensorId}`,
          requestId,
        },
      };
    }
    if (registeredKey.siteCode !== payload.siteId) {
      await this.eventRepo.recordSecurityEvent('WITNESS_KEY_BINDING_MISMATCH', 'KEY_SITE_MISMATCH', {
        keyId: payload.keyId,
        claimed: payload.siteId,
        bound: registeredKey.siteCode,
        messageId: payload.eventId,
        requestId,
      });
      return {
        status: 400,
        body: {
          success: false,
          code: 'KEY_SITE_MISMATCH',
          message: `Key is bound to site ${registeredKey.siteCode}, not ${payload.siteId}`,
          requestId,
        },
      };
    }
    if (registeredKey.stationCode !== payload.stationId) {
      await this.eventRepo.recordSecurityEvent('WITNESS_KEY_BINDING_MISMATCH', 'KEY_STATION_MISMATCH', {
        keyId: payload.keyId,
        claimed: payload.stationId,
        bound: registeredKey.stationCode,
        messageId: payload.eventId,
        requestId,
      });
      return {
        status: 400,
        body: {
          success: false,
          code: 'KEY_STATION_MISMATCH',
          message: `Key is bound to station ${registeredKey.stationCode}, not ${payload.stationId}`,
          requestId,
        },
      };
    }

    // 5. Signature Encoding Check
    const sigValidation = validateSignatureEncoding(signature);
    if (!sigValidation.valid) {
      return {
        status: 400,
        body: {
          success: false,
          code: 'INVALID_SIGNATURE_ENCODING',
          message: sigValidation.error || 'Invalid Base64 signature encoding',
          requestId,
        },
      };
    }

    // 6. Independent Ed25519 Signature Verification
    const canonicalPayload = canonicalizePayload(payload);
    const payloadHash = crypto.createHash('sha256').update(canonicalPayload, 'utf-8').digest('hex').toLowerCase();
    const signatureHash = crypto.createHash('sha256').update(signature, 'utf-8').digest('hex').toLowerCase();

    const verifyResult = verifySignature(payload, signature, registeredKey.publicKeyPem);
    if (!verifyResult.valid) {
      await this.eventRepo.recordSecurityEvent('WITNESS_SIGNATURE_VERIFICATION_FAILED', 'INVALID_SIGNATURE', {
        keyId: payload.keyId,
        eventId: payload.eventId,
        error: verifyResult.reason,
        requestId,
      });
      return {
        status: 401,
        body: {
          success: false,
          code: 'INVALID_SIGNATURE',
          message: 'Witness independent signature verification failed for tamper event.',
          requestId,
        },
      };
    }

    // 7. Freshness Check
    const eventDate = new Date(payload.eventTimestamp);
    const nowMs = Date.now();
    const futureSkewSec = (eventDate.getTime() - nowMs) / 1000;
    if (futureSkewSec > this.env.MAX_FUTURE_SKEW_SECONDS) {
      return {
        status: 400,
        body: {
          success: false,
          code: 'TIMESTAMP_FUTURE',
          message: `Tamper eventTimestamp is in the future beyond allowed skew limit (${Math.round(futureSkewSec)}s > ${this.env.MAX_FUTURE_SKEW_SECONDS}s)`,
          requestId,
        },
      };
    }

    // 8. Idempotency Check
    const dupCheck = await this.eventRepo.checkDuplicateMessage(payload.eventId);
    if (dupCheck.exists) {
      if (dupCheck.payloadHash === payloadHash && dupCheck.signatureBase64 === signature) {
        return {
          status: 200,
          body: {
            success: true,
            status: 'ACCEPTED',
            witnessEventId: dupCheck.eventId,
            witnessSequence: dupCheck.witnessSequence,
            witnessReceivedAt: dupCheck.witnessReceivedAt?.toISOString(),
            eventHash: dupCheck.eventHash,
            isDuplicate: true,
            requestId,
          },
        };
      } else {
        await this.eventRepo.recordSecurityEvent('WITNESS_DUPLICATE_MESSAGE_CONFLICT', 'DUPLICATE_MESSAGE', {
          eventId: payload.eventId,
          requestId,
        });
        return {
          status: 409,
          body: {
            success: false,
            code: 'DUPLICATE_MESSAGE',
            message: `Event ID ${payload.eventId} already exists in witness with differing payload content or signature`,
            requestId,
          },
        };
      }
    }

    // 9. Transactional persistence & hash chain append
    const witnessReceivedAt = new Date();
    const client = await this.pool.connect();
    try {
      await client.query('BEGIN');

      // Monotonic sequence check on sensor
      const lastSeq = await this.eventRepo.getLastTamperSequence(registeredKey.sensorCode, client);
      if (payload.sequence <= lastSeq) {
        await client.query('ROLLBACK');
        return {
          status: 409,
          body: {
            success: false,
            code: 'REPLAYED_SEQUENCE',
            message: `Tamper sequence ${payload.sequence} is not strictly monotonic in witness (last recorded: ${lastSeq})`,
            requestId,
          },
        };
      }

      // Insert into witness_tamper_events
      await this.eventRepo.insertTamperRecord(
        {
          eventId: payload.eventId,
          sensorCode: payload.sensorId,
          siteCode: registeredKey.siteCode,
          stationCode: registeredKey.stationCode,
          keyId: payload.keyId,
          eventType: payload.eventType,
          eventTimestamp: eventDate,
          tamperSource: payload.tamperSource,
          sequenceNo: payload.sequence,
          payload: payload as unknown as Record<string, unknown>,
          signatureBase64: signature,
          payloadHash,
          signatureHash,
        },
        client
      );

      // Append to witness hash chain
      const appendResult = await this.eventRepo.appendWitnessEventTransaction(
        {
          eventType: 'PHYSICAL_TAMPER',
          messageId: payload.eventId,
          siteCode: registeredKey.siteCode,
          stationCode: registeredKey.stationCode,
          identityType: 'SENSOR',
          identityCode: payload.sensorId,
          keyId: payload.keyId,
          bootId: 'TAMPER',
          sourceSequence: payload.sequence,
          sourceTimestamp: eventDate,
          payload: payload as unknown as Record<string, unknown>,
          signatureBase64: signature,
          payloadHash,
          signatureHash,
          checkpointService: this.checkpointService,
          checkpointInterval: this.env.WITNESS_CHECKPOINT_EVERY,
        },
        client
      );

      await client.query('COMMIT');

      return {
        status: 201,
        body: {
          success: true,
          status: 'ACCEPTED',
          witnessEventId: appendResult.eventId,
          witnessSequence: appendResult.witnessSequence,
          witnessReceivedAt: witnessReceivedAt.toISOString(),
          eventHash: appendResult.eventHash,
          previousHash: appendResult.previousHash,
          checkpointCreated: appendResult.checkpointCreated,
          requestId,
          simulated: payload.tamperSource === 'SIMULATED',
        },
      };
    } catch (err: any) {
      await client.query('ROLLBACK');
      console.error('[WITNESS_TAMPER_INGESTION_ERROR]', err);
      return {
        status: 500,
        body: {
          success: false,
          code: 'INTERNAL_ERROR',
          message: 'Failed to append tamper event to witness chain.',
          requestId,
        },
      };
    } finally {
      client.release();
    }
  }
}
