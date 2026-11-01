import crypto from 'node:crypto';
import type { Pool } from 'pg';
import {
  validateSignedTelemetryEnvelope,
  validateSignedOpsContextEnvelope,
  validateSignedHeartbeatEnvelope,
  type SignedTelemetryEnvelope,
  type SignedOpsContextEnvelope,
  type SignedHeartbeatEnvelope,
  validateSignedTamperEnvelope,
  type SignedTamperEnvelope,
} from '@envirotrust/contracts';
import {
  canonicalizePayload,
  verifySignature,
  validateSignatureEncoding,
} from '@envirotrust/crypto';
import { KeyRepository } from '../repositories/key.repository.js';
import { TelemetryRepository } from '../repositories/telemetry.repository.js';
import { OperationsRepository } from '../repositories/operations.repository.js';
import { AuditRepository } from '../repositories/audit.repository.js';
import { SecurityEventRepository } from '../repositories/security-event.repository.js';
import { HeartbeatRepository } from '../repositories/heartbeat.repository.js';
import { TamperRepository } from '../repositories/tamper.repository.js';
import { AlertRepository } from '../repositories/alert.repository.js';
import { AVAILABILITY_CONSTANTS } from '../constants/availability.constants.js';

export interface IngestionError {
  httpStatus: number;
  code: string;
  message: string;
  details?: unknown;
}

export interface TelemetryIngestSuccess {
  success: true;
  messageId: string;
  readingId: string;
  signatureStatus: 'VALID';
  protocolStatus: string;
  primaryAuditSequence: number;
  chainHeadHash: string;
  witnessStatus: 'PENDING';
  receivedAt: string;
}

export interface OperationsIngestSuccess {
  success: true;
  messageId: string;
  readingId: string;
  verificationStatus: 'VALID';
  primaryAuditSequence: number;
  chainHeadHash: string;
  receivedAt: string;
}

export interface HeartbeatIngestSuccess {
  success: true;
  status: 'ACCEPTED';
  messageId: string;
  heartbeatSequence: number;
  receivedAt: string;
  primaryAuditSequence: number;
  chainHeadHash: string;
  isDuplicate?: boolean;
}

export class IngestionService {
  private readonly keyRepo: KeyRepository;
  private readonly telemetryRepo: TelemetryRepository;
  private readonly opsRepo: OperationsRepository;
  private readonly auditRepo: AuditRepository;
  private readonly securityRepo: SecurityEventRepository;
  private readonly heartbeatRepo: HeartbeatRepository;
  private readonly tamperRepo: TamperRepository;
  private readonly alertRepo: AlertRepository;

  constructor(private readonly pool: Pool) {
    this.keyRepo = new KeyRepository(pool);
    this.telemetryRepo = new TelemetryRepository(pool);
    this.opsRepo = new OperationsRepository(pool);
    this.auditRepo = new AuditRepository(pool);
    this.securityRepo = new SecurityEventRepository(pool);
    this.heartbeatRepo = new HeartbeatRepository(pool);
    this.tamperRepo = new TamperRepository(pool);
    this.alertRepo = new AlertRepository(pool);
  }

  private getMaxFutureSkewSeconds(): number {
    return Number(process.env['MAX_FUTURE_SKEW_SECONDS']) || AVAILABILITY_CONSTANTS.MAX_FUTURE_SKEW_SECONDS;
  }

  private getMaxTelemetryAgeSeconds(): number {
    return Number(process.env['MAX_TELEMETRY_AGE_SECONDS']) || AVAILABILITY_CONSTANTS.MAX_TELEMETRY_AGE_SECONDS;
  }

  /**
   * Ingests and cryptographically validates a signed telemetry envelope.
   */
  async ingestTelemetry(
    body: unknown,
    requestId: string
  ): Promise<{ status: number; body: TelemetryIngestSuccess | Record<string, unknown> }> {
    // 1. Schema Validation
    const validation = validateSignedTelemetryEnvelope(body);
    if (!validation.valid || !validation.data) {
      return {
        status: 400,
        body: {
          success: false,
          code: 'INVALID_SCHEMA',
          message: 'Telemetry payload does not match schema',
          requestId,
          details: validation.errors,
        },
      };
    }

    const envelope: SignedTelemetryEnvelope = validation.data;
    const { payload, signature } = envelope;

    // 2. Public Key Registry Lookup
    const registeredKey = await this.keyRepo.getDeviceKey(payload.keyId);
    if (!registeredKey) {
      await this.securityRepo.recordSecurityEvent({
        eventType: 'INGESTION_UNKNOWN_KEY',
        reasonCode: 'UNKNOWN_KEY',
        metadata: { keyId: payload.keyId, sensorId: payload.sensorId, requestId },
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

    // 3. Key Status and Validity Check
    if (registeredKey.status !== 'ACTIVE') {
      await this.securityRepo.recordSecurityEvent({
        siteId: registeredKey.siteId,
        sensorId: registeredKey.sensorId,
        eventType: 'INGESTION_INACTIVE_KEY',
        reasonCode: 'KEY_NOT_ACTIVE',
        metadata: { keyId: payload.keyId, status: registeredKey.status, requestId },
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

    const measuredDate = new Date(payload.measuredAt);
    if (registeredKey.validFrom && measuredDate < new Date(registeredKey.validFrom)) {
      return {
        status: 403,
        body: {
          success: false,
          code: 'KEY_NOT_YET_VALID',
          message: 'Measurement timestamp is earlier than key validity start time',
          requestId,
        },
      };
    }
    if (registeredKey.validTo && measuredDate > new Date(registeredKey.validTo)) {
      return {
        status: 403,
        body: {
          success: false,
          code: 'KEY_EXPIRED',
          message: 'Signing key has expired',
          requestId,
        },
      };
    }

    // 4. Sensor Identity Binding Verification
    if (registeredKey.sensorCode !== payload.sensorId) {
      await this.securityRepo.recordSecurityEvent({
        siteId: registeredKey.siteId,
        sensorId: registeredKey.sensorId,
        eventType: 'INGESTION_KEY_BINDING_MISMATCH',
        reasonCode: 'KEY_SENSOR_MISMATCH',
        metadata: {
          keyId: payload.keyId,
          claimed: payload.sensorId,
          bound: registeredKey.sensorCode,
          messageId: payload.messageId,
          requestId,
        },
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
      await this.securityRepo.recordSecurityEvent({
        siteId: registeredKey.siteId,
        sensorId: registeredKey.sensorId,
        eventType: 'INGESTION_KEY_BINDING_MISMATCH',
        reasonCode: 'KEY_SITE_MISMATCH',
        metadata: {
          keyId: payload.keyId,
          claimed: payload.siteId,
          bound: registeredKey.siteCode,
          messageId: payload.messageId,
          requestId,
        },
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
      await this.securityRepo.recordSecurityEvent({
        siteId: registeredKey.siteId,
        sensorId: registeredKey.sensorId,
        eventType: 'INGESTION_KEY_BINDING_MISMATCH',
        reasonCode: 'KEY_STATION_MISMATCH',
        metadata: {
          keyId: payload.keyId,
          claimed: payload.stationId,
          bound: registeredKey.stationCode,
          messageId: payload.messageId,
          requestId,
        },
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
      await this.securityRepo.recordSecurityEvent({
        siteId: registeredKey.siteId,
        sensorId: registeredKey.sensorId,
        eventType: 'INGESTION_KEY_BINDING_MISMATCH',
        reasonCode: 'KEY_PARAMETER_MISMATCH',
        metadata: {
          keyId: payload.keyId,
          claimed: payload.parameter,
          bound: registeredKey.parameter,
          messageId: payload.messageId,
          requestId,
        },
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

    // 5. Signature Encoding Validation
    const sigValidation = validateSignatureEncoding(signature);
    if (!sigValidation.valid) {
      await this.securityRepo.recordSecurityEvent({
        siteId: registeredKey.siteId,
        sensorId: registeredKey.sensorId,
        eventType: 'INGESTION_INVALID_SIGNATURE_ENCODING',
        reasonCode: 'INVALID_SIGNATURE_ENCODING',
        metadata: { keyId: payload.keyId, error: sigValidation.error, requestId },
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

    // 6. Cryptographic Signature Verification
    const canonicalPayload = canonicalizePayload(payload);
    const payloadHash = crypto.createHash('sha256').update(canonicalPayload).digest('hex').toLowerCase();

    const verifyResult = verifySignature(payload, signature, registeredKey.publicKeyPem);
    if (!verifyResult.valid) {
      await this.securityRepo.recordSecurityEvent({
        siteId: registeredKey.siteId,
        sensorId: registeredKey.sensorId,
        eventType: 'INGESTION_SIGNATURE_VERIFICATION_FAILED',
        reasonCode: 'INVALID_SIGNATURE',
        metadata: {
          keyId: payload.keyId,
          messageId: payload.messageId,
          error: verifyResult.reason,
          requestId,
        },
      });
      return {
        status: 401,
        body: {
          success: false,
          code: 'INVALID_SIGNATURE',
          message: 'The submitted telemetry signature could not be verified.',
          requestId,
        },
      };
    }

    // 7. Freshness and Timestamp Policy
    const nowMs = Date.now();
    const measuredMs = measuredDate.getTime();
    const futureSkewSec = (measuredMs - nowMs) / 1000;
    const maxFutureSkew = this.getMaxFutureSkewSeconds();

    if (futureSkewSec > maxFutureSkew) {
      return {
        status: 400,
        body: {
          success: false,
          code: 'TIMESTAMP_FUTURE',
          message: `Timestamp is in the future beyond allowed skew limit (${Math.round(futureSkewSec)}s > ${maxFutureSkew}s)`,
          requestId,
        },
      };
    }

    const ageSec = (nowMs - measuredMs) / 1000;
    const maxAge = this.getMaxTelemetryAgeSeconds();
    let protocolStatus: 'FRESH' | 'DELAYED' = 'FRESH';
    if (ageSec > maxAge) {
      protocolStatus = 'DELAYED';
    }

    // 8. Transactional Persistence and Replay Protection
    const client = await this.pool.connect();
    try {
      await client.query('BEGIN');

      // 8a. Check duplicate messageId
      const dupCheck = await this.telemetryRepo.checkDuplicateMessage(
        payload.messageId,
        payloadHash,
        signature,
        client
      );

      if (dupCheck.status === 'IDEMPOTENT_DUPLICATE') {
        await client.query('COMMIT');
        return {
          status: 200,
          body: {
            success: true,
            messageId: payload.messageId,
            readingId: dupCheck.readingId,
            signatureStatus: 'VALID',
            protocolStatus: dupCheck.protocolStatus,
            primaryAuditSequence: dupCheck.sequenceNo,
            witnessStatus: 'PENDING',
            receivedAt: dupCheck.receivedAt,
            isDuplicate: true,
          },
        };
      }

      if (dupCheck.status === 'CONFLICT') {
        await client.query('ROLLBACK');
        await this.securityRepo.recordSecurityEvent({
          siteId: registeredKey.siteId,
          sensorId: registeredKey.sensorId,
          eventType: 'INGESTION_DUPLICATE_MESSAGE_CONFLICT',
          reasonCode: 'DUPLICATE_MESSAGE',
          metadata: { messageId: payload.messageId, requestId },
        });
        return {
          status: 409,
          body: {
            success: false,
            code: 'DUPLICATE_MESSAGE',
            message: `Message ID ${payload.messageId} already exists with differing payload content`,
            requestId,
          },
        };
      }

      // 8b. Sequence validation & insert into telemetry_readings
      const insertResult = await this.telemetryRepo.insertTelemetryTransaction(
        {
          sensorIdUuid: registeredKey.sensorId,
          keyId: payload.keyId,
          siteIdUuid: registeredKey.siteId,
          stationIdUuid: registeredKey.stationId,
          payload,
          signatureBase64: signature,
          payloadHash,
          protocolStatus,
        },
        client
      );

      if (!insertResult.success) {
        await client.query('ROLLBACK');
        await this.securityRepo.recordSecurityEvent({
          siteId: registeredKey.siteId,
          sensorId: registeredKey.sensorId,
          eventType: 'INGESTION_REPLAY_DETECTED',
          reasonCode: insertResult.code,
          metadata: { messageId: payload.messageId, error: insertResult.message, requestId },
        });
        return {
          status: 409,
          body: {
            success: false,
            code: insertResult.code,
            message: insertResult.message,
            requestId,
          },
        };
      }

      // 8c. Append to Station Audit Hash Chain
      const auditResult = await this.auditRepo.appendStationEvent(
        {
          stationId: registeredKey.stationId,
          eventType: 'TELEMETRY_INGESTION',
          entityId: payload.sensorId,
          messageId: payload.messageId,
          payloadHash,
          eventPayload: {
            messageId: payload.messageId,
            sensorId: payload.sensorId,
            parameter: payload.parameter,
            value: payload.value,
            unit: payload.unit,
            measuredAt: payload.measuredAt,
            sequence: payload.sequence,
            bootId: payload.bootId,
            payloadHash,
            signature,
          },
        },
        client
      );

      // 8d. If COD parameter, enqueue asynchronous ML assessment job transactionally
      if (payload.parameter === 'COD') {
        await client.query(
          `INSERT INTO ml_assessment_jobs (reading_id, site_id, sensor_id, status, attempts, next_run_at)
           VALUES ($1, $2, $3, 'PENDING', 0, now())
           ON CONFLICT (reading_id) DO NOTHING`,
          [insertResult.readingId, registeredKey.siteId, registeredKey.sensorId]
        );
      }

      await client.query('COMMIT');

      return {
        status: 201,
        body: {
          success: true,
          messageId: payload.messageId,
          readingId: insertResult.readingId,
          signatureStatus: 'VALID',
          protocolStatus: insertResult.protocolStatus,
          primaryAuditSequence: auditResult.eventSequence,
          chainHeadHash: auditResult.eventHash,
          witnessStatus: 'PENDING',
          receivedAt: insertResult.receivedAt,
        },
      };
    } catch (err) {
      await client.query('ROLLBACK');
      console.error('[INGESTION] Internal database error:', (err as Error).message);
      return {
        status: 500,
        body: {
          success: false,
          code: 'DATABASE_ERROR',
          message: 'Internal error processing telemetry ingestion',
          requestId,
        },
      };
    } finally {
      client.release();
    }
  }

  /**
   * Ingests and independently verifies a signed sensor heartbeat.
   */
  async ingestHeartbeat(
    body: unknown,
    requestId: string
  ): Promise<{ status: number; body: HeartbeatIngestSuccess | Record<string, unknown> }> {
    // 1. Schema Validation
    const validation = validateSignedHeartbeatEnvelope(body);
    if (!validation.valid || !validation.data) {
      return {
        status: 400,
        body: {
          success: false,
          code: 'INVALID_SCHEMA',
          message: 'Heartbeat payload does not match schema',
          requestId,
          details: validation.errors,
        },
      };
    }

    const envelope: SignedHeartbeatEnvelope = validation.data;
    const { payload, signature } = envelope;

    // 2. Public Key Registry Lookup
    const registeredKey = await this.keyRepo.getDeviceKey(payload.keyId);
    if (!registeredKey) {
      await this.securityRepo.recordSecurityEvent({
        eventType: 'HEARTBEAT_UNKNOWN_KEY',
        reasonCode: 'UNKNOWN_KEY',
        metadata: { keyId: payload.keyId, sensorId: payload.sensorId, requestId },
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

    // 3. Key Status and Validity Check
    if (registeredKey.status !== 'ACTIVE') {
      await this.securityRepo.recordSecurityEvent({
        siteId: registeredKey.siteId,
        sensorId: registeredKey.sensorId,
        eventType: 'HEARTBEAT_INACTIVE_KEY',
        reasonCode: 'KEY_NOT_ACTIVE',
        metadata: { keyId: payload.keyId, status: registeredKey.status, requestId },
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
    if (registeredKey.validFrom && sentDate < new Date(registeredKey.validFrom)) {
      return {
        status: 403,
        body: {
          success: false,
          code: 'KEY_NOT_YET_VALID',
          message: 'Heartbeat timestamp is earlier than key validity start time',
          requestId,
        },
      };
    }
    if (registeredKey.validTo && sentDate > new Date(registeredKey.validTo)) {
      return {
        status: 403,
        body: {
          success: false,
          code: 'KEY_EXPIRED',
          message: 'Signing key has expired',
          requestId,
        },
      };
    }

    // 4. Sensor Identity Binding Verification
    if (registeredKey.sensorCode !== payload.sensorId) {
      await this.securityRepo.recordSecurityEvent({
        siteId: registeredKey.siteId,
        sensorId: registeredKey.sensorId,
        eventType: 'HEARTBEAT_KEY_BINDING_MISMATCH',
        reasonCode: 'KEY_SENSOR_MISMATCH',
        metadata: {
          keyId: payload.keyId,
          claimed: payload.sensorId,
          bound: registeredKey.sensorCode,
          messageId: payload.messageId,
          requestId,
        },
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
      await this.securityRepo.recordSecurityEvent({
        siteId: registeredKey.siteId,
        sensorId: registeredKey.sensorId,
        eventType: 'HEARTBEAT_KEY_BINDING_MISMATCH',
        reasonCode: 'KEY_SITE_MISMATCH',
        metadata: {
          keyId: payload.keyId,
          claimed: payload.siteId,
          bound: registeredKey.siteCode,
          messageId: payload.messageId,
          requestId,
        },
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
      await this.securityRepo.recordSecurityEvent({
        siteId: registeredKey.siteId,
        sensorId: registeredKey.sensorId,
        eventType: 'HEARTBEAT_KEY_BINDING_MISMATCH',
        reasonCode: 'KEY_STATION_MISMATCH',
        metadata: {
          keyId: payload.keyId,
          claimed: payload.stationId,
          bound: registeredKey.stationCode,
          messageId: payload.messageId,
          requestId,
        },
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

    // 5. Signature Encoding Validation
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

    // 6. Cryptographic Signature Verification
    const canonicalPayload = canonicalizePayload(payload);
    const payloadHash = crypto.createHash('sha256').update(canonicalPayload, 'utf-8').digest('hex').toLowerCase();

    const verifyResult = verifySignature(payload, signature, registeredKey.publicKeyPem);
    if (!verifyResult.valid) {
      await this.securityRepo.recordSecurityEvent({
        siteId: registeredKey.siteId,
        sensorId: registeredKey.sensorId,
        eventType: 'HEARTBEAT_SIGNATURE_VERIFICATION_FAILED',
        reasonCode: 'INVALID_SIGNATURE',
        metadata: {
          keyId: payload.keyId,
          messageId: payload.messageId,
          error: verifyResult.reason,
          requestId,
        },
      });
      return {
        status: 401,
        body: {
          success: false,
          code: 'INVALID_SIGNATURE',
          message: 'The submitted heartbeat signature could not be verified.',
          requestId,
        },
      };
    }

    // 7. Freshness check
    const nowMs = Date.now();
    const sentMs = sentDate.getTime();
    const futureSkewSec = (sentMs - nowMs) / 1000;
    if (futureSkewSec > this.getMaxFutureSkewSeconds()) {
      return {
        status: 400,
        body: {
          success: false,
          code: 'TIMESTAMP_FUTURE',
          message: `Heartbeat timestamp is in the future beyond allowed skew limit (${Math.round(futureSkewSec)}s > ${this.getMaxFutureSkewSeconds()}s)`,
          requestId,
        },
      };
    }

    // 8. Transactional persistence & replay protection
    const serverReceivedAt = new Date();
    const client = await this.pool.connect();

    try {
      await client.query('BEGIN');

      // Check duplicate messageId
      const dupCheck = await this.heartbeatRepo.checkDuplicateMessage(payload.messageId, signature, client);
      if (dupCheck.status === 'IDEMPOTENT_DUPLICATE') {
        await client.query('COMMIT');
        return {
          status: 200,
          body: {
            success: true,
            status: 'ACCEPTED',
            messageId: payload.messageId,
            heartbeatSequence: dupCheck.sequenceNo || payload.heartbeatSequence,
            receivedAt: dupCheck.receivedAt || serverReceivedAt.toISOString(),
            primaryAuditSequence: 0,
            chainHeadHash: '',
            isDuplicate: true,
            requestId,
          },
        };
      }

      if (dupCheck.status === 'CONFLICT') {
        await client.query('ROLLBACK');
        return {
          status: 409,
          body: {
            success: false,
            code: 'DUPLICATE_MESSAGE',
            message: `Message ID ${payload.messageId} already exists with differing signature`,
            requestId,
          },
        };
      }

      // Insert heartbeat & update sequence cursor
      let insertResult;
      try {
        insertResult = await this.heartbeatRepo.insertHeartbeatTransaction(
          {
            sensorIdUuid: registeredKey.sensorId,
            keyId: payload.keyId,
            stationIdUuid: registeredKey.stationId,
            payload,
            signatureBase64: signature,
            payloadHash,
            serverReceivedAt,
          },
          client
        );
      } catch (insertErr: any) {
        if (insertErr.code === 'REPLAYED_SEQUENCE') {
          await client.query('ROLLBACK');
          return {
            status: 409,
            body: {
              success: false,
              code: 'REPLAYED_SEQUENCE',
              message: insertErr.message,
              requestId,
            },
          };
        }
        throw insertErr;
      }

      // Append station audit event for heartbeat
      const auditResult = await this.auditRepo.appendStationEvent(
        {
          stationId: registeredKey.stationId,
          eventType: 'HEARTBEAT',
          entityId: payload.sensorId,
          messageId: payload.messageId,
          payloadHash,
          eventPayload: {
            messageId: payload.messageId,
            sensorId: payload.sensorId,
            keyId: payload.keyId,
            bootId: payload.bootId,
            heartbeatSequence: payload.heartbeatSequence,
            sentAt: payload.sentAt,
            serverReceivedAt: insertResult.serverReceivedAt,
          },
        },
        client
      );

      // If recovered from OFFLINE/STALE, append SENSOR_STATE_TRANSITION audit event
      if (insertResult.recoveredFromOffline) {
        await this.auditRepo.appendStationEvent(
          {
            stationId: registeredKey.stationId,
            eventType: 'SENSOR_STATE_TRANSITION',
            entityId: payload.sensorId,
            messageId: payload.messageId,
            payloadHash,
            eventPayload: {
              sensorId: payload.sensorId,
              fromStatus: insertResult.previousStatus || 'OFFLINE',
              toStatus: 'ONLINE',
              reason: 'SENSOR_RECOVERED',
              messageId: payload.messageId,
              heartbeatSequence: payload.heartbeatSequence,
              serverReceivedAt: insertResult.serverReceivedAt,
            },
          },
          client
        );
      }

      await client.query('COMMIT');

      return {
        status: 201,
        body: {
          success: true,
          status: 'ACCEPTED',
          messageId: payload.messageId,
          heartbeatSequence: insertResult.sequenceNo,
          receivedAt: insertResult.serverReceivedAt,
          primaryAuditSequence: auditResult.eventSequence,
          chainHeadHash: auditResult.eventHash,
          requestId,
        },
      };
    } catch (err: any) {
      await client.query('ROLLBACK');
      console.error('[INGESTION] Heartbeat DB error:', err.message);
      return {
        status: 500,
        body: {
          success: false,
          code: 'DATABASE_ERROR',
          message: 'Internal error processing heartbeat ingestion',
          requestId,
        },
      };
    } finally {
      client.release();
    }
  }

  /**
   * Ingests and cryptographically validates a signed operations context envelope.
   */
  async ingestOperationsContext(
    body: unknown,
    requestId: string
  ): Promise<{ status: number; body: OperationsIngestSuccess | Record<string, unknown> }> {
    // 1. Schema Validation
    const validation = validateSignedOpsContextEnvelope(body);
    if (!validation.valid || !validation.data) {
      return {
        status: 400,
        body: {
          success: false,
          code: 'INVALID_SCHEMA',
          message: 'Operations context payload does not match schema',
          requestId,
          details: validation.errors,
        },
      };
    }

    const envelope: SignedOpsContextEnvelope = validation.data;
    const { payload, signature } = envelope;

    // 2. Public Key Registry Lookup
    const registeredKey = await this.keyRepo.getOperationsKey(payload.keyId);
    if (!registeredKey) {
      await this.securityRepo.recordSecurityEvent({
        eventType: 'INGESTION_UNKNOWN_OPS_KEY',
        reasonCode: 'UNKNOWN_KEY',
        metadata: { keyId: payload.keyId, sourceId: payload.sourceId, requestId },
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

    // 3. Key Status Check
    if (registeredKey.status !== 'ACTIVE') {
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
      await this.securityRepo.recordSecurityEvent({
        siteId: registeredKey.siteId,
        eventType: 'OPERATIONS_KEY_BINDING_MISMATCH',
        reasonCode: 'KEY_SOURCE_MISMATCH',
        metadata: {
          keyId: payload.keyId,
          claimed: payload.sourceId,
          bound: registeredKey.sourceId,
          messageId: payload.messageId,
          requestId,
        },
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
      await this.securityRepo.recordSecurityEvent({
        siteId: registeredKey.siteId,
        eventType: 'OPERATIONS_KEY_BINDING_MISMATCH',
        reasonCode: 'KEY_SITE_MISMATCH',
        metadata: {
          keyId: payload.keyId,
          claimed: payload.siteId,
          bound: registeredKey.siteCode,
          messageId: payload.messageId,
          requestId,
        },
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
      await this.securityRepo.recordSecurityEvent({
        siteId: registeredKey.siteId,
        eventType: 'OPERATIONS_KEY_BINDING_MISMATCH',
        reasonCode: 'KEY_STATION_MISMATCH',
        metadata: {
          keyId: payload.keyId,
          claimed: payload.stationId,
          bound: registeredKey.stationCode,
          messageId: payload.messageId,
          requestId,
        },
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

    // 5. Signature Encoding & Verification
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

    const canonicalPayload = canonicalizePayload(payload);
    const payloadHash = crypto.createHash('sha256').update(canonicalPayload).digest('hex').toLowerCase();

    const verifyResult = verifySignature(payload, signature, registeredKey.publicKeyPem);
    if (!verifyResult.valid) {
      await this.securityRepo.recordSecurityEvent({
        siteId: registeredKey.siteId,
        eventType: 'OPS_INGESTION_INVALID_SIGNATURE',
        reasonCode: 'INVALID_SIGNATURE',
        metadata: {
          keyId: payload.keyId,
          sourceId: payload.sourceId,
          messageId: payload.messageId,
          requestId,
        },
      });
      return {
        status: 401,
        body: {
          success: false,
          code: 'INVALID_SIGNATURE',
          message: 'The submitted operations context signature could not be verified.',
          requestId,
        },
      };
    }

    // 6. Transactional Persistence and Audit Append
    const client = await this.pool.connect();
    try {
      await client.query('BEGIN');

      // Check duplicate messageId
      const dupCheck = await this.opsRepo.checkDuplicateMessage(
        payload.messageId,
        payloadHash,
        signature,
        client
      );

      if (dupCheck.status === 'IDEMPOTENT_DUPLICATE') {
        await client.query('COMMIT');
        return {
          status: 200,
          body: {
            success: true,
            messageId: payload.messageId,
            readingId: dupCheck.readingId,
            verificationStatus: 'VALID',
            primaryAuditSequence: dupCheck.sequenceNo,
            receivedAt: dupCheck.receivedAt,
            isDuplicate: true,
          },
        };
      }

      if (dupCheck.status === 'CONFLICT') {
        await client.query('ROLLBACK');
        return {
          status: 409,
          body: {
            success: false,
            code: 'DUPLICATE_MESSAGE',
            message: `Operations message ID ${payload.messageId} already exists with differing payload content`,
            requestId,
          },
        };
      }

      const insertResult = await this.opsRepo.insertOperationsTransaction(
        {
          siteIdUuid: registeredKey.siteId,
          stationIdUuid: registeredKey.stationId,
          payload,
          signatureBase64: signature,
          payloadHash,
        },
        client
      );

      if (!insertResult.success) {
        await client.query('ROLLBACK');
        return {
          status: insertResult.code === 'INVALID_INTERVAL' ? 400 : 409,
          body: {
            success: false,
            code: insertResult.code,
            message: insertResult.message,
            requestId,
          },
        };
      }

      // Append to Station Audit Hash Chain
      const auditResult = await this.auditRepo.appendStationEvent(
        {
          stationId: registeredKey.stationId,
          eventType: 'OPERATIONS_CONTEXT_INGESTION',
          entityId: payload.sourceId,
          messageId: payload.messageId,
          payloadHash,
          eventPayload: {
            messageId: payload.messageId,
            sourceId: payload.sourceId,
            sequence: payload.sequence,
            intervalStart: payload.intervalStart,
            intervalEnd: payload.intervalEnd,
            operatingMode: payload.operatingMode,
            payloadHash,
            signature,
          },
        },
        client
      );

      // Awaken any pending COD assessment jobs for this site waiting for this interval
      await client.query(
        `UPDATE ml_assessment_jobs j
         SET next_run_at = now(),
             updated_at = now()
         FROM telemetry_readings tr
         WHERE j.reading_id = tr.id
           AND j.site_id = $1
           AND j.status = 'PENDING'
           AND tr.measured_at >= ($2::timestamptz - INTERVAL '30 seconds')
           AND tr.measured_at <= ($3::timestamptz + INTERVAL '30 seconds')`,
        [registeredKey.siteId, payload.intervalStart, payload.intervalEnd]
      );

      await client.query('COMMIT');

      return {
        status: 201,
        body: {
          success: true,
          messageId: payload.messageId,
          readingId: insertResult.readingId,
          verificationStatus: 'VALID',
          primaryAuditSequence: auditResult.eventSequence,
          chainHeadHash: auditResult.eventHash,
          receivedAt: insertResult.receivedAt,
        },
      };
    } catch (err) {
      await client.query('ROLLBACK');
      console.error('[INGESTION] Operations DB error:', (err as Error).message);
      return {
        status: 500,
        body: {
          success: false,
          code: 'DATABASE_ERROR',
          message: 'Internal error processing operations context ingestion',
          requestId,
        },
      };
    } finally {
      client.release();
    }
  }

  /**
   * Ingests and cryptographically validates a signed physical tamper event.
   */
  async ingestTamper(
    body: unknown,
    requestId: string
  ): Promise<{ status: number; body: Record<string, unknown> }> {
    // 1. Schema Validation
    const validation = validateSignedTamperEnvelope(body);
    if (!validation.valid || !validation.data) {
      return {
        status: 400,
        body: {
          success: false,
          code: 'INVALID_SCHEMA',
          message: 'Tamper event payload does not match schema',
          requestId,
          details: validation.errors,
        },
      };
    }

    const envelope: SignedTamperEnvelope = validation.data;
    const { payload, signature } = envelope;

    // 2. Public Key Registry Lookup
    const registeredKey = await this.keyRepo.getDeviceKey(payload.keyId);
    if (!registeredKey) {
      await this.securityRepo.recordSecurityEvent({
        eventType: 'TAMPER_UNKNOWN_KEY',
        reasonCode: 'UNKNOWN_KEY',
        metadata: { keyId: payload.keyId, sensorId: payload.sensorId, eventId: payload.eventId, requestId },
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

    // 3. Key Status and Validity Check
    if (registeredKey.status !== 'ACTIVE') {
      await this.securityRepo.recordSecurityEvent({
        siteId: registeredKey.siteId,
        sensorId: registeredKey.sensorId,
        eventType: 'TAMPER_INACTIVE_KEY',
        reasonCode: 'KEY_NOT_ACTIVE',
        metadata: { keyId: payload.keyId, status: registeredKey.status, requestId },
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

    // 4. Sensor Identity Binding Verification
    if (registeredKey.sensorCode !== payload.sensorId) {
      await this.securityRepo.recordSecurityEvent({
        siteId: registeredKey.siteId,
        sensorId: registeredKey.sensorId,
        eventType: 'TAMPER_IDENTITY_MISMATCH',
        reasonCode: 'KEY_SENSOR_MISMATCH',
        metadata: { keySensor: registeredKey.sensorCode, payloadSensor: payload.sensorId, requestId },
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
      await this.securityRepo.recordSecurityEvent({
        siteId: registeredKey.siteId,
        sensorId: registeredKey.sensorId,
        eventType: 'TAMPER_KEY_BINDING_MISMATCH',
        reasonCode: 'KEY_SITE_MISMATCH',
        metadata: {
          keyId: payload.keyId,
          claimed: payload.siteId,
          bound: registeredKey.siteCode,
          messageId: payload.eventId,
          requestId,
        },
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
      await this.securityRepo.recordSecurityEvent({
        siteId: registeredKey.siteId,
        sensorId: registeredKey.sensorId,
        eventType: 'TAMPER_KEY_BINDING_MISMATCH',
        reasonCode: 'KEY_STATION_MISMATCH',
        metadata: {
          keyId: payload.keyId,
          claimed: payload.stationId,
          bound: registeredKey.stationCode,
          messageId: payload.eventId,
          requestId,
        },
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

    // 5. Signature Encoding Validation
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

    // 6. Cryptographic Signature Verification
    const canonicalPayload = canonicalizePayload(payload);
    const payloadHash = crypto.createHash('sha256').update(canonicalPayload, 'utf-8').digest('hex').toLowerCase();

    const verifyResult = verifySignature(payload, signature, registeredKey.publicKeyPem);
    if (!verifyResult.valid) {
      await this.securityRepo.recordSecurityEvent({
        siteId: registeredKey.siteId,
        sensorId: registeredKey.sensorId,
        eventType: 'TAMPER_SIGNATURE_VERIFICATION_FAILED',
        reasonCode: 'INVALID_SIGNATURE',
        metadata: {
          keyId: payload.keyId,
          eventId: payload.eventId,
          error: verifyResult.reason,
          requestId,
        },
      });
      return {
        status: 401,
        body: {
          success: false,
          code: 'INVALID_SIGNATURE',
          message: 'The submitted tamper event signature could not be verified.',
          requestId,
        },
      };
    }

    // 7. Freshness check
    const eventDate = new Date(payload.eventTimestamp);
    const nowMs = Date.now();
    const futureSkewSec = (eventDate.getTime() - nowMs) / 1000;
    if (futureSkewSec > this.getMaxFutureSkewSeconds()) {
      return {
        status: 400,
        body: {
          success: false,
          code: 'TIMESTAMP_FUTURE',
          message: `Tamper event timestamp is in the future beyond allowed skew limit (${Math.round(futureSkewSec)}s > ${this.getMaxFutureSkewSeconds()}s)`,
          requestId,
        },
      };
    }

    // 8. Transactional persistence & replay protection
    const serverReceivedAt = new Date();
    const client = await this.pool.connect();

    try {
      await client.query('BEGIN');

      // Check duplicate eventId
      const dupCheck = await this.tamperRepo.checkDuplicateEvent(payload.eventId, signature, client);
      if (dupCheck.status === 'IDEMPOTENT_DUPLICATE') {
        await client.query('COMMIT');
        return {
          status: 200,
          body: {
            success: true,
            status: 'ACCEPTED',
            eventId: payload.eventId,
            sequenceNo: dupCheck.sequenceNo || payload.sequence,
            receivedAt: serverReceivedAt.toISOString(),
            isDuplicate: true,
            message: 'Idempotent duplicate tamper event already recorded',
          },
        };
      }

      if (dupCheck.status === 'DUPLICATE_MISMATCH') {
        await client.query('ROLLBACK');
        await this.securityRepo.recordSecurityEvent({
          siteId: registeredKey.siteId,
          sensorId: registeredKey.sensorId,
          eventType: 'TAMPER_REPLAY_CONFLICT',
          reasonCode: 'DUPLICATE_EVENT_ID',
          metadata: { eventId: payload.eventId, requestId },
        });
        return {
          status: 409,
          body: {
            success: false,
            code: 'DUPLICATE_EVENT_ID',
            message: 'Tamper eventId has already been used with different content or signature',
            requestId,
          },
        };
      }

      // Check sequence monotonicity
      const lastSeq = await this.tamperRepo.getLastTamperSequence(registeredKey.sensorId, client);
      if (payload.sequence <= lastSeq) {
        await client.query('ROLLBACK');
        await this.securityRepo.recordSecurityEvent({
          siteId: registeredKey.siteId,
          sensorId: registeredKey.sensorId,
          eventType: 'TAMPER_REPLAYED_SEQUENCE',
          reasonCode: 'REPLAYED_SEQUENCE',
          metadata: { submittedSequence: payload.sequence, lastRecordedSequence: lastSeq, requestId },
        });
        return {
          status: 409,
          body: {
            success: false,
            code: 'REPLAYED_SEQUENCE',
            message: `Tamper sequence ${payload.sequence} is not strictly monotonic (last recorded: ${lastSeq})`,
            requestId,
          },
        };
      }

      // Record tamper event
      await this.tamperRepo.recordTamperEvent(
        {
          eventId: payload.eventId,
          sensorId: registeredKey.sensorId,
          siteId: registeredKey.siteId,
          stationId: registeredKey.stationId,
          keyId: payload.keyId,
          eventType: payload.eventType,
          eventTimestamp: payload.eventTimestamp,
          tamperSource: payload.tamperSource,
          sequenceNo: payload.sequence,
          originalPayload: payload as unknown as Record<string, unknown>,
          signatureBase64: signature,
          payloadHash,
          signatureStatus: 'VALID',
          receivedAt: serverReceivedAt,
        },
        client
      );

      // Append primary audit event
      const auditResult = await this.auditRepo.appendStationEvent(
        {
          stationId: registeredKey.stationId,
          eventType: 'PHYSICAL_TAMPER',
          entityId: registeredKey.sensorCode,
          messageId: payload.eventId,
          payloadHash,
          eventPayload: {
            ...payload,
            payloadHash,
            signatureStatus: 'VALID',
          },
        },
        client
      );

      // Create CRITICAL alert immediately
      const isSimulated = payload.tamperSource === 'SIMULATED';
      const alert = await this.alertRepo.createAlert(
        {
          siteId: registeredKey.siteId,
          sensorId: registeredKey.sensorId,
          stationId: registeredKey.stationId,
          alertType: 'PHYSICAL_TAMPER',
          severity: 'CRITICAL',
          title: 'PHYSICAL TAMPERING DETECTED',
          description: `A verified tamper signal was received from ${payload.sensorId} at ${registeredKey.siteCode}.${isSimulated ? ' [SIMULATED PHYSICAL TAMPER EVENT]' : ''}`,
          sourceEventId: payload.eventId,
          detectionSource: payload.tamperSource,
          status: 'OPEN',
          recommendedAction:
            'Inspect the sensor enclosure and installation.\nSecure the affected equipment.\nPreserve the signed event and associated audit evidence.\nVerify sensor calibration and physical condition.\nEscalate to responsible site personnel and the competent environmental authority when required by applicable procedures.',
          deduplicationKey: `tamper:${payload.eventId}`,
          metadata: {
            simulated: isSimulated,
            eventType: payload.eventType,
            tamperSource: payload.tamperSource,
            sequence: payload.sequence,
            payloadHash,
            primaryAuditSequence: auditResult.eventSequence,
            chainHeadHash: auditResult.eventHash,
          },
        },
        client
      );

      await client.query('COMMIT');

      return {
        status: 201,
        body: {
          success: true,
          status: 'ACCEPTED',
          eventId: payload.eventId,
          alertId: alert.id,
          severity: 'CRITICAL',
          primaryAuditSequence: auditResult.eventSequence,
          chainHeadHash: auditResult.eventHash,
          receivedAt: serverReceivedAt.toISOString(),
          simulated: isSimulated,
        },
      };
    } catch (err) {
      await client.query('ROLLBACK');
      console.error('[INGESTION] Tamper DB error:', (err as Error).message);
      return {
        status: 500,
        body: {
          success: false,
          code: 'DATABASE_ERROR',
          message: 'Internal error processing tamper event ingestion',
          requestId,
        },
      };
    } finally {
      client.release();
    }
  }
}
