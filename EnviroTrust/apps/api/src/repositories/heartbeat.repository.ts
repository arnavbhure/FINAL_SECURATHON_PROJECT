import type { Pool, PoolClient } from 'pg';
import type { HeartbeatPayload } from '@envirotrust/contracts';
import { AVAILABILITY_CONSTANTS } from '../constants/availability.constants.js';

export interface HeartbeatInsertParams {
  sensorIdUuid: string;
  keyId: string;
  stationIdUuid: string;
  payload: HeartbeatPayload;
  signatureBase64: string;
  payloadHash: string;
  serverReceivedAt: Date;
}

export interface HeartbeatInsertResult {
  heartbeatId: string;
  sequenceNo: number;
  serverReceivedAt: string;
  isSequenceGap: boolean;
  recoveredFromOffline: boolean;
  previousStatus?: string;
}

export interface DuplicateHeartbeatCheckResult {
  status: 'IDEMPOTENT_DUPLICATE' | 'CONFLICT' | 'NOT_FOUND';
  heartbeatId?: string;
  sequenceNo?: number;
  receivedAt?: string;
}

export interface HeartbeatRecord {
  id: string;
  messageId: string;
  sensorId: string;
  sensorCode: string;
  keyId: string;
  bootId: string;
  heartbeatSequence: number;
  sentAt: string;
  receivedAt: string;
  signatureBase64: string;
  verificationStatus: string;
}

export class HeartbeatRepository {
  constructor(private readonly pool: Pool) {}

  /**
   * Checks whether a messageId has already been ingested.
   */
  async checkDuplicateMessage(
    messageId: string,
    signature: string,
    client?: PoolClient
  ): Promise<DuplicateHeartbeatCheckResult> {
    const q = client || this.pool;
    const res = await q.query<{
      id: string;
      heartbeat_sequence: string;
      received_at: Date;
      signature_base64: string;
    }>(
      `SELECT id, heartbeat_sequence, received_at, signature_base64
       FROM heartbeats
       WHERE message_id = $1`,
      [messageId]
    );

    if (res.rows.length === 0 || !res.rows[0]) {
      return { status: 'NOT_FOUND' };
    }

    const row = res.rows[0];
    if (row.signature_base64 === signature) {
      return {
        status: 'IDEMPOTENT_DUPLICATE',
        heartbeatId: row.id,
        sequenceNo: Number(row.heartbeat_sequence),
        receivedAt: row.received_at.toISOString(),
      };
    }

    return { status: 'CONFLICT' };
  }

  /**
   * Locks and retrieves the heartbeat sequence cursor for a sensor.
   */
  async getHeartbeatCursorForUpdate(
    sensorId: string,
    client: PoolClient
  ): Promise<{
    bootId: string;
    lastSequenceNo: number;
    lastSentAt: Date;
    lastReceivedAt: Date;
  } | null> {
    const res = await client.query<{
      boot_id: string;
      last_heartbeat_sequence: string;
      last_sent_at: Date;
      last_received_at: Date;
    }>(
      `SELECT boot_id, last_heartbeat_sequence, last_sent_at, last_received_at
       FROM sensor_heartbeat_cursors
       WHERE sensor_id = $1
       FOR UPDATE`,
      [sensorId]
    );

    if (res.rows.length === 0 || !res.rows[0]) {
      return null;
    }

    const row = res.rows[0];
    return {
      bootId: row.boot_id,
      lastSequenceNo: Number(row.last_heartbeat_sequence),
      lastSentAt: row.last_sent_at,
      lastReceivedAt: row.last_received_at,
    };
  }

  /**
   * Inserts a verified heartbeat and updates the heartbeat sequence cursor.
   */
  async insertHeartbeatTransaction(
    params: HeartbeatInsertParams,
    client: PoolClient
  ): Promise<HeartbeatInsertResult> {
    const { sensorIdUuid, keyId, payload, signatureBase64, serverReceivedAt } = params;

    // 1. Lock and inspect heartbeat cursor
    const cursor = await this.getHeartbeatCursorForUpdate(sensorIdUuid, client);
    let isSequenceGap = false;
    let recoveredFromOffline = false;
    let previousStatus = cursor ? 'ONLINE' : 'OFFLINE';

    if (cursor) {
      const elapsedSinceReceived = (serverReceivedAt.getTime() - cursor.lastReceivedAt.getTime()) / 1000;
      const elapsedSinceSent = (serverReceivedAt.getTime() - cursor.lastSentAt.getTime()) / 1000;
      if (elapsedSinceReceived > 30 || elapsedSinceSent > 30) {
        previousStatus = 'OFFLINE';
      } else if (elapsedSinceReceived > 20 || elapsedSinceSent > 20) {
        previousStatus = 'STALE';
      } else {
        previousStatus = 'ONLINE';
      }

      if (cursor.bootId === payload.bootId) {
        if (payload.heartbeatSequence <= cursor.lastSequenceNo) {
          const err = new Error(`Replayed heartbeat sequence: ${payload.heartbeatSequence} <= ${cursor.lastSequenceNo}`);
          (err as any).code = 'REPLAYED_SEQUENCE';
          throw err;
        }
        if (payload.heartbeatSequence > cursor.lastSequenceNo + 1) {
          isSequenceGap = true;
        }
      }
    }

    // 2. Insert into heartbeats
    const insertRes = await client.query<{ id: string }>(
      `INSERT INTO heartbeats (
         message_id, sensor_id, key_id, boot_id, heartbeat_sequence, sent_at, received_at, signature_base64, verification_status
       )
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, 'VALID')
       RETURNING id`,
      [
        payload.messageId,
        sensorIdUuid,
        keyId,
        payload.bootId,
        payload.heartbeatSequence,
        payload.sentAt,
        serverReceivedAt.toISOString(),
        signatureBase64,
      ]
    );

    const heartbeatId = insertRes.rows[0]?.id;
    if (!heartbeatId) {
      throw new Error('Failed to retrieve inserted heartbeat ID');
    }

    // 3. Evaluate transit delay and state recovery using configured constants
    const transitDelay = Math.max(0, (serverReceivedAt.getTime() - new Date(payload.sentAt).getTime()) / 1000);
    const isIncomingFresh = transitDelay <= AVAILABILITY_CONSTANTS.MAX_HEARTBEAT_AGE_SECONDS;

    if (isIncomingFresh && (previousStatus === 'OFFLINE' || previousStatus === 'STALE')) {
      recoveredFromOffline = true;
      // Persist durable state transition to database
      await client.query(
        `INSERT INTO sensor_state_transitions (
           sensor_id, from_status, to_status, reason, heartbeat_id, occurred_at, metadata
         )
         VALUES ($1, $2, $3, $4, $5, $6, $7)`,
        [
          sensorIdUuid,
          previousStatus,
          'ONLINE',
          'SENSOR_RECOVERED',
          heartbeatId,
          serverReceivedAt.toISOString(),
          JSON.stringify({
            messageId: payload.messageId,
            transitDelaySeconds: Math.round(transitDelay),
            heartbeatSequence: payload.heartbeatSequence,
            bootId: payload.bootId,
          }),
        ]
      );
    }

    // 4. Update sequence cursor:
    // A delayed heartbeat must NOT update the current liveness cursor timestamps!
    // Using GREATEST ensures that an older outbox heartbeat can NEVER push timestamps or sequences backwards.
    if (isIncomingFresh) {
      await client.query(
        `INSERT INTO sensor_heartbeat_cursors (
           sensor_id, boot_id, last_heartbeat_sequence, last_sent_at, last_received_at, updated_at
         )
         VALUES ($1, $2, $3, $4, $5, now())
         ON CONFLICT (sensor_id)
         DO UPDATE SET
           boot_id = EXCLUDED.boot_id,
           last_heartbeat_sequence = CASE
             WHEN sensor_heartbeat_cursors.boot_id = EXCLUDED.boot_id
             THEN GREATEST(sensor_heartbeat_cursors.last_heartbeat_sequence, EXCLUDED.last_heartbeat_sequence)
             ELSE EXCLUDED.last_heartbeat_sequence
           END,
           last_sent_at = CASE
             WHEN sensor_heartbeat_cursors.boot_id = EXCLUDED.boot_id
             THEN GREATEST(sensor_heartbeat_cursors.last_sent_at, EXCLUDED.last_sent_at)
             ELSE EXCLUDED.last_sent_at
           END,
           last_received_at = CASE
             WHEN sensor_heartbeat_cursors.boot_id = EXCLUDED.boot_id
             THEN GREATEST(sensor_heartbeat_cursors.last_received_at, EXCLUDED.last_received_at)
             ELSE EXCLUDED.last_received_at
           END,
           updated_at = now()`,
        [
          sensorIdUuid,
          payload.bootId,
          payload.heartbeatSequence,
          payload.sentAt,
          serverReceivedAt.toISOString(),
        ]
      );
    } else {
      // Ineligible delayed heartbeat: advances sequence to prevent replays,
      // but strictly PRESERVES existing liveness timestamps (does not make sensor appear online)
      await client.query(
        `INSERT INTO sensor_heartbeat_cursors (
           sensor_id, boot_id, last_heartbeat_sequence, last_sent_at, last_received_at, updated_at
         )
         VALUES ($1, $2, $3, $4, $5, now())
         ON CONFLICT (sensor_id)
         DO UPDATE SET
           boot_id = EXCLUDED.boot_id,
           last_heartbeat_sequence = CASE
             WHEN sensor_heartbeat_cursors.boot_id = EXCLUDED.boot_id
             THEN GREATEST(sensor_heartbeat_cursors.last_heartbeat_sequence, EXCLUDED.last_heartbeat_sequence)
             ELSE EXCLUDED.last_heartbeat_sequence
           END,
           updated_at = now()`,
        [
          sensorIdUuid,
          payload.bootId,
          payload.heartbeatSequence,
          payload.sentAt,
          serverReceivedAt.toISOString(),
        ]
      );
    }

    return {
      heartbeatId,
      sequenceNo: payload.heartbeatSequence,
      serverReceivedAt: serverReceivedAt.toISOString(),
      isSequenceGap,
      recoveredFromOffline,
      previousStatus,
    };
  }

  /**
   * Retrieves the most recent heartbeat for a specific sensor.
   */
  async getLatestHeartbeat(sensorCode: string): Promise<HeartbeatRecord | null> {
    const res = await this.pool.query<{
      id: string;
      message_id: string;
      sensor_id: string;
      sensor_code: string;
      key_id: string;
      boot_id: string;
      heartbeat_sequence: string;
      sent_at: Date;
      received_at: Date;
      signature_base64: string;
      verification_status: string;
    }>(
      `SELECT h.id, h.message_id, h.sensor_id, s.sensor_code, h.key_id, h.boot_id,
              h.heartbeat_sequence, h.sent_at, h.received_at, h.signature_base64, h.verification_status
       FROM heartbeats h
       JOIN sensors s ON s.id = h.sensor_id
       WHERE (s.sensor_code = $1 OR s.id::text = $1)
       ORDER BY h.received_at DESC
       LIMIT 1`,
      [sensorCode]
    );

    if (res.rows.length === 0 || !res.rows[0]) return null;
    const r = res.rows[0];
    return {
      id: r.id,
      messageId: r.message_id,
      sensorId: r.sensor_id,
      sensorCode: r.sensor_code,
      keyId: r.key_id,
      bootId: r.boot_id,
      heartbeatSequence: Number(r.heartbeat_sequence),
      sentAt: r.sent_at.toISOString(),
      receivedAt: r.received_at.toISOString(),
      signatureBase64: r.signature_base64,
      verificationStatus: r.verification_status,
    };
  }

  /**
   * Retrieves heartbeat history for a sensor.
   */
  async getHeartbeatHistory(sensorCode: string, limit = 50): Promise<HeartbeatRecord[]> {
    const res = await this.pool.query<{
      id: string;
      message_id: string;
      sensor_id: string;
      sensor_code: string;
      key_id: string;
      boot_id: string;
      heartbeat_sequence: string;
      sent_at: Date;
      received_at: Date;
      signature_base64: string;
      verification_status: string;
    }>(
      `SELECT h.id, h.message_id, h.sensor_id, s.sensor_code, h.key_id, h.boot_id,
              h.heartbeat_sequence, h.sent_at, h.received_at, h.signature_base64, h.verification_status
       FROM heartbeats h
       JOIN sensors s ON s.id = h.sensor_id
       WHERE (s.sensor_code = $1 OR s.id::text = $1)
       ORDER BY h.received_at DESC
       LIMIT $2`,
      [sensorCode, limit]
    );

    return res.rows.map((r: any) => ({
      id: r.id,
      messageId: r.message_id,
      sensorId: r.sensor_id,
      sensorCode: r.sensor_code,
      keyId: r.key_id,
      bootId: r.boot_id,
      heartbeatSequence: Number(r.heartbeat_sequence),
      sentAt: r.sent_at.toISOString(),
      receivedAt: r.received_at.toISOString(),
      signatureBase64: r.signature_base64,
      verificationStatus: r.verification_status,
    }));
  }
}
