import type { Pool, PoolClient } from 'pg';
import type { TelemetryPayload } from '@envirotrust/contracts';

export interface InsertTelemetryParams {
  sensorIdUuid: string;
  keyId: string;
  siteIdUuid: string;
  stationIdUuid: string;
  payload: TelemetryPayload;
  signatureBase64: string;
  payloadHash: string;
  protocolStatus: 'FRESH' | 'GAP_DETECTED' | 'DELAYED';
}

export type TelemetryValidationResult =
  | { success: true; readingId: string; sequenceNo: number; protocolStatus: string; receivedAt: string; isDuplicate?: boolean }
  | { success: false; code: 'DUPLICATE_MESSAGE' | 'REPLAYED_SEQUENCE' | 'OUT_OF_ORDER'; message: string };

export class TelemetryRepository {
  constructor(private readonly pool: Pool) {}

  getPool(): Pool {
    return this.pool;
  }

  async checkDuplicateMessage(
    messageId: string,
    payloadHash: string,
    signatureBase64: string,
    client: PoolClient
  ): Promise<
    | { status: 'NONE' }
    | { status: 'IDEMPOTENT_DUPLICATE'; readingId: string; sequenceNo: number; protocolStatus: string; receivedAt: string }
    | { status: 'CONFLICT' }
  > {
    const res = await client.query<{
      id: string;
      sequence_no: string;
      payload_hash: string;
      signature_base64: string;
      protocol_status: string;
      received_at: Date;
    }>(
      `SELECT id, sequence_no, payload_hash, signature_base64, protocol_status, received_at
       FROM telemetry_readings
       WHERE message_id = $1`,
      [messageId]
    );

    if (res.rows.length === 0 || !res.rows[0]) {
      return { status: 'NONE' };
    }

    const row = res.rows[0];
    if (row.payload_hash === payloadHash && row.signature_base64 === signatureBase64) {
      return {
        status: 'IDEMPOTENT_DUPLICATE',
        readingId: row.id,
        sequenceNo: Number(row.sequence_no),
        protocolStatus: row.protocol_status,
        receivedAt: row.received_at.toISOString(),
      };
    }

    return { status: 'CONFLICT' };
  }

  async insertTelemetryTransaction(
    params: InsertTelemetryParams,
    client: PoolClient
  ): Promise<TelemetryValidationResult> {
    const {
      sensorIdUuid,
      keyId,
      siteIdUuid,
      stationIdUuid,
      payload,
      signatureBase64,
      payloadHash,
    } = params;

    let effectiveProtocolStatus = params.protocolStatus;

    // 1. Lock sensor sequence cursor FOR UPDATE
    const cursorRes = await client.query<{
      boot_id: string;
      last_sequence_no: string;
      last_measured_at: Date;
    }>(
      `SELECT boot_id, last_sequence_no, last_measured_at
       FROM sensor_sequence_cursors
       WHERE sensor_id = $1
       FOR UPDATE`,
      [sensorIdUuid]
    );

    const incomingSeq = Number(payload.sequence);

    if (cursorRes.rows.length > 0 && cursorRes.rows[0]) {
      const cursor = cursorRes.rows[0];
      const lastSeq = Number(cursor.last_sequence_no);

      if (cursor.boot_id === payload.bootId) {
        if (incomingSeq <= lastSeq) {
          return {
            success: false,
            code: 'REPLAYED_SEQUENCE',
            message: `Replay detected: sequence ${incomingSeq} has already been seen (last sequence: ${lastSeq})`,
          };
        }
        if (params.protocolStatus === 'DELAYED') {
          effectiveProtocolStatus = 'DELAYED';
        } else if (incomingSeq > lastSeq + 1) {
          // Detected sequence gap
          effectiveProtocolStatus = 'GAP_DETECTED';
        }
      } else {
        // New boot session detected for this sensor
        // Sequence should start at >= 1
        if (incomingSeq < 1) {
          return {
            success: false,
            code: 'OUT_OF_ORDER',
            message: `Invalid sequence ${incomingSeq} for new boot session`,
          };
        }
      }
    }

    // 2. Insert into telemetry_readings
    const insertRes = await client.query<{ id: string; received_at: Date }>(
      `INSERT INTO telemetry_readings (
         message_id, sensor_id, key_id, site_id, station_id, boot_id,
         sequence_no, parameter, value_numeric, value_wire, unit,
         measured_at, original_payload, signature_base64, payload_hash,
         signature_status, protocol_status, calibration_status, witness_status
       )
       VALUES (
         $1, $2, $3, $4, $5, $6,
         $7, $8, $9, $10, $11,
         $12, $13, $14, $15,
         'VALID', $16, 'UNKNOWN', 'PENDING'
       )
       RETURNING id, received_at`,
      [
        payload.messageId,
        sensorIdUuid,
        keyId,
        siteIdUuid,
        stationIdUuid,
        payload.bootId,
        incomingSeq,
        payload.parameter,
        payload.value, // numeric
        payload.value, // wire string
        payload.unit,
        payload.measuredAt,
        JSON.stringify(payload),
        signatureBase64,
        payloadHash,
        effectiveProtocolStatus,
      ]
    );

    const row = insertRes.rows[0];
    if (!row) {
      throw new Error('Failed to insert telemetry reading');
    }

    // 3. Upsert sensor sequence cursor
    await client.query(
      `INSERT INTO sensor_sequence_cursors (sensor_id, boot_id, last_sequence_no, last_measured_at, updated_at)
       VALUES ($1, $2, $3, $4, now())
       ON CONFLICT (sensor_id) DO UPDATE SET
         boot_id = EXCLUDED.boot_id,
         last_sequence_no = EXCLUDED.last_sequence_no,
         last_measured_at = EXCLUDED.last_measured_at,
         updated_at = now()`,
      [sensorIdUuid, payload.bootId, incomingSeq, payload.measuredAt]
    );

    return {
      success: true,
      readingId: row.id,
      sequenceNo: incomingSeq,
      protocolStatus: effectiveProtocolStatus,
      receivedAt: row.received_at.toISOString(),
    };
  }
}
