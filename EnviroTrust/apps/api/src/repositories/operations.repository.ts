import type { Pool, PoolClient } from 'pg';
import type { OpsContextPayload } from '@envirotrust/contracts';

export interface InsertOperationsContextParams {
  siteIdUuid: string;
  stationIdUuid: string;
  payload: OpsContextPayload;
  signatureBase64: string;
  payloadHash: string;
}

export type OperationsValidationResult =
  | { success: true; readingId: string; sequenceNo: number; verificationStatus: string; receivedAt: string; isDuplicate?: boolean }
  | { success: false; code: 'DUPLICATE_MESSAGE' | 'REPLAYED_SEQUENCE' | 'INVALID_INTERVAL'; message: string };

export class OperationsRepository {
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
    | { status: 'IDEMPOTENT_DUPLICATE'; readingId: string; sequenceNo: number; verificationStatus: string; receivedAt: string }
    | { status: 'CONFLICT' }
  > {
    const res = await client.query<{
      id: string;
      sequence_no: string;
      payload_hash: string;
      signature_base64: string;
      verification_status: string;
      received_at: Date;
    }>(
      `SELECT id, sequence_no, payload_hash, signature_base64, verification_status, received_at
       FROM operations_context_readings
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
        verificationStatus: row.verification_status,
        receivedAt: row.received_at.toISOString(),
      };
    }

    return { status: 'CONFLICT' };
  }

  async insertOperationsTransaction(
    params: InsertOperationsContextParams,
    client: PoolClient
  ): Promise<OperationsValidationResult> {
    const { siteIdUuid, stationIdUuid, payload, signatureBase64, payloadHash } = params;

    const startDate = new Date(payload.intervalStart);
    const endDate = new Date(payload.intervalEnd);
    if (startDate.getTime() >= endDate.getTime()) {
      return {
        success: false,
        code: 'INVALID_INTERVAL',
        message: 'intervalStart must be strictly earlier than intervalEnd',
      };
    }

    const incomingSeq = Number(payload.sequence);

    // 1. Lock operations sequence cursor FOR UPDATE
    const cursorRes = await client.query<{
      last_sequence_no: string;
      last_interval_end: Date;
    }>(
      `SELECT last_sequence_no, last_interval_end
       FROM operations_sequence_cursors
       WHERE source_id = $1
       FOR UPDATE`,
      [payload.sourceId]
    );

    if (cursorRes.rows.length > 0 && cursorRes.rows[0]) {
      const cursor = cursorRes.rows[0];
      const lastSeq = Number(cursor.last_sequence_no);
      if (incomingSeq <= lastSeq) {
        return {
          success: false,
          code: 'REPLAYED_SEQUENCE',
          message: `Replay detected: operations sequence ${incomingSeq} has already been seen (last sequence: ${lastSeq})`,
        };
      }
    }

    // 2. Insert into operations_context_readings
    const insertRes = await client.query<{ id: string; received_at: Date }>(
      `INSERT INTO operations_context_readings (
         message_id, source_id, key_id, site_id, station_id, sequence_no,
         interval_start, interval_end, production_rate, wastewater_flow,
         treatment_dose, energy_consumption, operating_mode,
         original_payload, signature_base64, payload_hash, verification_status
       )
       VALUES (
         $1, $2, $3, $4, $5, $6,
         $7, $8, $9, $10,
         $11, $12, $13,
         $14, $15, $16, 'VALID'
       )
       RETURNING id, received_at`,
      [
        payload.messageId,
        payload.sourceId,
        payload.keyId,
        siteIdUuid,
        stationIdUuid,
        incomingSeq,
        payload.intervalStart,
        payload.intervalEnd,
        payload.productionRate,
        payload.wastewaterFlow,
        payload.treatmentDose,
        payload.energyConsumption,
        payload.operatingMode,
        JSON.stringify(payload),
        signatureBase64,
        payloadHash,
      ]
    );

    const row = insertRes.rows[0];
    if (!row) {
      throw new Error('Failed to insert operations context reading');
    }

    // 3. Upsert operations sequence cursor
    await client.query(
      `INSERT INTO operations_sequence_cursors (source_id, last_sequence_no, last_interval_end, updated_at)
       VALUES ($1, $2, $3, now())
       ON CONFLICT (source_id) DO UPDATE SET
         last_sequence_no = EXCLUDED.last_sequence_no,
         last_interval_end = EXCLUDED.last_interval_end,
         updated_at = now()`,
      [payload.sourceId, incomingSeq, payload.intervalEnd]
    );

    return {
      success: true,
      readingId: row.id,
      sequenceNo: incomingSeq,
      verificationStatus: 'VALID',
      receivedAt: row.received_at.toISOString(),
    };
  }
}
