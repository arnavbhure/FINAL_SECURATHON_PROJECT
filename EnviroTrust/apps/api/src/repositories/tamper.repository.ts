import type { Pool, PoolClient } from 'pg';

export interface TamperEventRecord {
  eventId: string;
  sensorId: string;
  siteId: string;
  stationId: string;
  keyId: string;
  eventType: string;
  eventTimestamp: string;
  tamperSource: string;
  sequenceNo: number;
  originalPayload: Record<string, unknown>;
  signatureBase64: string;
  payloadHash: string;
  signatureStatus: 'VALID';
  receivedAt?: Date;
}

export interface TamperEventRow {
  [key: string]: any;
  id: string;
  event_id: string;
  sensor_id: string;
  site_id: string;
  station_id: string;
  key_id: string;
  event_type: string;
  event_timestamp: string;
  tamper_source: string;
  sequence_no: string;
  original_payload: Record<string, unknown>;
  signature_base64: string;
  payload_hash: string;
  signature_status: string;
  received_at: string;
  created_at: string;
}

export class TamperRepository {
  constructor(private readonly pool: Pool) {}

  /**
   * Check for duplicate or replayed tamper events.
   */
  async checkDuplicateEvent(
    eventId: string,
    signature: string,
    client?: PoolClient
  ): Promise<{ status: 'NEW' | 'IDEMPOTENT_DUPLICATE' | 'DUPLICATE_MISMATCH'; sequenceNo?: number }> {
    const q = 'SELECT event_id, sequence_no, signature_base64 FROM tamper_events WHERE event_id = $1';
    const res = client
      ? await client.query<{ event_id: string; sequence_no: string; signature_base64: string }>(q, [eventId])
      : await this.pool.query<{ event_id: string; sequence_no: string; signature_base64: string }>(q, [eventId]);

    if (!res.rowCount || res.rowCount === 0 || !res.rows[0]) {
      return { status: 'NEW' };
    }

    const row = res.rows[0];
    if (row.signature_base64 === signature) {
      return { status: 'IDEMPOTENT_DUPLICATE', sequenceNo: Number(row.sequence_no) };
    }

    return { status: 'DUPLICATE_MISMATCH', sequenceNo: Number(row.sequence_no) };
  }

  /**
   * Get maximum recorded tamper sequence for a sensor.
   */
  async getLastTamperSequence(sensorId: string, client?: PoolClient): Promise<number> {
    const q = 'SELECT COALESCE(MAX(sequence_no), 0) as max_seq FROM tamper_events WHERE sensor_id = $1';
    const res = client
      ? await client.query<{ max_seq: string }>(q, [sensorId])
      : await this.pool.query<{ max_seq: string }>(q, [sensorId]);
    return res.rows[0] ? Number(res.rows[0].max_seq) : 0;
  }

  /**
   * Persists a verified tamper event.
   */
  async recordTamperEvent(event: TamperEventRecord, client?: PoolClient): Promise<TamperEventRow> {
    const q = `
      INSERT INTO tamper_events (
        event_id,
        sensor_id,
        site_id,
        station_id,
        key_id,
        event_type,
        event_timestamp,
        tamper_source,
        sequence_no,
        original_payload,
        signature_base64,
        payload_hash,
        signature_status,
        received_at
      ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, COALESCE($14, now()))
      RETURNING *
    `;
    const params = [
      event.eventId,
      event.sensorId,
      event.siteId,
      event.stationId,
      event.keyId,
      event.eventType,
      event.eventTimestamp,
      event.tamperSource,
      event.sequenceNo,
      JSON.stringify(event.originalPayload),
      event.signatureBase64,
      event.payloadHash,
      event.signatureStatus,
      event.receivedAt || new Date(),
    ];

    const res = client
      ? await client.query<TamperEventRow>(q, params)
      : await this.pool.query<TamperEventRow>(q, params);
    const row = res.rows[0];
    if (!row) {
      throw new Error('Failed to insert tamper event record');
    }
    return row;
  }

  /**
   * Retrieves a tamper event by eventId.
   */
  async getTamperEventByEventId(eventId: string, client?: PoolClient): Promise<TamperEventRow | null> {
    const q = 'SELECT * FROM tamper_events WHERE event_id = $1';
    const res = client
      ? await client.query<TamperEventRow>(q, [eventId])
      : await this.pool.query<TamperEventRow>(q, [eventId]);
    return res.rows[0] || null;
  }
}
