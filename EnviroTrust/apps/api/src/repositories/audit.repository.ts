import crypto from 'node:crypto';
import type { Pool, PoolClient } from 'pg';
import { canonicalizePayload } from '@envirotrust/crypto';

export interface AuditAppendParams {
  stationId: string; // UUID
  eventType:
    | 'TELEMETRY_INGESTION'
    | 'OPERATIONS_CONTEXT_INGESTION'
    | 'HEARTBEAT'
    | 'KEY_ROTATION'
    | 'SENSOR_STATE_TRANSITION'
    | 'SENSOR_RECOVERED'
    | 'ML_ASSESSMENT_EVALUATED'
    | 'PHYSICAL_TAMPER';
  entityId: string;
  messageId: string;
  payloadHash: string;
  eventPayload: Record<string, unknown>;
}

export interface AuditAppendResult {
  auditEventId: string;
  eventSequence: number;
  eventHash: string;
  previousHash: string;
}

const GENESIS_HASH = '0000000000000000000000000000000000000000000000000000000000000000';
const PRIMARY_CHAIN_DOMAIN = 'ENVIROTRUST-PRIMARY-V1\n';

export class AuditRepository {
  constructor(private readonly pool: Pool) {}

  getPool(): Pool {
    return this.pool;
  }

  /**
   * Appends an audit event to the station's hash chain transactionally.
   * Uses row-level lock on station_audit_cursors to prevent concurrent sequence races.
   */
  async appendStationEvent(
    params: AuditAppendParams,
    client: PoolClient
  ): Promise<AuditAppendResult> {
    const { stationId, eventType, entityId, messageId, payloadHash, eventPayload } = params;

    // 1. Lock station audit cursor row FOR UPDATE
    const cursorRes = await client.query<{
      last_event_sequence: string;
      chain_head_hash: string;
    }>(
      `SELECT last_event_sequence, chain_head_hash
       FROM station_audit_cursors
       WHERE station_id = $1
       FOR UPDATE`,
      [stationId]
    );

    let lastSeq = 0;
    let prevHash = GENESIS_HASH;

    if (cursorRes.rows.length === 0 || !cursorRes.rows[0]) {
      // Initialize if missing
      await client.query(
        `INSERT INTO station_audit_cursors (station_id, last_event_sequence, chain_head_hash)
         VALUES ($1, 0, $2)
         ON CONFLICT (station_id) DO NOTHING`,
        [stationId, GENESIS_HASH]
      );
    } else {
      lastSeq = Number(cursorRes.rows[0].last_event_sequence);
      prevHash = cursorRes.rows[0].chain_head_hash;
    }

    const newSeq = lastSeq + 1;

    // 2. Compute canonical audit data and SHA-256 hash
    const auditDataToHash = {
      stationId,
      eventSequence: newSeq,
      eventType,
      entityId,
      messageId,
      previousHash: prevHash,
      payloadHash,
    };

    const canonicalBytes = canonicalizePayload(auditDataToHash);
    const eventHash = crypto
      .createHash('sha256')
      .update(PRIMARY_CHAIN_DOMAIN + canonicalBytes)
      .digest('hex')
      .toLowerCase();

    // 3. Insert into audit_events
    const insertRes = await client.query<{ id: string }>(
      `INSERT INTO audit_events (
         station_id, event_sequence, event_type, entity_id, message_id, event_payload, previous_hash, event_hash
       )
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
       RETURNING id`,
      [
        stationId,
        newSeq,
        eventType,
        entityId,
        messageId,
        JSON.stringify(eventPayload),
        prevHash,
        eventHash,
      ]
    );

    const auditEventId = insertRes.rows[0]?.id || '';

    // 4. Update station_audit_cursors
    await client.query(
      `UPDATE station_audit_cursors
       SET last_event_sequence = $1, chain_head_hash = $2, updated_at = now()
       WHERE station_id = $3`,
      [newSeq, eventHash, stationId]
    );

    return {
      auditEventId,
      eventSequence: newSeq,
      eventHash,
      previousHash: prevHash,
    };
  }
}
