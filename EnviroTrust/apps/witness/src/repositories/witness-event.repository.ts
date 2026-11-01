import crypto from 'node:crypto';
import type { Pool, PoolClient } from 'pg';
import { canonicalizePayload } from '@envirotrust/crypto';
import type { CheckpointService, CreatedCheckpoint } from '../services/checkpoint.service.js';

export const WITNESS_GENESIS_HASH = '0000000000000000000000000000000000000000000000000000000000000000';
export const WITNESS_CHAIN_DOMAIN = 'ENVIROTRUST-WITNESS-V1\n';

export interface WitnessEventDataWithoutHash {
    schemaVersion: 1;
    stationCode: string;
    siteCode: string;
    witnessSequence: number;
    eventType: 'TELEMETRY' | 'OPERATIONS_CONTEXT' | 'HEARTBEAT' | 'PHYSICAL_TAMPER';
    identityType: 'SENSOR' | 'OPERATIONS_SOURCE';
    identityCode: string;
    keyId: string;
    bootId: string | null;
    sourceSequence: number;
    sourceTimestamp: string;
    messageId: string;
    payloadHash: string;
    signatureHash: string;
    witnessReceivedAt: string;
    previousHash: string;
}

/**
 * Pure function computing the witness event hash using the specified domain separator,
 * previous hash bytes, and RFC 8785 canonical JSON of the event metadata.
 */
export function computeWitnessEventHash(prevHashHex: string, eventDataWithoutHash: WitnessEventDataWithoutHash): string {
    const canonicalString = canonicalizePayload(eventDataWithoutHash);
    const domainBytes = Buffer.from(WITNESS_CHAIN_DOMAIN, 'utf-8');
    const prevHashBytes = Buffer.from(prevHashHex, 'hex');
    const canonicalBytes = Buffer.from(canonicalString, 'utf-8');

    return crypto
        .createHash('sha256')
        .update(Buffer.concat([domainBytes, prevHashBytes, canonicalBytes]))
        .digest('hex')
        .toLowerCase();
}

export interface AppendWitnessEventParams {
    eventType: 'TELEMETRY' | 'OPERATIONS_CONTEXT' | 'HEARTBEAT' | 'PHYSICAL_TAMPER';
    messageId: string;
    siteCode: string;
    stationCode: string;
    identityType: 'SENSOR' | 'OPERATIONS_SOURCE';
    identityCode: string;
    keyId: string;
    bootId?: string | null;
    sourceSequence: number;
    sourceTimestamp: Date;
    payload: Record<string, unknown>;
    signatureBase64: string;
    payloadHash: string;
    signatureHash: string;
    checkpointService: CheckpointService;
    checkpointInterval?: number;
    /**
     * When true, rejects a new message that reuses an already witnessed
     * (identity, bootId, sourceSequence) tuple for the same event type.
     * Checked under the station cursor lock so concurrent appends cannot both pass.
     */
    enforceSourceSequenceUniqueness?: boolean;
}

/**
 * Raised when a new message reuses a source sequence the witness has already recorded
 * for the same identity and boot session (sequence rollback / replay with a new messageId).
 */
export class WitnessSequenceReplayError extends Error {
    readonly code = 'REPLAYED_SEQUENCE';

    constructor(
        public readonly existingMessageId: string,
        public readonly sourceSequence: number
    ) {
        super(`Source sequence ${sourceSequence} was already witnessed for this identity and boot session`);
        this.name = 'WitnessSequenceReplayError';
    }
}

export interface AppendWitnessEventResult {
    eventId: string;
    witnessSequence: number;
    eventHash: string;
    previousHash: string;
    witnessReceivedAt: Date;
    checkpointCreated?: CreatedCheckpoint | null;
}

export interface WitnessEventRecord {
    id: string;
    witnessSequence: number;
    eventType: 'TELEMETRY' | 'OPERATIONS_CONTEXT' | 'HEARTBEAT';
    messageId: string;
    siteCode: string;
    stationCode: string;
    identityType: 'SENSOR' | 'OPERATIONS_SOURCE';
    identityCode: string;
    keyId: string;
    bootId: string | null;
    sourceSequence: number;
    sourceTimestamp: Date;
    payload: Record<string, unknown>;
    signatureBase64: string;
    payloadHash: string;
    signatureHash: string;
    witnessReceivedAt: Date;
    previousHash: string;
    eventHash: string;
}

export interface WitnessCheckpointRecord {
    id: string;
    witnessId: string;
    witnessKeyId: string;
    siteCode: string;
    stationCode: string;
    checkpointSequence: number;
    lastWitnessSequence: number;
    chainHeadHash: string;
    previousCheckpointHash: string;
    createdAt: Date;
    canonicalPayload: string;
    signatureBase64: string;
    checkpointHash: string;
    witnessPublicKeyFingerprint: string;
}

export class WitnessEventRepository {
    constructor(private readonly pool: Pool) { }

    getPool(): Pool {
        return this.pool;
    }

    /**
     * Checks if a messageId already exists in witness_events.
     */
    async checkDuplicateMessage(messageId: string, client?: PoolClient): Promise<{
        exists: boolean;
        eventId?: string;
        payloadHash?: string;
        signatureHash?: string;
        signatureBase64?: string;
        witnessSequence?: number;
        eventHash?: string;
        witnessReceivedAt?: Date;
    }> {
        const q = client || this.pool;
        const res = await q.query<{
            id: string;
            payload_hash: string;
            signature_hash: string;
            signature_base64: string;
            witness_sequence: string;
            event_hash: string;
            witness_received_at: Date;
        }>(
            `SELECT id, payload_hash, signature_hash, signature_base64, witness_sequence, event_hash, witness_received_at
       FROM witness_events
       WHERE message_id = $1`,
            [messageId]
        );

        if (res.rows.length === 0 || !res.rows[0]) {
            return { exists: false };
        }

        const row = res.rows[0];
        return {
            exists: true,
            eventId: row.id,
            payloadHash: row.payload_hash,
            signatureHash: row.signature_hash,
            signatureBase64: row.signature_base64,
            witnessSequence: Number(row.witness_sequence),
            eventHash: row.event_hash,
            witnessReceivedAt: row.witness_received_at,
        };
    }

    /**
     * Transactionally appends an event to the station's witness hash chain.
     * Uses SELECT ... FOR UPDATE on witness_chain_cursors to prevent sequence forks.
     */
    async appendWitnessEventTransaction(
        params: AppendWitnessEventParams,
        existingClient?: PoolClient
    ): Promise<AppendWitnessEventResult> {
        const shouldManageClient = !existingClient;
        const client = existingClient || (await this.pool.connect());
        const checkpointInterval = params.checkpointInterval || 10;

        try {
            if (shouldManageClient) {
                await client.query('BEGIN');
            }

            // 1. Lock station chain cursor row FOR UPDATE
            let cursorRes = await client.query<{
                last_witness_sequence: string;
                chain_head_hash: string;
                last_checkpoint_sequence: string;
                last_checkpoint_hash: string | null;
            }>(
                `SELECT last_witness_sequence, chain_head_hash, last_checkpoint_sequence, last_checkpoint_hash
         FROM witness_chain_cursors
         WHERE station_code = $1
         FOR UPDATE`,
                [params.stationCode]
            );

            let lastSeq = 0;
            let prevHash = WITNESS_GENESIS_HASH;
            let lastCheckpointSeq = 0;
            let lastCheckpointHash = WITNESS_GENESIS_HASH;

            if (cursorRes.rows.length === 0 || !cursorRes.rows[0]) {
                // Initialize cursor for this station
                await client.query(
                    `INSERT INTO witness_chain_cursors (station_code, last_witness_sequence, chain_head_hash, last_checkpoint_sequence, last_checkpoint_hash)
           VALUES ($1, 0, $2, 0, $3)
           ON CONFLICT (station_code) DO NOTHING`,
                    [params.stationCode, WITNESS_GENESIS_HASH, WITNESS_GENESIS_HASH]
                );

                cursorRes = await client.query(
                    `SELECT last_witness_sequence, chain_head_hash, last_checkpoint_sequence, last_checkpoint_hash
           FROM witness_chain_cursors
           WHERE station_code = $1
           FOR UPDATE`,
                    [params.stationCode]
                );
            }

            if (cursorRes.rows.length > 0 && cursorRes.rows[0]) {
                lastSeq = Number(cursorRes.rows[0].last_witness_sequence);
                prevHash = cursorRes.rows[0].chain_head_hash;
                lastCheckpointSeq = Number(cursorRes.rows[0].last_checkpoint_sequence);
                lastCheckpointHash = cursorRes.rows[0].last_checkpoint_hash || WITNESS_GENESIS_HASH;
            }

            if (params.enforceSourceSequenceUniqueness) {
                const seqRes = await client.query<{ message_id: string }>(
                    `SELECT message_id
           FROM witness_events
           WHERE event_type = $1
             AND identity_code = $2
             AND boot_id IS NOT DISTINCT FROM $3
             AND source_sequence = $4
           LIMIT 1`,
                    [params.eventType, params.identityCode, params.bootId ?? null, params.sourceSequence]
                );
                const existing = seqRes.rows[0];
                if (existing) {
                    throw new WitnessSequenceReplayError(existing.message_id, params.sourceSequence);
                }
            }

            const newSeq = lastSeq + 1;
            const witnessReceivedAt = new Date();

            // 2. Prepare canonical event object and compute SHA-256 hash
            const eventDataWithoutHash: WitnessEventDataWithoutHash = {
                schemaVersion: 1,
                stationCode: params.stationCode,
                siteCode: params.siteCode,
                witnessSequence: newSeq,
                eventType: params.eventType,
                identityType: params.identityType,
                identityCode: params.identityCode,
                keyId: params.keyId,
                bootId: params.bootId ?? null,
                sourceSequence: params.sourceSequence,
                sourceTimestamp: params.sourceTimestamp.toISOString(),
                messageId: params.messageId,
                payloadHash: params.payloadHash,
                signatureHash: params.signatureHash,
                witnessReceivedAt: witnessReceivedAt.toISOString(),
                previousHash: prevHash,
            };

            const eventHash = computeWitnessEventHash(prevHash, eventDataWithoutHash);

            // 3. Insert into witness_events
            const insertRes = await client.query<{ id: string }>(
                `INSERT INTO witness_events (
           witness_sequence, event_type, message_id, site_code, station_code,
           identity_type, identity_code, key_id, boot_id, source_sequence,
           source_timestamp, payload, signature_base64, payload_hash, signature_hash,
           witness_received_at, previous_hash, event_hash
         )
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18)
         RETURNING id`,
                [
                    newSeq,
                    params.eventType,
                    params.messageId,
                    params.siteCode,
                    params.stationCode,
                    params.identityType,
                    params.identityCode,
                    params.keyId,
                    params.bootId ?? null,
                    params.sourceSequence,
                    params.sourceTimestamp.toISOString(),
                    JSON.stringify(params.payload),
                    params.signatureBase64,
                    params.payloadHash,
                    params.signatureHash,
                    witnessReceivedAt.toISOString(),
                    prevHash,
                    eventHash,
                ]
            );

            const eventId = insertRes.rows[0]?.id;
            if (!eventId) {
                throw new Error('Failed to retrieve inserted witness event ID');
            }

            let checkpointCreated: CreatedCheckpoint | null = null;

            // 4. Check if a periodic checkpoint should be triggered
            if (newSeq % checkpointInterval === 0) {
                const nextCheckpointSeq = lastCheckpointSeq + 1;
                checkpointCreated = params.checkpointService.createSignedCheckpoint({
                    siteId: params.siteCode,
                    stationId: params.stationCode,
                    checkpointSequence: nextCheckpointSeq,
                    lastWitnessSequence: newSeq,
                    chainHeadHash: eventHash,
                    previousCheckpointHash: lastCheckpointHash,
                });

                // Insert checkpoint
                await client.query(
                    `INSERT INTO witness_checkpoints (
             id, witness_id, witness_key_id, site_code, station_code, checkpoint_sequence,
             last_witness_sequence, chain_head_hash, previous_checkpoint_hash, created_at,
             canonical_payload, signature_base64, checkpoint_hash, witness_public_key_fingerprint
           )
           VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14)`,
                    [
                        checkpointCreated.payload.checkpointId,
                        checkpointCreated.payload.witnessId,
                        checkpointCreated.payload.witnessKeyId,
                        checkpointCreated.payload.siteId,
                        checkpointCreated.payload.stationId,
                        checkpointCreated.payload.checkpointSequence,
                        checkpointCreated.payload.lastWitnessSequence,
                        checkpointCreated.payload.chainHeadHash,
                        checkpointCreated.payload.previousCheckpointHash,
                        checkpointCreated.payload.createdAt,
                        checkpointCreated.canonicalPayload,
                        checkpointCreated.signature,
                        checkpointCreated.checkpointHash,
                        checkpointCreated.witnessPublicKeyFingerprint,
                    ]
                );

                // Update cursor with checkpoint info
                await client.query(
                    `UPDATE witness_chain_cursors
           SET last_witness_sequence = $1, chain_head_hash = $2, last_checkpoint_sequence = $3, last_checkpoint_hash = $4, updated_at = now()
           WHERE station_code = $5`,
                    [newSeq, eventHash, nextCheckpointSeq, checkpointCreated.checkpointHash, params.stationCode]
                );
            } else {
                // Update cursor without checkpoint
                await client.query(
                    `UPDATE witness_chain_cursors
           SET last_witness_sequence = $1, chain_head_hash = $2, updated_at = now()
           WHERE station_code = $3`,
                    [newSeq, eventHash, params.stationCode]
                );
            }

            if (shouldManageClient) {
                await client.query('COMMIT');
            }

            return {
                eventId,
                witnessSequence: newSeq,
                eventHash,
                previousHash: prevHash,
                witnessReceivedAt,
                checkpointCreated,
            };
        } catch (err) {
            if (shouldManageClient) {
                await client.query('ROLLBACK');
            }
            throw err;
        } finally {
            if (shouldManageClient) {
                client.release();
            }
        }
    }

    /**
     * Checks and updates the operations cursor for replay protection.
     */
    async checkAndUpdateOperationsCursor(
        sourceId: string,
        sequence: number,
        intervalEnd: Date,
        client: PoolClient
    ): Promise<{ valid: boolean; reason?: string }> {
        const cursorRes = await client.query<{
            last_sequence: string;
            last_interval_end: Date;
        }>(
            `SELECT last_sequence, last_interval_end
       FROM witness_operations_cursors
       WHERE source_id = $1
       FOR UPDATE`,
            [sourceId]
        );

        if (cursorRes.rows.length > 0 && cursorRes.rows[0]) {
            const lastSeq = Number(cursorRes.rows[0].last_sequence);
            if (sequence <= lastSeq) {
                return {
                    valid: false,
                    reason: `Replayed operations sequence: ${sequence} <= ${lastSeq}`,
                };
            }
        }

        await client.query(
            `INSERT INTO witness_operations_cursors (source_id, last_sequence, last_interval_end, updated_at)
       VALUES ($1, $2, $3, now())
       ON CONFLICT (source_id)
       DO UPDATE SET
         last_sequence = EXCLUDED.last_sequence,
         last_interval_end = EXCLUDED.last_interval_end,
         updated_at = now()`,
            [sourceId, sequence, intervalEnd.toISOString()]
        );

        return { valid: true };
    }

    /**
     * Checks and updates the witness heartbeat cursor for replay protection.
     */
    async checkAndUpdateHeartbeatCursor(
        sensorCode: string,
        bootId: string,
        heartbeatSequence: number,
        sentAt: Date,
        receivedAt: Date,
        client: PoolClient
    ): Promise<{ valid: boolean; reason?: string }> {
        const cursorRes = await client.query<{
            boot_id: string;
            last_heartbeat_sequence: string;
        }>(
            `SELECT boot_id, last_heartbeat_sequence
       FROM witness_heartbeat_cursors
       WHERE sensor_code = $1
       FOR UPDATE`,
            [sensorCode]
        );

        if (cursorRes.rows.length > 0 && cursorRes.rows[0]) {
            const cursor = cursorRes.rows[0];
            if (cursor.boot_id === bootId) {
                const lastSeq = Number(cursor.last_heartbeat_sequence);
                if (heartbeatSequence <= lastSeq) {
                    return {
                        valid: false,
                        reason: `Replayed heartbeat sequence: ${heartbeatSequence} <= ${lastSeq}`,
                    };
                }
            }
        }

        await client.query(
            `INSERT INTO witness_heartbeat_cursors (sensor_code, boot_id, last_heartbeat_sequence, last_sent_at, last_received_at, updated_at)
       VALUES ($1, $2, $3, $4, $5, now())
       ON CONFLICT (sensor_code)
       DO UPDATE SET
         boot_id = EXCLUDED.boot_id,
         last_heartbeat_sequence = EXCLUDED.last_heartbeat_sequence,
         last_sent_at = EXCLUDED.last_sent_at,
         last_received_at = EXCLUDED.last_received_at,
         updated_at = now()`,
            [sensorCode, bootId, heartbeatSequence, sentAt.toISOString(), receivedAt.toISOString()]
        );

        return { valid: true };
    }

    /**
     * Inserts a record into witness_heartbeats table.
     */
    async insertHeartbeatRecord(
        params: {
            messageId: string;
            sensorCode: string;
            siteCode: string;
            stationCode: string;
            keyId: string;
            bootId: string;
            heartbeatSequence: number;
            sentAt: Date;
            receivedAt: Date;
            payload: Record<string, unknown>;
            signatureBase64: string;
            payloadHash: string;
            signatureHash: string;
        },
        client: PoolClient
    ): Promise<{ id: string }> {
        const res = await client.query<{ id: string }>(
            `INSERT INTO witness_heartbeats (
         message_id, sensor_code, site_code, station_code, key_id, boot_id,
         heartbeat_sequence, sent_at, witness_received_at, payload,
         signature_base64, payload_hash, signature_hash
       )
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)
       RETURNING id`,
            [
                params.messageId,
                params.sensorCode,
                params.siteCode,
                params.stationCode,
                params.keyId,
                params.bootId,
                params.heartbeatSequence,
                params.sentAt.toISOString(),
                params.receivedAt.toISOString(),
                JSON.stringify(params.payload),
                params.signatureBase64,
                params.payloadHash,
                params.signatureHash,
            ]
        );

        const id = res.rows[0]?.id;
        if (!id) {
            throw new Error('Failed to retrieve inserted witness heartbeat ID');
        }
        return { id };
    }

    /**
     * Retrieves a single witness event by messageId.
     */
    async getEventByMessageId(messageId: string): Promise<WitnessEventRecord | null> {
        const res = await this.pool.query<{
            id: string;
            witness_sequence: string;
            event_type: 'TELEMETRY' | 'OPERATIONS_CONTEXT';
            message_id: string;
            site_code: string;
            station_code: string;
            identity_type: 'SENSOR' | 'OPERATIONS_SOURCE';
            identity_code: string;
            key_id: string;
            boot_id: string | null;
            source_sequence: string;
            source_timestamp: Date;
            payload: Record<string, unknown>;
            signature_base64: string;
            payload_hash: string;
            signature_hash: string;
            witness_received_at: Date;
            previous_hash: string;
            event_hash: string;
        }>(
            `SELECT id, witness_sequence, event_type, message_id, site_code, station_code,
              identity_type, identity_code, key_id, boot_id, source_sequence,
              source_timestamp, payload, signature_base64, payload_hash, signature_hash,
              witness_received_at, previous_hash, event_hash
       FROM witness_events
       WHERE message_id = $1`,
            [messageId]
        );

        if (res.rows.length === 0 || !res.rows[0]) return null;
        const r = res.rows[0];
        return {
            id: r.id,
            witnessSequence: Number(r.witness_sequence),
            eventType: r.event_type,
            messageId: r.message_id,
            siteCode: r.site_code,
            stationCode: r.station_code,
            identityType: r.identity_type,
            identityCode: r.identity_code,
            keyId: r.key_id,
            bootId: r.boot_id,
            sourceSequence: Number(r.source_sequence),
            sourceTimestamp: r.source_timestamp,
            payload: r.payload,
            signatureBase64: r.signature_base64,
            payloadHash: r.payload_hash,
            signatureHash: r.signature_hash,
            witnessReceivedAt: r.witness_received_at,
            previousHash: r.previous_hash,
            eventHash: r.event_hash,
        };
    }

    /**
     * Retrieves the latest checkpoint for a station.
     */
    async getLatestCheckpoint(stationCode: string): Promise<WitnessCheckpointRecord | null> {
        const res = await this.pool.query<{
            id: string;
            witness_id: string;
            witness_key_id: string;
            site_code: string;
            station_code: string;
            checkpoint_sequence: string;
            last_witness_sequence: string;
            chain_head_hash: string;
            previous_checkpoint_hash: string;
            created_at: Date;
            canonical_payload: string;
            signature_base64: string;
            checkpoint_hash: string;
            witness_public_key_fingerprint: string;
        }>(
            `SELECT id, witness_id, witness_key_id, site_code, station_code, checkpoint_sequence,
              last_witness_sequence, chain_head_hash, previous_checkpoint_hash, created_at,
              canonical_payload, signature_base64, checkpoint_hash, witness_public_key_fingerprint
       FROM witness_checkpoints
       WHERE station_code = $1
       ORDER BY checkpoint_sequence DESC
       LIMIT 1`,
            [stationCode]
        );

        if (res.rows.length === 0 || !res.rows[0]) return null;
        const r = res.rows[0];
        return {
            id: r.id,
            witnessId: r.witness_id,
            witnessKeyId: r.witness_key_id,
            siteCode: r.site_code,
            stationCode: r.station_code,
            checkpointSequence: Number(r.checkpoint_sequence),
            lastWitnessSequence: Number(r.last_witness_sequence),
            chainHeadHash: r.chain_head_hash,
            previousCheckpointHash: r.previous_checkpoint_hash,
            createdAt: r.created_at,
            canonicalPayload: r.canonical_payload,
            signatureBase64: r.signature_base64,
            checkpointHash: r.checkpoint_hash,
            witnessPublicKeyFingerprint: r.witness_public_key_fingerprint,
        };
    }

    /**
     * Retrieves events for a station in sequence order.
     */
    async getEventsForStation(
        stationCode: string,
        fromSeq = 1,
        toSeq?: number
    ): Promise<WitnessEventRecord[]> {
        let query = `
      SELECT id, witness_sequence, event_type, message_id, site_code, station_code,
             identity_type, identity_code, key_id, boot_id, source_sequence,
             source_timestamp, payload, signature_base64, payload_hash, signature_hash,
             witness_received_at, previous_hash, event_hash
      FROM witness_events
      WHERE station_code = $1 AND witness_sequence >= $2
    `;
        const params: (string | number)[] = [stationCode, fromSeq];

        if (toSeq !== undefined) {
            query += ` AND witness_sequence <= $3`;
            params.push(toSeq);
        }

        query += ` ORDER BY witness_sequence ASC`;

        const res = await this.pool.query(query, params);
        return res.rows.map((r: any) => ({
            id: r.id,
            witnessSequence: Number(r.witness_sequence),
            eventType: r.event_type,
            messageId: r.message_id,
            siteCode: r.site_code,
            stationCode: r.station_code,
            identityType: r.identity_type,
            identityCode: r.identity_code,
            keyId: r.key_id,
            bootId: r.boot_id,
            sourceSequence: Number(r.source_sequence),
            sourceTimestamp: r.source_timestamp,
            payload: r.payload,
            signatureBase64: r.signature_base64,
            payloadHash: r.payload_hash,
            signatureHash: r.signature_hash,
            witnessReceivedAt: r.witness_received_at,
            previousHash: r.previous_hash,
            eventHash: r.event_hash,
        }));
    }

    /**
     * Retrieves all checkpoints for a station in sequence order.
     */
    async getCheckpointsForStation(stationCode: string): Promise<WitnessCheckpointRecord[]> {
        const res = await this.pool.query(
            `SELECT id, witness_id, witness_key_id, site_code, station_code, checkpoint_sequence,
              last_witness_sequence, chain_head_hash, previous_checkpoint_hash, created_at,
              canonical_payload, signature_base64, checkpoint_hash, witness_public_key_fingerprint
       FROM witness_checkpoints
       WHERE station_code = $1
       ORDER BY checkpoint_sequence ASC`,
            [stationCode]
        );

        return res.rows.map((r: any) => ({
            id: r.id,
            witnessId: r.witness_id,
            witnessKeyId: r.witness_key_id,
            siteCode: r.site_code,
            stationCode: r.station_code,
            checkpointSequence: Number(r.checkpoint_sequence),
            lastWitnessSequence: Number(r.last_witness_sequence),
            chainHeadHash: r.chain_head_hash,
            previousCheckpointHash: r.previous_checkpoint_hash,
            createdAt: r.created_at,
            canonicalPayload: r.canonical_payload,
            signatureBase64: r.signature_base64,
            checkpointHash: r.checkpoint_hash,
            witnessPublicKeyFingerprint: r.witness_public_key_fingerprint,
        }));
    }

    /**
     * Inserts a record into witness_tamper_events.
     */
    async insertTamperRecord(
        record: {
            eventId: string;
            sensorCode: string;
            siteCode: string;
            stationCode: string;
            keyId: string;
            eventType: string;
            eventTimestamp: Date;
            tamperSource: string;
            sequenceNo: number;
            payload: Record<string, unknown>;
            signatureBase64: string;
            payloadHash: string;
            signatureHash: string;
        },
        client?: PoolClient
    ): Promise<void> {
        const q = `
      INSERT INTO witness_tamper_events (
        event_id,
        sensor_code,
        site_code,
        station_code,
        key_id,
        event_type,
        event_timestamp,
        tamper_source,
        sequence_no,
        payload,
        signature_base64,
        payload_hash,
        signature_hash
      ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)
    `;
        const params = [
            record.eventId,
            record.sensorCode,
            record.siteCode,
            record.stationCode,
            record.keyId,
            record.eventType,
            record.eventTimestamp,
            record.tamperSource,
            record.sequenceNo,
            JSON.stringify(record.payload),
            record.signatureBase64,
            record.payloadHash,
            record.signatureHash,
        ];
        if (client) {
            await client.query(q, params);
        } else {
            await this.pool.query(q, params);
        }
    }

    /**
     * Get maximum recorded tamper sequence for a sensor in witness.
     */
    async getLastTamperSequence(sensorCode: string, client?: PoolClient): Promise<number> {
        const q = 'SELECT COALESCE(MAX(sequence_no), 0) as max_seq FROM witness_tamper_events WHERE sensor_code = $1';
        const res = client
            ? await client.query<{ max_seq: string }>(q, [sensorCode])
            : await this.pool.query<{ max_seq: string }>(q, [sensorCode]);
        return res.rows[0] ? Number(res.rows[0].max_seq) : 0;
    }

    /**
     * Records a security event to witness_security_events.
     */
    async recordSecurityEvent(
        eventType: string,
        reasonCode: string,
        sanitizedMetadata: Record<string, unknown> = {}
    ): Promise<void> {
        try {
            await this.pool.query(
                `INSERT INTO witness_security_events (event_type, reason_code, sanitized_metadata)
         VALUES ($1, $2, $3)`,
                [eventType, reasonCode, JSON.stringify(sanitizedMetadata)]
            );
        } catch (err) {
            console.error('[WITNESS_SECURITY_LOG] Failed to record security event:', err);
        }
    }
}
