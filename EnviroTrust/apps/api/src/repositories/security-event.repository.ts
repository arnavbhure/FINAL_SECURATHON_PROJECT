import type { Pool, PoolClient } from 'pg';

export interface RecordSecurityEventParams {
  siteId?: string | null;
  sensorId?: string | null;
  eventType: string;
  reasonCode: string;
  metadata?: Record<string, unknown>;
}

interface SecurityAlertRule {
  severity: 'HIGH' | 'WARNING';
  title: string;
}

/**
 * Rejection reasons that raise a deduplicated SECURITY_EVENT alert.
 * These are rejected attempts, not physical tampering and not proof of intent.
 */
const SECURITY_ALERT_RULES: Record<string, SecurityAlertRule> = {
  INVALID_SIGNATURE: { severity: 'HIGH', title: 'SIGNED MESSAGE REJECTED — SIGNATURE VERIFICATION FAILED' },
  UNKNOWN_KEY: { severity: 'WARNING', title: 'MESSAGE REJECTED — UNKNOWN SIGNING KEY' },
  REPLAYED_SEQUENCE: { severity: 'HIGH', title: 'REPLAYED / ROLLED-BACK SEQUENCE REJECTED' },
  DUPLICATE_MESSAGE: { severity: 'HIGH', title: 'CONFLICTING DUPLICATE MESSAGE ID REJECTED' },
  DUPLICATE_EVENT_ID: { severity: 'HIGH', title: 'CONFLICTING DUPLICATE TAMPER EVENT ID REJECTED' },
  KEY_SENSOR_MISMATCH: { severity: 'HIGH', title: 'IDENTITY / KEY BINDING MISMATCH REJECTED' },
  KEY_SITE_MISMATCH: { severity: 'HIGH', title: 'IDENTITY / KEY BINDING MISMATCH REJECTED' },
  KEY_STATION_MISMATCH: { severity: 'HIGH', title: 'IDENTITY / KEY BINDING MISMATCH REJECTED' },
  KEY_PARAMETER_MISMATCH: { severity: 'HIGH', title: 'IDENTITY / KEY BINDING MISMATCH REJECTED' },
  KEY_SOURCE_MISMATCH: { severity: 'HIGH', title: 'IDENTITY / KEY BINDING MISMATCH REJECTED' },
  KEY_NOT_ACTIVE: { severity: 'WARNING', title: 'MESSAGE REJECTED — SIGNING KEY NOT ACTIVE' },
  INVALID_SIGNATURE_ENCODING: { severity: 'WARNING', title: 'MESSAGE REJECTED — MALFORMED SIGNATURE ENCODING' },
};

const MAX_LINKED_EVENT_IDS = 25;

export class SecurityEventRepository {
  constructor(private readonly pool: Pool) {}

  getPool(): Pool {
    return this.pool;
  }

  async recordSecurityEvent(
    params: RecordSecurityEventParams,
    client?: PoolClient
  ): Promise<string> {
    const q = client || this.pool;
    let securityEventId = '';
    try {
      const res = await q.query<{ id: string }>(
        `INSERT INTO security_events (
           site_id, sensor_id, event_type, reason_code, sanitized_metadata
         )
         VALUES ($1, $2, $3, $4, $5)
         RETURNING id`,
        [
          params.siteId || null,
          params.sensorId || null,
          params.eventType,
          params.reasonCode,
          JSON.stringify(params.metadata || {}),
        ]
      );
      securityEventId = res.rows[0]?.id || '';
    } catch (err) {
      console.error('[SECURITY_EVENT] Failed to record security event:', (err as Error).message);
      return '';
    }

    if (securityEventId && SECURITY_ALERT_RULES[params.reasonCode]) {
      try {
        await this.syncSecurityAlert(securityEventId, params, client);
      } catch (err) {
        // Alerting must never block ingestion responses or hide the recorded security event.
        console.error('[SECURITY_EVENT] Failed to synchronize security alert:', (err as Error).message);
      }
    }

    return securityEventId;
  }

  /**
   * Opens (or refreshes) one deduplicated SECURITY_EVENT alert per site, sensor and rejection reason.
   * Repeated rejections update the open alert's occurrence count instead of creating new alerts;
   * once the alert is resolved, the next rejection opens a new one.
   */
  private async syncSecurityAlert(
    securityEventId: string,
    params: RecordSecurityEventParams,
    existingClient?: PoolClient
  ): Promise<void> {
    const rule = SECURITY_ALERT_RULES[params.reasonCode];
    if (!rule) return;

    const client = existingClient || (await this.pool.connect());
    const manageTransaction = !existingClient;

    try {
      if (manageTransaction) await client.query('BEGIN');

      // Resolve site/sensor scope. Unknown-key rejections carry only the claimed (unauthenticated) sensor code.
      let siteId = params.siteId || null;
      let sensorId = params.sensorId || null;
      let stationId: string | null = null;
      let sensorCode: string | null = null;
      let siteCode: string | null = null;
      const claimedSensorCode =
        typeof params.metadata?.['sensorId'] === 'string' ? (params.metadata['sensorId'] as string) : null;
      const scopeIsClaimed = !sensorId && Boolean(claimedSensorCode);

      const scopeRes = await client.query<{
        sensor_id: string;
        sensor_code: string;
        station_id: string;
        site_id: string;
        site_code: string;
      }>(
        `SELECT s.id AS sensor_id, s.sensor_code, st.id AS station_id, si.id AS site_id, si.site_code
         FROM sensors s
         JOIN monitoring_stations st ON st.id = s.station_id
         JOIN sites si ON si.id = st.site_id
         WHERE ($1::uuid IS NOT NULL AND s.id = $1::uuid)
            OR ($1::uuid IS NULL AND s.sensor_code = $2)
         LIMIT 1`,
        [sensorId, claimedSensorCode]
      );
      const scope = scopeRes.rows[0];
      if (scope) {
        sensorId = scope.sensor_id;
        stationId = scope.station_id;
        sensorCode = scope.sensor_code;
        siteCode = scope.site_code;
        siteId = siteId || scope.site_id;
      } else if (siteId) {
        const siteRes = await client.query<{ site_code: string }>('SELECT site_code FROM sites WHERE id = $1', [siteId]);
        siteCode = siteRes.rows[0]?.site_code || null;
      }

      if (!siteId) {
        // Without a resolvable site the alert cannot be site-scoped; the security event row remains the record.
        if (manageTransaction) await client.query('COMMIT');
        return;
      }

      const scopeKey = `${siteId}:${sensorId || 'none'}:${params.reasonCode}`;
      await client.query('SELECT pg_advisory_xact_lock(hashtext($1))', [`security-alert:${scopeKey}`]);

      const nowIso = new Date().toISOString();
      const activeRes = await client.query<{ id: string; metadata: Record<string, unknown> }>(
        `SELECT id, metadata
         FROM alerts
         WHERE alert_type = 'SECURITY_EVENT'
           AND status IN ('OPEN', 'ACKNOWLEDGED')
           AND site_id = $1
           AND sensor_id IS NOT DISTINCT FROM $2
           AND metadata->>'reasonCode' = $3
         ORDER BY created_at DESC
         LIMIT 1`,
        [siteId, sensorId, params.reasonCode]
      );

      const active = activeRes.rows[0];
      if (active) {
        const meta = active.metadata || {};
        const previousIds = Array.isArray(meta['recentSecurityEventIds'])
          ? (meta['recentSecurityEventIds'] as string[])
          : [];
        const updatedMeta = {
          ...meta,
          occurrenceCount: Number(meta['occurrenceCount'] || 1) + 1,
          lastSeenAt: nowIso,
          lastSecurityEventId: securityEventId,
          lastEventType: params.eventType,
          recentSecurityEventIds: [...previousIds, securityEventId].slice(-MAX_LINKED_EVENT_IDS),
        };
        await client.query('UPDATE alerts SET metadata = $1 WHERE id = $2', [JSON.stringify(updatedMeta), active.id]);
      } else {
        const subject = sensorCode
          ? `${scopeIsClaimed ? 'claimed sensor identity ' : 'sensor '}${sensorCode}`
          : 'an operations source';
        await client.query(
          `INSERT INTO alerts (
             site_id, sensor_id, station_id, alert_type, severity, title, description,
             source_event_id, detection_source, status, recommended_action, deduplication_key, metadata
           )
           VALUES ($1, $2, $3, 'SECURITY_EVENT', $4, $5, $6, $7, 'INGESTION_VERIFICATION', 'OPEN', $8, $9, $10)`,
          [
            siteId,
            sensorId,
            stationId,
            rule.severity,
            rule.title,
            `The Primary API rejected a message for ${subject}${siteCode ? ` at ${siteCode}` : ''} (reason: ${params.reasonCode}). ` +
              'The rejected message was not stored as trusted telemetry. Repeated rejections with the same reason are counted on this alert until it is resolved. ' +
              'A rejected message is a security event; it is not evidence of physical tampering.',
            securityEventId,
            'Review the linked security events, confirm custody of the device signing key, and check the sending device or gateway for misconfiguration or interference.',
            `security:${params.reasonCode}:${securityEventId}`,
            JSON.stringify({
              reasonCode: params.reasonCode,
              eventType: params.eventType,
              scope: scopeIsClaimed ? 'CLAIMED_IDENTITY_UNAUTHENTICATED' : 'REGISTERED_IDENTITY',
              sensorCode,
              occurrenceCount: 1,
              firstSeenAt: nowIso,
              lastSeenAt: nowIso,
              lastSecurityEventId: securityEventId,
              recentSecurityEventIds: [securityEventId],
            }),
          ]
        );
      }

      if (manageTransaction) await client.query('COMMIT');
    } catch (err) {
      if (manageTransaction) await client.query('ROLLBACK').catch(() => undefined);
      throw err;
    } finally {
      if (manageTransaction) client.release();
    }
  }
}
