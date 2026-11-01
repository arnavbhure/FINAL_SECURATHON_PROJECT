import type { Pool, PoolClient } from 'pg';

export type AlertType =
  | 'PHYSICAL_TAMPER'
  | 'SENSOR_STALE'
  | 'SENSOR_OFFLINE'
  | 'SENSOR_RECOVERED'
  | 'SECURITY_EVENT';

export type AlertSeverity = 'CRITICAL' | 'HIGH' | 'WARNING' | 'INFO';

export type AlertStatus = 'OPEN' | 'ACKNOWLEDGED' | 'RESOLVED';

export interface CreateAlertData {
  siteId: string;
  sensorId?: string | null | undefined;
  stationId?: string | null | undefined;
  alertType: AlertType;
  severity: AlertSeverity;
  title: string;
  description: string;
  sourceEventId?: string | null | undefined;
  detectionSource?: string | undefined;
  status?: AlertStatus | undefined;
  recommendedAction: string;
  deduplicationKey?: string | null | undefined;
  metadata?: Record<string, unknown> | undefined;
}

export interface AlertRow {
  [key: string]: any;
  id: string;
  site_id: string;
  sensor_id: string | null;
  station_id: string | null;
  alert_type: AlertType;
  severity: AlertSeverity;
  title: string;
  description: string;
  source_event_id: string | null;
  detection_source: string;
  status: AlertStatus;
  recommended_action: string;
  deduplication_key: string | null;
  metadata: Record<string, unknown>;
  created_at: string;
  acknowledged_at: string | null;
  acknowledged_by: string | null;
  resolved_at: string | null;
  resolved_by: string | null;
  resolution_note: string | null;
  site_code?: string | undefined;
  site_name?: string | undefined;
  sensor_code?: string | undefined;
  station_code?: string | undefined;
  acknowledged_by_name?: string | null | undefined;
  resolved_by_name?: string | null | undefined;
}

export interface AlertFilters {
  siteIds?: string[] | undefined;
  sensorId?: string | undefined;
  severity?: AlertSeverity | undefined;
  status?: AlertStatus | undefined;
  alertType?: AlertType | undefined;
  limit?: number | undefined;
  offset?: number | undefined;
}

export interface AlertSummaryData {
  totalOpen: number;
  critical: number;
  high: number;
  warning: number;
  resolved: number;
  activeIncidents: number;
}

export class AlertRepository {
  constructor(private readonly pool: Pool) {}

  /**
   * Create an alert with idempotent deduplication key check.
   */
  async createAlert(data: CreateAlertData, client?: PoolClient): Promise<AlertRow> {
    const q = `
      INSERT INTO alerts (
        site_id,
        sensor_id,
        station_id,
        alert_type,
        severity,
        title,
        description,
        source_event_id,
        detection_source,
        status,
        recommended_action,
        deduplication_key,
        metadata
      ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)
      ON CONFLICT (deduplication_key) DO UPDATE
        SET metadata = EXCLUDED.metadata
      RETURNING *
    `;

    const params = [
      data.siteId,
      data.sensorId || null,
      data.stationId || null,
      data.alertType,
      data.severity,
      data.title,
      data.description,
      data.sourceEventId || null,
      data.detectionSource || 'SYSTEM',
      data.status || 'OPEN',
      data.recommendedAction,
      data.deduplicationKey || null,
      JSON.stringify(data.metadata || {}),
    ];

    const res = client
      ? await client.query<AlertRow>(q, params)
      : await this.pool.query<AlertRow>(q, params);
    const row = res.rows[0];
    if (!row) {
      throw new Error('Failed to insert or update alert');
    }
    return row;
  }

  /**
   * Get alert by ID with joined site/sensor details.
   */
  async getAlertById(alertId: string, client?: PoolClient): Promise<AlertRow | null> {
    const q = `
      SELECT 
        a.*,
        s.site_code,
        s.name as site_name,
        sn.sensor_code,
        st.station_code,
        u_ack.full_name as acknowledged_by_name,
        u_res.full_name as resolved_by_name
      FROM alerts a
      LEFT JOIN sites s ON a.site_id = s.id
      LEFT JOIN sensors sn ON a.sensor_id = sn.id
      LEFT JOIN monitoring_stations st ON a.station_id = st.id
      LEFT JOIN users u_ack ON a.acknowledged_by = u_ack.id
      LEFT JOIN users u_res ON a.resolved_by = u_res.id
      WHERE a.id = $1
    `;
    const res = client
      ? await client.query<AlertRow>(q, [alertId])
      : await this.pool.query<AlertRow>(q, [alertId]);
    return res.rows[0] || null;
  }

  /**
   * Get paginated and filtered alerts.
   */
  async getAlerts(filters: AlertFilters): Promise<{ alerts: AlertRow[]; total: number }> {
    const conditions: string[] = [];
    const params: unknown[] = [];
    let pIdx = 1;

    if (filters.siteIds && filters.siteIds.length > 0) {
      conditions.push(`(a.site_id::text = ANY($${pIdx}) OR s.site_code = ANY($${pIdx}))`);
      params.push(filters.siteIds);
      pIdx++;
    }

    if (filters.sensorId) {
      conditions.push(`(a.sensor_id = $${pIdx} OR sn.sensor_code = $${pIdx})`);
      params.push(filters.sensorId);
      pIdx++;
    }

    if (filters.severity) {
      conditions.push(`a.severity = $${pIdx++}`);
      params.push(filters.severity);
    }

    if (filters.status) {
      conditions.push(`a.status = $${pIdx++}`);
      params.push(filters.status);
    }

    if (filters.alertType) {
      conditions.push(`a.alert_type = $${pIdx++}`);
      params.push(filters.alertType);
    }

    const whereClause = conditions.length > 0 ? `WHERE ${conditions.join(' AND ')}` : '';

    const countQuery = `
      SELECT COUNT(*) as total
      FROM alerts a
      LEFT JOIN sites s ON a.site_id = s.id
      LEFT JOIN sensors sn ON a.sensor_id = sn.id
      ${whereClause}
    `;
    const countRes = await this.pool.query<{ total: string }>(countQuery, params);
    const total = countRes.rows[0] ? Number(countRes.rows[0].total) : 0;

    const limit = filters.limit ? Math.min(Math.max(1, filters.limit), 100) : 25;
    const offset = filters.offset ? Math.max(0, filters.offset) : 0;

    const dataQuery = `
      SELECT 
        a.*,
        s.site_code,
        s.name as site_name,
        sn.sensor_code,
        st.station_code,
        u_ack.full_name as acknowledged_by_name,
        u_res.full_name as resolved_by_name
      FROM alerts a
      LEFT JOIN sites s ON a.site_id = s.id
      LEFT JOIN sensors sn ON a.sensor_id = sn.id
      LEFT JOIN monitoring_stations st ON a.station_id = st.id
      LEFT JOIN users u_ack ON a.acknowledged_by = u_ack.id
      LEFT JOIN users u_res ON a.resolved_by = u_res.id
      ${whereClause}
      ORDER BY 
        CASE a.severity
          WHEN 'CRITICAL' THEN 1
          WHEN 'HIGH' THEN 2
          WHEN 'WARNING' THEN 3
          ELSE 4
        END ASC,
        a.created_at DESC
      LIMIT $${pIdx++} OFFSET $${pIdx++}
    `;
    params.push(limit, offset);

    const dataRes = await this.pool.query<AlertRow>(dataQuery, params);
    return {
      alerts: dataRes.rows,
      total,
    };
  }

  /**
   * Get alert metrics breakdown.
   */
  async getAlertSummary(siteIds?: string[] | undefined): Promise<AlertSummaryData> {
    const conditions: string[] = [];
    const params: unknown[] = [];

    if (siteIds && siteIds.length > 0) {
      conditions.push('(alerts.site_id::text = ANY($1) OR s.site_code = ANY($1))');
      params.push(siteIds);
    }

    const whereClause = conditions.length > 0 ? `WHERE ${conditions.join(' AND ')}` : '';

    const q = `
      SELECT
        COUNT(*) FILTER (WHERE alerts.status IN ('OPEN', 'ACKNOWLEDGED')) as total_open,
        COUNT(*) FILTER (WHERE alerts.status IN ('OPEN', 'ACKNOWLEDGED') AND alerts.severity = 'CRITICAL') as critical,
        COUNT(*) FILTER (WHERE alerts.status IN ('OPEN', 'ACKNOWLEDGED') AND alerts.severity = 'HIGH') as high,
        COUNT(*) FILTER (WHERE alerts.status IN ('OPEN', 'ACKNOWLEDGED') AND alerts.severity = 'WARNING') as warning,
        COUNT(*) FILTER (WHERE alerts.status = 'RESOLVED') as resolved,
        COUNT(*) FILTER (WHERE alerts.status = 'OPEN') as active_incidents
      FROM alerts
      LEFT JOIN sites s ON alerts.site_id = s.id
      ${whereClause}
    `;

    const res = await this.pool.query<{
      total_open: string;
      critical: string;
      high: string;
      warning: string;
      resolved: string;
      active_incidents: string;
    }>(q, params);
    const row = res.rows[0];

    return {
      totalOpen: Number(row?.total_open || 0),
      critical: Number(row?.critical || 0),
      high: Number(row?.high || 0),
      warning: Number(row?.warning || 0),
      resolved: Number(row?.resolved || 0),
      activeIncidents: Number(row?.active_incidents || 0),
    };
  }

  /**
   * Find an active (OPEN or ACKNOWLEDGED) alert for a sensor by alert type.
   */
  async findActiveAlertForSensor(
    sensorId: string,
    alertType: AlertType,
    client?: PoolClient
  ): Promise<AlertRow | null> {
    const q = `
      SELECT * FROM alerts
      WHERE sensor_id = $1 AND alert_type = $2 AND status IN ('OPEN', 'ACKNOWLEDGED')
      ORDER BY created_at DESC
      LIMIT 1
    `;
    const res = client
      ? await client.query<AlertRow>(q, [sensorId, alertType])
      : await this.pool.query<AlertRow>(q, [sensorId, alertType]);
    return res.rows[0] || null;
  }

  /**
   * Find open/active alert by deduplication key.
   */
  async findAlertByDeduplicationKey(key: string, client?: PoolClient): Promise<AlertRow | null> {
    const q = 'SELECT * FROM alerts WHERE deduplication_key = $1';
    const res = client
      ? await client.query<AlertRow>(q, [key])
      : await this.pool.query<AlertRow>(q, [key]);
    return res.rows[0] || null;
  }

  /**
   * Acknowledge an alert.
   */
  async acknowledgeAlert(alertId: string, userId: string, client?: PoolClient): Promise<AlertRow | null> {
    const q = `
      UPDATE alerts
      SET 
        status = 'ACKNOWLEDGED',
        acknowledged_at = now(),
        acknowledged_by = $2
      WHERE id = $1 AND status = 'OPEN'
      RETURNING *
    `;
    const res = client
      ? await client.query<AlertRow>(q, [alertId, userId])
      : await this.pool.query<AlertRow>(q, [alertId, userId]);
    return res.rows[0] || null;
  }

  /**
   * Resolve an alert with a resolution note.
   */
  async resolveAlert(
    alertId: string,
    userId: string,
    resolutionNote: string,
    client?: PoolClient
  ): Promise<AlertRow | null> {
    const q = `
      UPDATE alerts
      SET 
        status = 'RESOLVED',
        resolved_at = now(),
        resolved_by = $2,
        resolution_note = $3
      WHERE id = $1 AND status IN ('OPEN', 'ACKNOWLEDGED')
      RETURNING *
    `;
    const res = client
      ? await client.query<AlertRow>(q, [alertId, userId, resolutionNote])
      : await this.pool.query<AlertRow>(q, [alertId, userId, resolutionNote]);
    return res.rows[0] || null;
  }

  /**
   * Resolve active alerts for a sensor (e.g. when sensor recovers).
   */
  async resolveActiveAlertsForSensor(
    sensorId: string,
    alertTypes: AlertType[],
    systemNote: string,
    client?: PoolClient
  ): Promise<AlertRow[]> {
    const q = `
      UPDATE alerts
      SET 
        status = 'RESOLVED',
        resolved_at = now(),
        resolution_note = $2
      WHERE sensor_id = $1 AND alert_type = ANY($3) AND status IN ('OPEN', 'ACKNOWLEDGED')
      RETURNING *
    `;
    const res = client
      ? await client.query<AlertRow>(q, [sensorId, systemNote, alertTypes])
      : await this.pool.query<AlertRow>(q, [sensorId, systemNote, alertTypes]);
    return res.rows;
  }
}
