import type { Pool } from 'pg';
import { AVAILABILITY_CONSTANTS } from '../constants/availability.constants.js';

export type SensorAvailabilityStatus = 'ONLINE' | 'STALE' | 'OFFLINE';

export type AvailabilityReason =
  | 'HEARTBEAT_RECEIVED'
  | 'HEARTBEAT_DELAYED'
  | 'SENSOR_COMMUNICATION_LOST'
  | 'SENSOR_RECOVERED'
  | 'NO_HEARTBEAT_EVER_RECEIVED';

export interface SensorAvailabilitySummary {
  sensorId: string;
  sensorCode: string;
  siteId: string;
  siteCode: string;
  stationId: string;
  stationCode: string;
  parameter: string;
  /** Registry status of the sensor (ACTIVE / INACTIVE / REVOKED). */
  sensorStatus: string;
  /** True for dedicated Attack Lab demo identities. */
  isDemoIdentity: boolean;
  expectedIntervalSeconds: number;
  lastHeartbeatReceivedAt: string | null;
  lastHeartbeatSentAt: string | null;
  lastHeartbeatSequence: number | null;
  currentStatus: SensorAvailabilityStatus;
  statusReason: AvailabilityReason;
  missedIntervals: number;
  primaryDeliveryStatus: 'ONLINE' | 'STALE' | 'OFFLINE';
  witnessDeliveryStatus: 'CONFIRMED' | 'LAGGING' | 'UNREACHABLE' | 'PENDING';
  explanation: string;
}

export class SensorAvailabilityService {
  private readonly expectedIntervalSeconds: number;
  private readonly staleThresholdIntervals: number;
  private readonly offlineThresholdIntervals: number;

  constructor(
    private readonly pool: Pool,
    options: {
      intervalSeconds?: number;
      staleIntervals?: number;
      offlineIntervals?: number;
    } = {}
  ) {
    this.expectedIntervalSeconds = options.intervalSeconds || AVAILABILITY_CONSTANTS.DEFAULT_HEARTBEAT_INTERVAL_SECONDS;
    this.staleThresholdIntervals = options.staleIntervals || AVAILABILITY_CONSTANTS.DEFAULT_STALE_INTERVALS;
    this.offlineThresholdIntervals = options.offlineIntervals || AVAILABILITY_CONSTANTS.DEFAULT_OFFLINE_INTERVALS;
  }

  /**
   * Pure state machine evaluating sensor availability from server-side received timestamps
   * and signed sentAt timestamps to ensure delayed outbox deliveries do not falsely indicate ONLINE.
   */
  public evaluateStatus(
    lastReceivedAt: Date | string | null,
    now: Date = new Date(),
    lastSentAt?: Date | string | null
  ): {
    currentStatus: SensorAvailabilityStatus;
    statusReason: AvailabilityReason;
    missedIntervals: number;
    explanation: string;
  } {
    if (!lastReceivedAt) {
      return {
        currentStatus: 'OFFLINE',
        statusReason: 'NO_HEARTBEAT_EVER_RECEIVED',
        missedIntervals: 0,
        explanation: 'No signed heartbeat has been recorded by the server for this sensor.',
      };
    }

    const lastReceivedMs = new Date(lastReceivedAt).getTime();
    const elapsedReceivedSeconds = Math.max(0, (now.getTime() - lastReceivedMs) / 1000);
    const staleLimit = this.staleThresholdIntervals * this.expectedIntervalSeconds;
    const offlineLimit = this.offlineThresholdIntervals * this.expectedIntervalSeconds;

    // Check sentAt freshness if available
    if (lastSentAt) {
      const lastSentMs = new Date(lastSentAt).getTime();
      const transitDelay = Math.max(0, (lastReceivedMs - lastSentMs) / 1000);
      const elapsedSentSeconds = Math.max(0, (now.getTime() - lastSentMs) / 1000);
      const effectiveElapsed = Math.max(elapsedReceivedSeconds, elapsedSentSeconds);
      const missedIntervals = Math.floor(effectiveElapsed / this.expectedIntervalSeconds);

      // Delayed heartbeat check: if transit delay exceeds offlineLimit (e.g. 30s), it was delayed upon arrival
      if (transitDelay > offlineLimit) {
        return {
          currentStatus: 'OFFLINE',
          statusReason: 'HEARTBEAT_DELAYED',
          missedIntervals,
          explanation: `Heartbeat transmission was delayed (${Math.round(transitDelay)}s transit delay, sent ${Math.round(elapsedSentSeconds)}s ago). Delayed heartbeats do not establish current liveness.`,
        };
      }

      if (effectiveElapsed <= staleLimit && transitDelay <= staleLimit) {
        return {
          currentStatus: 'ONLINE',
          statusReason: 'HEARTBEAT_RECEIVED',
          missedIntervals,
          explanation: `Sensor is communicating normally. Last server receipt ${Math.round(elapsedReceivedSeconds)}s ago.`,
        };
      }

      if (effectiveElapsed <= offlineLimit) {
        return {
          currentStatus: 'STALE',
          statusReason: 'HEARTBEAT_DELAYED',
          missedIntervals,
          explanation: `Heartbeat delayed beyond ${this.staleThresholdIntervals} intervals (${Math.round(effectiveElapsed)}s elapsed). Communication is degraded.`,
        };
      }

      return {
        currentStatus: 'OFFLINE',
        statusReason: 'SENSOR_COMMUNICATION_LOST',
        missedIntervals,
        explanation: `Sensor communication lost after missing ${missedIntervals} expected intervals (${Math.round(effectiveElapsed)}s elapsed). Notice: Missing communication does not prove physical sensor shutdown or tampering.`,
      };
    }

    // Fallback if lastSentAt not provided
    const missedIntervals = Math.floor(elapsedReceivedSeconds / this.expectedIntervalSeconds);

    if (elapsedReceivedSeconds <= staleLimit) {
      return {
        currentStatus: 'ONLINE',
        statusReason: 'HEARTBEAT_RECEIVED',
        missedIntervals,
        explanation: `Sensor is communicating normally. Last server receipt ${Math.round(elapsedReceivedSeconds)}s ago.`,
      };
    }

    if (elapsedReceivedSeconds <= offlineLimit) {
      return {
        currentStatus: 'STALE',
        statusReason: 'HEARTBEAT_DELAYED',
        missedIntervals,
        explanation: `Heartbeat delayed beyond ${this.staleThresholdIntervals} intervals (${Math.round(elapsedReceivedSeconds)}s elapsed). Communication is degraded.`,
      };
    }

    return {
      currentStatus: 'OFFLINE',
      statusReason: 'SENSOR_COMMUNICATION_LOST',
      missedIntervals,
      explanation: `Sensor communication lost after missing ${missedIntervals} expected intervals (${Math.round(elapsedReceivedSeconds)}s elapsed). Notice: Missing communication does not prove physical sensor shutdown or tampering.`,
    };
  }

  /**
   * Retrieves availability summary for a single sensor.
   */
  public async getSensorAvailability(
    sensorCode: string,
    now = new Date()
  ): Promise<SensorAvailabilitySummary | null> {
    const res = await this.pool.query<{
      sensor_id: string;
      sensor_code: string;
      site_id: string;
      site_code: string;
      station_id: string;
      station_code: string;
      parameter: string;
      sensor_status: string;
      is_demo_identity: boolean;
      boot_id: string | null;
      last_heartbeat_sequence: string | null;
      last_sent_at: Date | null;
      last_received_at: Date | null;
    }>(
      `SELECT s.id as sensor_id, s.sensor_code, st.id as station_id, st.station_code,
              si.id as site_id, si.site_code, s.parameter,
              s.status as sensor_status, s.is_demo_identity,
              c.boot_id, c.last_heartbeat_sequence, c.last_sent_at, c.last_received_at
       FROM sensors s
       JOIN monitoring_stations st ON st.id = s.station_id
       JOIN sites si ON si.id = st.site_id
       LEFT JOIN sensor_heartbeat_cursors c ON c.sensor_id = s.id
       WHERE s.sensor_code = $1 OR s.id::text = $1`,
      [sensorCode]
    );

    if (res.rows.length === 0 || !res.rows[0]) return null;
    const row = res.rows[0];

    const evaluation = this.evaluateStatus(row.last_received_at, now, row.last_sent_at);

    return {
      sensorId: row.sensor_id,
      sensorCode: row.sensor_code,
      siteId: row.site_id,
      siteCode: row.site_code,
      stationId: row.station_id,
      stationCode: row.station_code,
      parameter: row.parameter,
      sensorStatus: row.sensor_status,
      isDemoIdentity: Boolean(row.is_demo_identity),
      expectedIntervalSeconds: this.expectedIntervalSeconds,
      lastHeartbeatReceivedAt: row.last_received_at ? row.last_received_at.toISOString() : null,
      lastHeartbeatSentAt: row.last_sent_at ? row.last_sent_at.toISOString() : null,
      lastHeartbeatSequence: row.last_heartbeat_sequence ? Number(row.last_heartbeat_sequence) : null,
      currentStatus: evaluation.currentStatus,
      statusReason: evaluation.statusReason,
      missedIntervals: evaluation.missedIntervals,
      primaryDeliveryStatus: evaluation.currentStatus,
      witnessDeliveryStatus: 'CONFIRMED',
      explanation: evaluation.explanation,
    };
  }

  /**
   * Retrieves availability summaries for all registered sensors.
   * Can be filtered by siteId for operator access restriction.
   */
  public async getAllSensorsAvailability(
    siteId?: string,
    now = new Date()
  ): Promise<SensorAvailabilitySummary[]> {
    let query = `
      SELECT s.id as sensor_id, s.sensor_code, st.id as station_id, st.station_code,
             si.id as site_id, si.site_code, s.parameter,
             s.status as sensor_status, s.is_demo_identity,
             c.boot_id, c.last_heartbeat_sequence, c.last_sent_at, c.last_received_at
      FROM sensors s
      JOIN monitoring_stations st ON st.id = s.station_id
      JOIN sites si ON si.id = st.site_id
      LEFT JOIN sensor_heartbeat_cursors c ON c.sensor_id = s.id
    `;
    const params: string[] = [];

    if (siteId) {
      query += ` WHERE si.id::text = $1 OR si.site_code = $1`;
      params.push(siteId);
    }

    query += ` ORDER BY s.sensor_code ASC`;

    const res = await this.pool.query(query, params);

    return res.rows.map((row: any) => {
      const evaluation = this.evaluateStatus(row.last_received_at, now, row.last_sent_at);

      return {
        sensorId: row.sensor_id,
        sensorCode: row.sensor_code,
        siteId: row.site_id,
        siteCode: row.site_code,
        stationId: row.station_id,
        stationCode: row.station_code,
        parameter: row.parameter,
        sensorStatus: row.sensor_status,
        isDemoIdentity: Boolean(row.is_demo_identity),
        expectedIntervalSeconds: this.expectedIntervalSeconds,
        lastHeartbeatReceivedAt: row.last_received_at ? new Date(row.last_received_at).toISOString() : null,
        lastHeartbeatSentAt: row.last_sent_at ? new Date(row.last_sent_at).toISOString() : null,
        lastHeartbeatSequence: row.last_heartbeat_sequence ? Number(row.last_heartbeat_sequence) : null,
        currentStatus: evaluation.currentStatus,
        statusReason: evaluation.statusReason,
        missedIntervals: evaluation.missedIntervals,
        primaryDeliveryStatus: evaluation.currentStatus,
        witnessDeliveryStatus: 'CONFIRMED',
        explanation: evaluation.explanation,
      };
    });
  }
}
