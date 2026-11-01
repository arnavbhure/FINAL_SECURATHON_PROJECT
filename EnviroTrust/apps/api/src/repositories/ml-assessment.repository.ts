import type { Pool, PoolClient, QueryResultRow } from 'pg';
import type { OperatingMode } from '@envirotrust/contracts';

export interface MlAssessmentJobRow extends QueryResultRow {
  id: string;
  reading_id: string;
  site_id: string;
  sensor_id: string;
  status: 'PENDING' | 'PROCESSING' | 'COMPLETED' | 'FAILED' | 'INSUFFICIENT_CONTEXT';
  attempts: number;
  max_attempts: number;
  last_error: string | null;
  next_run_at: Date;
  locked_at: Date | null;
  locked_by: string | null;
  created_at: Date;
  updated_at: Date;
}

export interface TelemetryReadingForMl extends QueryResultRow {
  id: string;
  message_id: string;
  sensor_id: string;
  sensor_code: string;
  station_id: string;
  station_code: string;
  site_id: string;
  site_code: string;
  parameter: string;
  value_numeric: string;
  measured_at: Date;
  signature_status: string;
}

export interface OpsContextForMl extends QueryResultRow {
  id: string;
  message_id: string;
  source_id: string;
  production_rate: string;
  wastewater_flow: string;
  treatment_dose: string;
  energy_consumption: string;
  operating_mode: OperatingMode;
  interval_start: Date;
  interval_end: Date;
  received_at: Date;
}

export interface SaveAssessmentParams {
  readingId: string;
  siteId: string;
  contextId?: string | null;
  modelVersion: string;
  status: 'CONSISTENT' | 'SUSPICIOUS' | 'NOT_EVALUATED' | 'ERROR';
  anomalyType?: string | null;
  actualValue: number;
  predictedValue?: number | null;
  residual?: number | null;
  threshold?: number | null;
  severity?: 'NONE' | 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL' | null;
  reasons: string[];
  processingStatus: 'COMPLETED' | 'INSUFFICIENT_CONTEXT' | 'FAILED';
  evaluatedAt: Date;
  /** Raw anomaly-model outputs as returned by the ML service (null when not provided). */
  anomalyScore?: number | null;
  anomalyThreshold?: number | null;
  isAnomaly?: boolean | null;
  detectionSources?: string[] | null;
}

export interface AnomalyAssessmentRow extends QueryResultRow {
  id: string;
  reading_id: string;
  site_id: string;
  site_code?: string;
  sensor_id?: string;
  sensor_code?: string;
  context_id: string | null;
  model_version: string;
  status: 'CONSISTENT' | 'SUSPICIOUS' | 'NOT_EVALUATED' | 'ERROR';
  anomaly_type: string | null;
  actual_value: string;
  predicted_value: string | null;
  residual: string | null;
  threshold: string | null;
  severity: 'NONE' | 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL' | null;
  reasons: string[];
  processing_status: string;
  evaluated_at: Date;
  measured_at?: Date;
}

export class MlAssessmentRepository {
  constructor(private readonly pool: Pool) { }

  getPool(): Pool {
    return this.pool;
  }

  /**
   * Enqueues an assessment job transactionally for a verified telemetry reading.
   */
  async enqueueJob(
    readingId: string,
    siteId: string,
    sensorId: string,
    client?: PoolClient
  ): Promise<string | null> {
    const runner = client || this.pool;
    const res = await runner.query<{ id: string }>(
      `INSERT INTO ml_assessment_jobs (
         reading_id, site_id, sensor_id, status, attempts, next_run_at
       )
       VALUES ($1, $2, $3, 'PENDING', 0, now())
       ON CONFLICT (reading_id) DO NOTHING
       RETURNING id`,
      [readingId, siteId, sensorId]
    );

    return res.rows[0]?.id || null;
  }

  /**
   * Atomically claims a batch of pending or timed-out jobs using FOR UPDATE SKIP LOCKED.
   */
  async claimNextJobs(
    batchSize: number = 10,
    workerId: string = 'worker-1',
    lockTimeoutSec: number = 60
  ): Promise<MlAssessmentJobRow[]> {
    const client = await this.pool.connect();
    try {
      await client.query('BEGIN');

      const selectRes = await client.query<{ id: string }>(
        `SELECT id
         FROM ml_assessment_jobs
         WHERE (
           (status = 'PENDING' AND next_run_at <= now())
           OR (status = 'PROCESSING' AND locked_at < now() - ($2 || ' seconds')::interval)
         )
         ORDER BY next_run_at ASC
         LIMIT $1
         FOR UPDATE SKIP LOCKED`,
        [batchSize, lockTimeoutSec]
      );

      if (selectRes.rows.length === 0) {
        await client.query('COMMIT');
        return [];
      }

      const ids = selectRes.rows.map((r) => r.id);
      const updateRes = await client.query<MlAssessmentJobRow>(
        `UPDATE ml_assessment_jobs
         SET status = 'PROCESSING',
             locked_at = now(),
             locked_by = $2,
             attempts = attempts + 1,
             updated_at = now()
         WHERE id = ANY($1::uuid[])
         RETURNING *`,
        [ids, workerId]
      );

      await client.query('COMMIT');
      return updateRes.rows;
    } catch (err) {
      await client.query('ROLLBACK');
      throw err;
    } finally {
      client.release();
    }
  }

  /**
   * Fetches telemetry reading details and related metadata.
   */
  async getTelemetryReading(readingId: string): Promise<TelemetryReadingForMl | null> {
    const res = await this.pool.query<TelemetryReadingForMl>(
      `SELECT tr.id, tr.message_id, tr.sensor_id, s.sensor_code,
              tr.station_id, ms.station_code,
              tr.site_id, si.site_code,
              tr.parameter, tr.value_numeric, tr.measured_at, tr.signature_status
       FROM telemetry_readings tr
       JOIN sensors s ON s.id = tr.sensor_id
       JOIN monitoring_stations ms ON ms.id = tr.station_id
       JOIN sites si ON si.id = tr.site_id
       WHERE tr.id = $1`,
      [readingId]
    );

    return res.rows[0] || null;
  }

  /**
   * Finds the appropriate verified operational context for the same site and measurement time.
   * Strict adherence to:
   * - Same-site matching (site_id)
   * - Verified OPS-001 identity (source_id = 'OPS-001')
   * - Cryptographically verified signature (verification_status = 'VALID')
   * - No future operational context (interval_start <= measuredAt)
   * - Reading occurred during interval or within boundary tolerance ($2 <= interval_end + boundaryToleranceSec)
   * - No stale/expired context (interval_end >= measuredAt - maxAgeSeconds)
   * - All 5 required numerical/categorical features are non-null
   * - Deterministic tie-breaking across multiple overlapping records (sequence_no DESC, interval_end DESC, id DESC)
   */
  async findMatchingOpsContext(
    siteId: string,
    measuredAt: Date,
    maxAgeSeconds: number = 900,
    boundaryToleranceSeconds: number = 30
  ): Promise<OpsContextForMl | null> {
    const res = await this.pool.query<OpsContextForMl>(
      `SELECT id, message_id, source_id, production_rate, wastewater_flow,
              treatment_dose, energy_consumption, operating_mode,
              interval_start, interval_end, received_at
       FROM operations_context_readings
       WHERE site_id = $1
         AND source_id = 'OPS-001'
         AND verification_status = 'VALID'
         AND interval_start <= $2
         AND $2 <= (interval_end + ($4 || ' seconds')::interval)
         AND interval_end >= ($2 - ($3 || ' seconds')::interval)
         AND production_rate IS NOT NULL
         AND wastewater_flow IS NOT NULL
         AND treatment_dose IS NOT NULL
         AND energy_consumption IS NOT NULL
         AND operating_mode IS NOT NULL
       ORDER BY sequence_no DESC, interval_end DESC, id DESC
       LIMIT 1`,
      [siteId, measuredAt, maxAgeSeconds, boundaryToleranceSeconds]
    );

    return res.rows[0] || null;
  }

  /**
   * Reschedules an assessment job that is awaiting operational context.
   * Keeps status as PENDING, releases lock, and schedules next check.
   */
  async rescheduleJobWaitingForContext(
    jobId: string,
    waitingReason: string,
    delaySeconds: number = 2
  ): Promise<void> {
    await this.pool.query(
      `UPDATE ml_assessment_jobs
       SET status = 'PENDING',
           locked_at = NULL,
           locked_by = NULL,
           last_error = $2,
           next_run_at = now() + ($3 || ' seconds')::interval,
           updated_at = now()
       WHERE id = $1`,
      [jobId, waitingReason, delaySeconds]
    );
  }

  /**
   * Awakens any pending COD assessment jobs for the given site whose measurement time
   * falls within the newly arrived operations context interval.
   */
  async awakenPendingJobsForContext(
    siteId: string,
    intervalStart: Date | string,
    intervalEnd: Date | string,
    boundaryToleranceSeconds: number = 30,
    client?: PoolClient
  ): Promise<string[]> {
    const runner = client || this.pool;
    const res = await runner.query<{ id: string }>(
      `UPDATE ml_assessment_jobs j
       SET next_run_at = now(),
           updated_at = now()
       FROM telemetry_readings tr
       WHERE j.reading_id = tr.id
         AND j.site_id = $1
         AND j.status = 'PENDING'
         AND tr.measured_at >= ($2::timestamptz - ($4 || ' seconds')::interval)
         AND tr.measured_at <= ($3::timestamptz + ($4 || ' seconds')::interval)
       RETURNING j.id`,
      [siteId, intervalStart, intervalEnd, boundaryToleranceSeconds]
    );

    return res.rows.map((r) => r.id);
  }

  /**
   * Fetches recent verified COD readings for the sensor up to the measurement time.
   * Returns them in ascending chronological order.
   */
  async getRecentCodReadings(
    sensorId: string,
    beforeOrAt: Date,
    limit: number = 50
  ): Promise<number[]> {
    const res = await this.pool.query<{ value_numeric: string }>(
      `SELECT value_numeric
       FROM telemetry_readings
       WHERE sensor_id = $1
         AND parameter = 'COD'
         AND signature_status = 'VALID'
         AND measured_at <= $2
       ORDER BY measured_at DESC
       LIMIT $3`,
      [sensorId, beforeOrAt, limit]
    );

    // Reverse to chronological order [oldest ... newest]
    return res.rows.map((r) => Number(r.value_numeric)).reverse();
  }

  /**
   * Persists an anomaly assessment result.
   */
  async saveAssessmentResult(
    params: SaveAssessmentParams,
    client?: PoolClient
  ): Promise<string> {
    const runner = client || this.pool;
    const res = await runner.query<{ id: string }>(
      `INSERT INTO anomaly_results (
         reading_id, site_id, context_id, model_version, status, anomaly_type,
         actual_value, predicted_value, residual, threshold, severity, reasons,
         processing_status, evaluated_at, anomaly_score, anomaly_threshold, is_anomaly, detection_sources
       )
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12::jsonb, $13, $14, $15, $16, $17, $18::jsonb)
       ON CONFLICT (reading_id) DO UPDATE SET
         site_id = EXCLUDED.site_id,
         context_id = EXCLUDED.context_id,
         model_version = EXCLUDED.model_version,
         status = EXCLUDED.status,
         anomaly_type = EXCLUDED.anomaly_type,
         actual_value = EXCLUDED.actual_value,
         predicted_value = EXCLUDED.predicted_value,
         residual = EXCLUDED.residual,
         threshold = EXCLUDED.threshold,
         severity = EXCLUDED.severity,
         reasons = EXCLUDED.reasons,
         processing_status = EXCLUDED.processing_status,
         evaluated_at = EXCLUDED.evaluated_at,
         anomaly_score = EXCLUDED.anomaly_score,
         anomaly_threshold = EXCLUDED.anomaly_threshold,
         is_anomaly = EXCLUDED.is_anomaly,
         detection_sources = EXCLUDED.detection_sources
       RETURNING id`,
      [
        params.readingId,
        params.siteId,
        params.contextId || null,
        params.modelVersion,
        params.status,
        params.anomalyType || null,
        params.actualValue,
        params.predictedValue ?? null,
        params.residual ?? null,
        params.threshold ?? null,
        params.severity || null,
        JSON.stringify(params.reasons),
        params.processingStatus,
        params.evaluatedAt,
        params.anomalyScore ?? null,
        params.anomalyThreshold ?? null,
        params.isAnomaly ?? null,
        params.detectionSources ? JSON.stringify(params.detectionSources) : null,
      ]
    );

    const row = res.rows[0];
    if (!row) {
      throw new Error('Failed to save anomaly assessment result');
    }
    return row.id;
  }

  /**
   * Marks a job as completed or completed with insufficient context.
   */
  async completeJob(
    jobId: string,
    status: 'COMPLETED' | 'INSUFFICIENT_CONTEXT' = 'COMPLETED'
  ): Promise<void> {
    await this.pool.query(
      `UPDATE ml_assessment_jobs
       SET status = $2,
           locked_at = NULL,
           locked_by = NULL,
           last_error = NULL,
           updated_at = now()
       WHERE id = $1`,
      [jobId, status]
    );
  }

  /**
   * Marks a job as failed or reschedules it for retry with backoff.
   */
  async failJob(
    jobId: string,
    error: string,
    canRetry: boolean,
    nextDelaySec: number = 5
  ): Promise<void> {
    await this.pool.query(
      `UPDATE ml_assessment_jobs
       SET status = CASE WHEN $2 = true THEN 'PENDING' ELSE 'FAILED' END,
           locked_at = NULL,
           locked_by = NULL,
           last_error = $3,
           next_run_at = CASE WHEN $2 = true THEN now() + ($4 || ' seconds')::interval ELSE next_run_at END,
           updated_at = now()
       WHERE id = $1`,
      [jobId, canRetry, error, nextDelaySec]
    );
  }

  async resolveSiteId(siteIdentifier: string): Promise<{ id: string; siteCode: string } | null> {
    const res = await this.pool.query<{ id: string; site_code: string }>(
      `SELECT id, site_code FROM sites WHERE id::text = $1 OR site_code = $1`,
      [siteIdentifier]
    );
    if (!res.rows[0]) return null;
    return { id: res.rows[0].id, siteCode: res.rows[0].site_code };
  }

  // --- Read APIs for Dashboard ---

  async getLatestAssessments(
    siteId?: string,
    limit: number = 50
  ): Promise<AnomalyAssessmentRow[]> {
    const params: unknown[] = [limit];
    let siteFilter = '';
    if (siteId) {
      params.push(siteId);
      siteFilter = `WHERE (s.id::text = $2 OR s.site_code = $2)`;
    }

    const res = await this.pool.query<AnomalyAssessmentRow>(
      `SELECT ar.*, s.site_code, tr.sensor_id, sn.sensor_code, tr.measured_at
       FROM anomaly_results ar
       JOIN telemetry_readings tr ON tr.id = ar.reading_id
       JOIN sensors sn ON sn.id = tr.sensor_id
       JOIN sites s ON s.id = ar.site_id
       ${siteFilter}
       ORDER BY ar.evaluated_at DESC
       LIMIT $1`,
      params
    );

    return res.rows;
  }

  async getAssessmentHistoryForSensor(
    sensorId: string,
    siteId?: string,
    limit: number = 50
  ): Promise<AnomalyAssessmentRow[]> {
    const params: unknown[] = [sensorId, limit];
    let siteFilter = '';
    if (siteId) {
      params.push(siteId);
      siteFilter = `AND (s.id::text = $3 OR s.site_code = $3)`;
    }

    const res = await this.pool.query<AnomalyAssessmentRow>(
      `SELECT ar.*, s.site_code, tr.sensor_id, sn.sensor_code, tr.measured_at
       FROM anomaly_results ar
       JOIN telemetry_readings tr ON tr.id = ar.reading_id
       JOIN sensors sn ON sn.id = tr.sensor_id
       JOIN sites s ON s.id = ar.site_id
       WHERE (sn.id::text = $1 OR sn.sensor_code = $1)
       ${siteFilter}
       ORDER BY ar.evaluated_at DESC
       LIMIT $2`,
      params
    );

    return res.rows;
  }

  async getAssessmentByReadingId(
    readingId: string,
    siteId?: string
  ): Promise<AnomalyAssessmentRow | null> {
    const params: unknown[] = [readingId];
    let siteFilter = '';
    if (siteId) {
      params.push(siteId);
      siteFilter = `AND (s.id::text = $2 OR s.site_code = $2)`;
    }

    const res = await this.pool.query<AnomalyAssessmentRow>(
      `SELECT ar.*, s.site_code, tr.sensor_id, sn.sensor_code, tr.measured_at
       FROM anomaly_results ar
       JOIN telemetry_readings tr ON tr.id = ar.reading_id
       JOIN sensors sn ON sn.id = tr.sensor_id
       JOIN sites s ON s.id = ar.site_id
       WHERE (ar.reading_id::text = $1 OR tr.message_id::text = $1)
       ${siteFilter}`,
      params
    );

    return res.rows[0] || null;
  }

  async getCodSeries(
    siteId: string,
    sensorId?: string,
    from?: string,
    to?: string,
    limit = 500
  ): Promise<
    Array<{
      readingId: string;
      siteId: string;
      sensorId: string;
      measuredAt: Date;
      actualCod: number;
      predictedCod: number | null;
      residual: number | null;
      threshold: number | null;
      status: string;
      severity: string | null;
      modelVersion: string | null;
    }>
  > {
    const conditions: string[] = [
      "tr.parameter = 'COD'",
      "(s.id::text = $1 OR s.site_code = $1)",
    ];
    const params: unknown[] = [siteId];

    if (sensorId) {
      params.push(sensorId);
      conditions.push(`(sn.id::text = $${params.length} OR sn.sensor_code = $${params.length})`);
    }
    if (from) {
      params.push(new Date(from));
      conditions.push(`tr.measured_at >= $${params.length}`);
    }
    if (to) {
      params.push(new Date(to));
      conditions.push(`tr.measured_at <= $${params.length}`);
    }
    params.push(limit);

    // Select the NEWEST `limit` readings in range, then return them in chronological order,
    // so live dashboards keep receiving fresh points once a site exceeds the limit.
    const res = await this.pool.query<{
      reading_id: string;
      site_code: string;
      sensor_code: string;
      measured_at: Date;
      actual_value: string;
      predicted_value: string | null;
      residual: string | null;
      threshold: string | null;
      status: string;
      severity: string | null;
      model_version: string | null;
    }>(
      `SELECT tr.id AS reading_id,
              s.site_code,
              sn.sensor_code,
              tr.measured_at,
              tr.value_numeric AS actual_value,
              ar.predicted_value,
              ar.residual,
              ar.threshold,
              COALESCE(ar.status, 'PENDING') AS status,
              ar.severity,
              ar.model_version
       FROM telemetry_readings tr
       JOIN sensors sn ON sn.id = tr.sensor_id
       JOIN sites s ON s.id = tr.site_id
       LEFT JOIN anomaly_results ar ON ar.reading_id = tr.id
       WHERE ${conditions.join(' AND ')}
       ORDER BY tr.measured_at DESC
       LIMIT $${params.length}`,
      params
    );

    return res.rows.reverse().map((r) => ({
      readingId: r.reading_id,
      siteId: r.site_code,
      sensorId: r.sensor_code,
      measuredAt: r.measured_at,
      actualCod: Number(r.actual_value),
      predictedCod: r.predicted_value !== null ? Number(r.predicted_value) : null,
      residual: r.residual !== null ? Number(r.residual) : null,
      threshold: r.threshold !== null ? Number(r.threshold) : null,
      status: r.status,
      severity: r.severity,
      modelVersion: r.model_version,
    }));
  }

  async getJobStatusSummary(siteId?: string): Promise<Record<string, number>> {
    const params: unknown[] = [];
    let filter = '';
    if (siteId) {
      params.push(siteId);
      filter = `WHERE (s.id::text = $1 OR s.site_code = $1)`;
    }

    const res = await this.pool.query<{ status: string; count: string }>(
      `SELECT j.status, count(*) as count
       FROM ml_assessment_jobs j
       JOIN sites s ON s.id = j.site_id
       ${filter}
       GROUP BY j.status`,
      params
    );

    const summary: Record<string, number> = {
      PENDING: 0,
      PROCESSING: 0,
      COMPLETED: 0,
      FAILED: 0,
      INSUFFICIENT_CONTEXT: 0,
    };

    for (const r of res.rows) {
      summary[r.status] = Number(r.count);
    }

    return summary;
  }
}
