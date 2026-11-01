import { Router, type Request, type Response } from 'express';
import type { Pool } from 'pg';
import { getDbPool } from '../db/connection.js';
import type { AuthService } from '../services/auth.service.js';
import { authenticateUser } from '../middleware/auth.middleware.js';

export function createMonitoringRouter(authService?: AuthService, customPool?: Pool): Router {
  const router = Router();
  const pool = customPool || getDbPool();

  if (authService) {
    router.use(authenticateUser(authService));
  }

  /**
   * Helper to resolve and authorize site access for the current user.
   */
  function authorizeSite(
    req: Request,
    res: Response,
    requestedSite?: string
  ): { authorized: boolean; siteFilter?: string | undefined } {
    const user = req.user;
    if (!user) {
      return { authorized: true, siteFilter: requestedSite };
    }

    if (user.role === 'PLATFORM_ADMIN') {
      return { authorized: true, siteFilter: requestedSite ? requestedSite.trim() : undefined };
    }

    if (requestedSite) {
      const site = requestedSite.trim();
      if (!user.sites.includes(site)) {
        res.status(403).json({
          success: false,
          code: 'FORBIDDEN_SITE_ACCESS',
          message: `Access denied: user '${user.email}' is not authorized to access site '${site}'`,
        });
        return { authorized: false, siteFilter: undefined };
      }
      return { authorized: true, siteFilter: site };
    }

    return { authorized: true, siteFilter: user.sites[0] };
  }

  function toIsoString(val: any): string | null {
    if (!val) return null;
    if (val instanceof Date) return val.toISOString();
    return new Date(val).toISOString();
  }

  // 1. GET /api/v1/monitoring/sites — List sites available to current user
  router.get('/sites', async (req: Request, res: Response) => {
    try {
      const user = req.user;
      let query = `
        SELECT s.id, s.site_code, s.name, s.industry_type, s.is_demo, s.status, s.created_at,
               count(DISTINCT ms.id) as station_count,
               count(DISTINCT sens.id) as sensor_count
        FROM sites s
        LEFT JOIN monitoring_stations ms ON ms.site_id = s.id
        LEFT JOIN sensors sens ON sens.station_id = ms.id
      `;
      const params: any[] = [];

      if (user && user.role !== 'PLATFORM_ADMIN') {
        query += ` WHERE s.site_code = ANY($1::text[]) OR s.id::text = ANY($1::text[])`;
        params.push(user.sites);
      }

      query += ` GROUP BY s.id, s.site_code, s.name, s.industry_type, s.is_demo, s.status, s.created_at ORDER BY s.site_code ASC`;

      const result = await pool.query(query, params);
      return res.status(200).json({
        success: true,
        count: result.rows.length,
        sites: result.rows.map((r) => ({
          id: r.id,
          siteCode: r.site_code,
          name: r.name,
          industryType: r.industry_type,
          isDemo: r.is_demo,
          demoLabel: r.is_demo ? 'Hackathon Prototype Site' : 'Production Site',
          status: r.status,
          stationCount: Number(r.station_count),
          sensorCount: Number(r.sensor_count),
          createdAt: r.created_at,
        })),
      });
    } catch (err: any) {
      return res.status(500).json({
        success: false,
        code: 'INTERNAL_ERROR',
        message: err.message,
      });
    }
  });

  // 2. GET /api/v1/monitoring/readings — Filterable telemetry readings
  router.get('/readings', async (req: Request, res: Response) => {
    try {
      const requestedSite = (req.query['siteId'] as string) || (req.headers['x-site-id'] as string);
      const auth = authorizeSite(req, res, requestedSite);
      if (!auth.authorized) return;

      const sensorCode = req.query['sensorId'] as string | undefined;
      const parameter = req.query['parameter'] as string | undefined;
      const from = req.query['from'] as string | undefined;
      const to = req.query['to'] as string | undefined;
      const limit = Math.min(Math.max(Number(req.query['limit']) || 50, 1), 500);

      let whereConditions: string[] = [];
      let params: any[] = [];
      let pIdx = 1;

      if (auth.siteFilter) {
        whereConditions.push(`(s.site_code = $${pIdx} OR s.id::text = $${pIdx})`);
        params.push(auth.siteFilter);
        pIdx++;
      } else if (req.user && req.user.role !== 'PLATFORM_ADMIN') {
        whereConditions.push(`(s.site_code = ANY($${pIdx}::text[]) OR s.id::text = ANY($${pIdx}::text[]))`);
        params.push(req.user.sites);
        pIdx++;
      }

      if (sensorCode) {
        whereConditions.push(`sens.sensor_code = $${pIdx}`);
        params.push(sensorCode.trim());
        pIdx++;
      }

      if (parameter) {
        whereConditions.push(`tr.parameter = $${pIdx}`);
        params.push(parameter.trim());
        pIdx++;
      }

      if (from) {
        whereConditions.push(`tr.measured_at >= $${pIdx}::timestamptz`);
        params.push(from);
        pIdx++;
      }

      if (to) {
        whereConditions.push(`tr.measured_at <= $${pIdx}::timestamptz`);
        params.push(to);
        pIdx++;
      }

      const whereClause = whereConditions.length > 0 ? `WHERE ${whereConditions.join(' AND ')}` : '';

      const query = `
        SELECT tr.id, tr.message_id, tr.boot_id, tr.sequence_no, tr.parameter,
               tr.value_numeric, tr.value_wire, tr.unit, tr.measured_at, tr.received_at,
               tr.signature_status, tr.protocol_status, tr.calibration_status, tr.witness_status,
               tr.payload_hash, tr.key_id,
               sens.sensor_code, s.site_code, s.name as site_name, ms.station_code,
               ar.id as anomaly_result_id, ar.status as anomaly_status, ar.severity as anomaly_severity
        FROM telemetry_readings tr
        JOIN sensors sens ON sens.id = tr.sensor_id
        JOIN monitoring_stations ms ON ms.id = tr.station_id
        JOIN sites s ON s.id = tr.site_id
        LEFT JOIN anomaly_results ar ON ar.reading_id = tr.id
        ${whereClause}
        ORDER BY tr.measured_at DESC
        LIMIT $${pIdx}
      `;
      params.push(limit);

      const result = await pool.query(query, params);

      return res.status(200).json({
        success: true,
        count: result.rows.length,
        siteFilter: auth.siteFilter || null,
        readings: result.rows.map((r) => ({
          id: r.id,
          messageId: r.message_id,
          sensorId: r.sensor_code,
          siteId: r.site_code,
          siteName: r.site_name,
          stationId: r.station_code,
          parameter: r.parameter,
          valueNumeric: Number(r.value_numeric),
          valueWire: r.value_wire,
          unit: r.unit,
          measuredAt: toIsoString(r.measured_at),
          receivedAt: toIsoString(r.received_at),
          bootId: r.boot_id,
          sequenceNo: Number(r.sequence_no),
          keyId: r.key_id,
          payloadHash: r.payload_hash,
          signatureStatus: r.signature_status,
          protocolStatus: r.protocol_status,
          calibrationStatus: r.calibration_status,
          witnessStatus: r.witness_status,
          anomaly: r.anomaly_result_id
            ? {
                id: r.anomaly_result_id,
                status: r.anomaly_status,
                severity: r.anomaly_severity,
              }
            : null,
        })),
      });
    } catch (err: any) {
      return res.status(500).json({
        success: false,
        code: 'INTERNAL_ERROR',
        message: err.message,
      });
    }
  });

  // 3. GET /api/v1/monitoring/overview — High-level platform/site metrics
  router.get('/overview', async (req: Request, res: Response) => {
    try {
      const requestedSite = (req.query['siteId'] as string) || (req.headers['x-site-id'] as string);
      const auth = authorizeSite(req, res, requestedSite);
      if (!auth.authorized) return;

      const siteFilter = auth.siteFilter;
      const siteCondition = siteFilter
        ? `WHERE (s.site_code = $1 OR s.id::text = $1)`
        : req.user && req.user.role !== 'PLATFORM_ADMIN'
        ? `WHERE (s.site_code = ANY($1::text[]) OR s.id::text = ANY($1::text[]))`
        : '';
      const params = siteFilter ? [siteFilter] : req.user && req.user.role !== 'PLATFORM_ADMIN' ? [req.user.sites] : [];

      // 1. Reading count
      const countRes = await pool.query(
        `SELECT count(*)::int as total
         FROM telemetry_readings tr
         JOIN sites s ON s.id = tr.site_id
         ${siteCondition}`,
        params
      );
      const totalReadings = countRes.rows[0]?.total || 0;

      // 2. Latest reading per parameter
      const latestQuery = `
        SELECT DISTINCT ON (tr.parameter, sens.sensor_code)
               tr.id, tr.parameter, tr.value_numeric, tr.value_wire, tr.unit, tr.measured_at, tr.received_at,
               sens.sensor_code, s.site_code, ms.station_code, tr.signature_status, tr.protocol_status
        FROM telemetry_readings tr
        JOIN sensors sens ON sens.id = tr.sensor_id
        JOIN monitoring_stations ms ON ms.id = tr.station_id
        JOIN sites s ON s.id = tr.site_id
        ${siteCondition}
        ORDER BY tr.parameter, sens.sensor_code, tr.measured_at DESC
      `;
      const latestRes = await pool.query(latestQuery, params);

      // 3. Anomaly breakdown
      const anomalyRes = await pool.query(
        `SELECT ar.status, count(*)::int as count
         FROM anomaly_results ar
         JOIN telemetry_readings tr ON tr.id = ar.reading_id
         JOIN sites s ON s.id = tr.site_id
         ${siteCondition}
         GROUP BY ar.status`,
        params
      );
      const anomalySummary: Record<string, number> = {
        CONSISTENT: 0,
        SUSPICIOUS: 0,
        NOT_EVALUATED: 0,
        ERROR: 0,
      };
      for (const row of anomalyRes.rows) {
        const s = String(row.status);
        if (s in anomalySummary) {
          anomalySummary[s] = Number(row.count);
        }
      }

      // 4. Recent security events count
      const secEventRes = await pool.query(
        `SELECT count(*)::int as count
         FROM security_events se
         LEFT JOIN sites s ON s.id = se.site_id
         ${siteCondition}`,
        params
      );

      // 5. Total active sensors
      const sensorRes = await pool.query(
        `SELECT count(*)::int as total
         FROM sensors sens
         JOIN monitoring_stations ms ON ms.id = sens.station_id
         JOIN sites s ON s.id = ms.site_id
         ${siteCondition}`,
        params
      );

      return res.status(200).json({
        success: true,
        siteFilter: siteFilter || null,
        metrics: {
          totalReadings,
          totalSensors: sensorRes.rows[0]?.total || 0,
          recentSecurityEventsCount: secEventRes.rows[0]?.count || 0,
          anomalySummary,
          latestReadings: latestRes.rows.map((r) => ({
            id: r.id,
            parameter: r.parameter,
            value: Number(r.value_numeric),
            wireValue: r.value_wire,
            unit: r.unit,
            sensorId: r.sensor_code,
            siteId: r.site_code,
            stationId: r.station_code,
            measuredAt: toIsoString(r.measured_at),
            receivedAt: toIsoString(r.received_at),
            signatureStatus: r.signature_status,
            protocolStatus: r.protocol_status,
          })),
        },
      });
    } catch (err: any) {
      return res.status(500).json({
        success: false,
        code: 'INTERNAL_ERROR',
        message: err.message,
      });
    }
  });

  // 4. GET /api/v1/monitoring/security-events — Security events log
  router.get('/security-events', async (req: Request, res: Response) => {
    try {
      const requestedSite = (req.query['siteId'] as string) || (req.headers['x-site-id'] as string);
      const auth = authorizeSite(req, res, requestedSite);
      if (!auth.authorized) return;

      const limit = Math.min(Math.max(Number(req.query['limit']) || 50, 1), 200);

      let whereConditions: string[] = [];
      let params: any[] = [];
      let pIdx = 1;

      if (auth.siteFilter) {
        whereConditions.push(`(s.site_code = $${pIdx} OR s.id::text = $${pIdx})`);
        params.push(auth.siteFilter);
        pIdx++;
      } else if (req.user && req.user.role !== 'PLATFORM_ADMIN') {
        whereConditions.push(`(s.site_code = ANY($${pIdx}::text[]) OR s.id::text = ANY($${pIdx}::text[]))`);
        params.push(req.user.sites);
        pIdx++;
      }

      const whereClause = whereConditions.length > 0 ? `WHERE ${whereConditions.join(' AND ')}` : '';

      const query = `
        SELECT se.id, se.event_type, se.reason_code, se.sanitized_metadata, se.occurred_at, se.created_at,
               s.site_code, sens.sensor_code
        FROM security_events se
        LEFT JOIN sites s ON s.id = se.site_id
        LEFT JOIN sensors sens ON sens.id = se.sensor_id
        ${whereClause}
        ORDER BY se.occurred_at DESC
        LIMIT $${pIdx}
      `;
      params.push(limit);

      const result = await pool.query(query, params);

      return res.status(200).json({
        success: true,
        count: result.rows.length,
        events: result.rows.map((r) => ({
          id: r.id,
          eventType: r.event_type,
          reasonCode: r.reason_code,
          metadata: r.sanitized_metadata,
          siteId: r.site_code || null,
          sensorId: r.sensor_code || null,
          occurredAt: toIsoString(r.occurred_at),
          createdAt: toIsoString(r.created_at),
        })),
      });
    } catch (err: any) {
      return res.status(500).json({
        success: false,
        code: 'INTERNAL_ERROR',
        message: err.message,
      });
    }
  });

  // 5. GET /api/v1/monitoring/audit-events — Primary hash chain audit events
  router.get('/audit-events', async (req: Request, res: Response) => {
    try {
      const requestedSite = (req.query['siteId'] as string) || (req.headers['x-site-id'] as string);
      const auth = authorizeSite(req, res, requestedSite);
      if (!auth.authorized) return;

      const limit = Math.min(Math.max(Number(req.query['limit']) || 50, 1), 200);

      let whereConditions: string[] = [];
      let params: any[] = [];
      let pIdx = 1;

      if (auth.siteFilter) {
        whereConditions.push(`(s.site_code = $${pIdx} OR s.id::text = $${pIdx})`);
        params.push(auth.siteFilter);
        pIdx++;
      } else if (req.user && req.user.role !== 'PLATFORM_ADMIN') {
        whereConditions.push(`(s.site_code = ANY($${pIdx}::text[]) OR s.id::text = ANY($${pIdx}::text[]))`);
        params.push(req.user.sites);
        pIdx++;
      }

      const whereClause = whereConditions.length > 0 ? `WHERE ${whereConditions.join(' AND ')}` : '';

      const query = `
        SELECT ae.id, ae.event_sequence, ae.event_type, ae.entity_id, ae.message_id,
               ae.event_payload, ae.previous_hash, ae.event_hash, ae.created_at,
               s.site_code, ms.station_code
        FROM audit_events ae
        JOIN monitoring_stations ms ON ms.id = ae.station_id
        JOIN sites s ON s.id = ms.site_id
        ${whereClause}
        ORDER BY ae.event_sequence DESC
        LIMIT $${pIdx}
      `;
      params.push(limit);

      const result = await pool.query(query, params);

      return res.status(200).json({
        success: true,
        count: result.rows.length,
        events: result.rows.map((r) => ({
          id: r.id,
          eventSequence: Number(r.event_sequence),
          eventType: r.event_type,
          entityId: r.entity_id,
          messageId: r.message_id,
          payload: r.event_payload,
          previousHash: r.previous_hash,
          eventHash: r.event_hash,
          siteId: r.site_code,
          stationId: r.station_code,
          createdAt: toIsoString(r.created_at),
        })),
      });
    } catch (err: any) {
      return res.status(500).json({
        success: false,
        code: 'INTERNAL_ERROR',
        message: err.message,
      });
    }
  });

  return router;
}
