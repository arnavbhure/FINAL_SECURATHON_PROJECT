import { Router, type Request, type Response } from 'express';
import { getDbPool } from '../db/connection.js';
import { SensorAvailabilityService } from '../services/sensor-availability.service.js';
import { HeartbeatRepository } from '../repositories/heartbeat.repository.js';
import type { AuthService } from '../services/auth.service.js';
import { authenticateUser } from '../middleware/auth.middleware.js';

export function createSensorHealthRouter(authService?: AuthService): Router {
  const router = Router();
  const pool = getDbPool();
  const availabilityService = new SensorAvailabilityService(pool);

  // Apply authentication middleware if authService is provided
  if (authService) {
    router.use(authenticateUser(authService));
  }

  // GET /api/v1/sensors/health
  router.get('/health', async (req: Request, res: Response) => {
    try {
      const user = req.user;
      let siteFilter: string | undefined = undefined;

      const requestedSite = (req.query.siteId as string) || (req.headers['x-site-id'] as string);

      if (user) {
        if (user.role === 'PLATFORM_ADMIN') {
          // Admin can view all sites or filter by requested site
          siteFilter = requestedSite ? requestedSite.trim() : undefined;
        } else {
          // Factory Operator or Regulator Auditor: restricted to assigned sites
          if (requestedSite) {
            const requested = requestedSite.trim();
            if (!user.sites.includes(requested)) {
              return res.status(403).json({
                success: false,
                code: 'FORBIDDEN_SITE_ACCESS',
                message: `Access denied: user '${user.email}' is not authorized to access site '${requested}'`,
              });
            }
            siteFilter = requested;
          } else {
            // Default to first permitted site if single, or filter dynamically
            siteFilter = user.sites[0];
          }
        }
      } else {
        // Fallback for unauthenticated dev if authService omitted
        siteFilter = requestedSite ? requestedSite.trim() : undefined;
      }

      const allSensors = await availabilityService.getAllSensorsAvailability(siteFilter);

      // If user is non-admin and no specific site was requested, filter all results to permitted sites
      let sensors = allSensors;
      if (user && user.role !== 'PLATFORM_ADMIN' && !siteFilter) {
        sensors = allSensors.filter((s) => user.sites.includes(s.siteCode) || user.sites.includes(s.siteId));
      }

      return res.status(200).json({
        success: true,
        count: sensors.length,
        siteFilter: siteFilter || null,
        evaluatedAt: new Date().toISOString(),
        sensors,
      });
    } catch (err) {
      console.error('[ROUTE /sensors/health] Error:', (err as Error).message);
      return res.status(500).json({
        success: false,
        code: 'INTERNAL_ERROR',
        message: 'Failed to retrieve sensor health',
      });
    }
  });

  // GET /api/v1/sensors/:sensorId/health
  router.get('/:sensorId/health', async (req: Request, res: Response) => {
    const rawSensorId = req.params.sensorId;
    const sensorId = Array.isArray(rawSensorId) ? rawSensorId[0] : rawSensorId;
    if (!sensorId) {
      return res.status(400).json({
        success: false,
        code: 'INVALID_PARAMETER',
        message: 'sensorId is required',
      });
    }

    try {
      const summary = await availabilityService.getSensorAvailability(sensorId);
      if (!summary) {
        return res.status(404).json({
          success: false,
          code: 'SENSOR_NOT_FOUND',
          message: `Sensor '${sensorId}' was not found in the registry`,
        });
      }

      const user = req.user;
      if (user && user.role !== 'PLATFORM_ADMIN') {
        const hasAccess = user.sites.includes(summary.siteCode) || user.sites.includes(summary.siteId);
        if (!hasAccess) {
          return res.status(403).json({
            success: false,
            code: 'FORBIDDEN_SITE_ACCESS',
            message: `Access denied: sensor '${sensorId}' belongs to site '${summary.siteCode}', not authorized site`,
          });
        }
      }

      // Check client-provided site scope header/query param
      const requestedSite = (req.query.siteId as string) || (req.headers['x-site-id'] as string);
      if (requestedSite) {
        const trimmed = requestedSite.trim();
        if (trimmed !== summary.siteId && trimmed !== summary.siteCode) {
          return res.status(403).json({
            success: false,
            code: 'FORBIDDEN_SITE_ACCESS',
            message: `Access denied: sensor '${sensorId}' belongs to site '${summary.siteCode}', not requested site '${trimmed}'`,
          });
        }
      }

      return res.status(200).json({
        success: true,
        evaluatedAt: new Date().toISOString(),
        sensor: summary,
      });
    } catch (err) {
      console.error(`[ROUTE /sensors/${sensorId}/health] Error:`, (err as Error).message);
      return res.status(500).json({
        success: false,
        code: 'INTERNAL_ERROR',
        message: 'Failed to retrieve sensor health',
      });
    }
  });

  return router;
}

export function createHeartbeatRouter(authService?: AuthService): Router {
  const router = Router();
  const pool = getDbPool();
  const availabilityService = new SensorAvailabilityService(pool);
  const heartbeatRepo = new HeartbeatRepository(pool);

  // Apply authentication middleware if authService is provided
  if (authService) {
    router.use(authenticateUser(authService));
  }

  // GET /api/v1/heartbeats/history?sensorId=...
  router.get('/history', async (req: Request, res: Response) => {
    const sensorId = req.query.sensorId;
    if (!sensorId || typeof sensorId !== 'string') {
      return res.status(400).json({
        success: false,
        code: 'MISSING_SENSOR_ID',
        message: 'Query parameter "sensorId" is required',
      });
    }

    const limitParam = req.query.limit;
    let limit = 50;
    if (typeof limitParam === 'string') {
      const parsed = parseInt(limitParam, 10);
      if (!isNaN(parsed) && parsed > 0) {
        limit = Math.min(parsed, 200);
      }
    }

    try {
      // Check sensor existence & site scoping
      const summary = await availabilityService.getSensorAvailability(sensorId);
      if (!summary) {
        return res.status(404).json({
          success: false,
          code: 'SENSOR_NOT_FOUND',
          message: `Sensor '${sensorId}' was not found in the registry`,
        });
      }

      const user = req.user;
      if (user && user.role !== 'PLATFORM_ADMIN') {
        const hasAccess = user.sites.includes(summary.siteCode) || user.sites.includes(summary.siteId);
        if (!hasAccess) {
          return res.status(403).json({
            success: false,
            code: 'FORBIDDEN_SITE_ACCESS',
            message: `Access denied: sensor '${sensorId}' belongs to site '${summary.siteCode}', not authorized site`,
          });
        }
      }

      // Check client-provided site scope header/query param
      const requestedSite = (req.query.siteId as string) || (req.headers['x-site-id'] as string);
      if (requestedSite) {
        const trimmed = requestedSite.trim();
        if (trimmed !== summary.siteId && trimmed !== summary.siteCode) {
          return res.status(403).json({
            success: false,
            code: 'FORBIDDEN_SITE_ACCESS',
            message: `Access denied: sensor '${sensorId}' belongs to site '${summary.siteCode}', not requested site '${trimmed}'`,
          });
        }
      }

      const history = await heartbeatRepo.getHeartbeatHistory(sensorId, limit);

      return res.status(200).json({
        success: true,
        sensorId,
        sensorCode: summary.sensorCode,
        siteCode: summary.siteCode,
        count: history.length,
        heartbeats: history,
      });
    } catch (err) {
      console.error('[ROUTE /heartbeats/history] Error:', (err as Error).message);
      return res.status(500).json({
        success: false,
        code: 'INTERNAL_ERROR',
        message: 'Failed to retrieve heartbeat history',
      });
    }
  });

  return router;
}
