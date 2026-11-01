import { Router, type Request, type Response } from 'express';
import { AlertService, type AuthenticatedUserPrincipal } from '../services/alert.service.js';
import type { AuthService } from '../services/auth.service.js';
import { authenticateUser } from '../middleware/auth.middleware.js';
import type { AlertSeverity, AlertStatus, AlertType } from '../repositories/alert.repository.js';
import { getDbPool } from '../db/connection.js';

export function createAlertRouter(alertService?: AlertService, authService?: AuthService): Router {
  const router = Router();
  const pool = getDbPool();
  const service = alertService || new AlertService(pool);

  // Require human user authentication on all alert routes
  if (authService) {
    router.use(authenticateUser(authService));
  }

  // Helper to extract principal
  function getPrincipal(req: Request): AuthenticatedUserPrincipal {
    if (req.user) {
      return {
        id: req.user.sub,
        email: req.user.email,
        role: req.user.role,
        sites: req.user.sites || [],
      };
    }
    // Fallback in test/dev if authService not passed
    return {
      id: '00000000-0000-0000-0000-000000000001',
      email: 'admin@envirotrust.local',
      role: 'PLATFORM_ADMIN',
      sites: [],
    };
  }

  // 1. GET /api/v1/alerts — List and filter alerts
  router.get('/', async (req: Request, res: Response) => {
    try {
      const user = getPrincipal(req);
      const siteId = typeof req.query['siteId'] === 'string' ? req.query['siteId'].trim() : undefined;
      const sensorId = typeof req.query['sensorId'] === 'string' ? req.query['sensorId'].trim() : undefined;
      const severity = typeof req.query['severity'] === 'string' ? (req.query['severity'].trim() as AlertSeverity) : undefined;
      const status = typeof req.query['status'] === 'string' ? (req.query['status'].trim() as AlertStatus) : undefined;
      const alertType = typeof req.query['alertType'] === 'string' ? (req.query['alertType'].trim() as AlertType) : undefined;
      const limit = req.query['limit'] ? Number(req.query['limit']) : 25;
      const offset = req.query['offset'] ? Number(req.query['offset']) : 0;

      const result = await service.getAlerts(
        {
          siteId,
          sensorId,
          severity,
          status,
          alertType,
          limit,
          offset,
        },
        user
      );

      return res.status(200).json({
        success: true,
        alerts: result.alerts,
        total: result.total,
        limit,
        offset,
      });
    } catch (err: any) {
      const status = err.status || 500;
      return res.status(status).json({
        success: false,
        code: err.code || 'INTERNAL_ERROR',
        message: err.message,
      });
    }
  });

  // 2. GET /api/v1/alerts/summary — Alert metric counts
  router.get('/summary', async (req: Request, res: Response) => {
    try {
      const user = getPrincipal(req);
      const summary = await service.getAlertSummary(user);
      return res.status(200).json({
        success: true,
        summary,
      });
    } catch (err: any) {
      const status = err.status || 500;
      return res.status(status).json({
        success: false,
        code: err.code || 'INTERNAL_ERROR',
        message: err.message,
      });
    }
  });

  // 3. GET /api/v1/alerts/:alertId — Single alert details
  router.get('/:alertId', async (req: Request, res: Response) => {
    try {
      const user = getPrincipal(req);
      const alertId = req.params['alertId'] as string;
      const alert = await service.getAlertById(alertId, user);

      if (!alert) {
        return res.status(404).json({
          success: false,
          code: 'NOT_FOUND',
          message: `Alert '${alertId}' not found`,
        });
      }

      return res.status(200).json({
        success: true,
        alert,
      });
    } catch (err: any) {
      const status = err.status || 500;
      return res.status(status).json({
        success: false,
        code: err.code || 'INTERNAL_ERROR',
        message: err.message,
      });
    }
  });

  // 4. PATCH /api/v1/alerts/:alertId/acknowledge — Acknowledge alert
  router.patch('/:alertId/acknowledge', async (req: Request, res: Response) => {
    try {
      const user = getPrincipal(req);
      const alertId = req.params['alertId'] as string;
      const updated = await service.acknowledgeAlert(alertId, user);

      return res.status(200).json({
        success: true,
        message: 'Alert acknowledged successfully',
        alert: updated,
      });
    } catch (err: any) {
      const status = err.status || 500;
      return res.status(status).json({
        success: false,
        code: err.code || 'INTERNAL_ERROR',
        message: err.message,
      });
    }
  });

  // 5. PATCH /api/v1/alerts/:alertId/resolve — Resolve alert with note
  router.patch('/:alertId/resolve', async (req: Request, res: Response) => {
    try {
      const user = getPrincipal(req);
      const alertId = req.params['alertId'] as string;
      const resolutionNote = req.body?.resolutionNote;

      if (!resolutionNote || typeof resolutionNote !== 'string' || resolutionNote.trim().length < 3) {
        return res.status(400).json({
          success: false,
          code: 'INVALID_RESOLUTION_NOTE',
          message: 'A non-empty resolutionNote (min 3 chars) is required to resolve an incident',
        });
      }

      const updated = await service.resolveAlert(alertId, resolutionNote, user);

      return res.status(200).json({
        success: true,
        message: 'Alert resolved successfully',
        alert: updated,
      });
    } catch (err: any) {
      const status = err.status || 500;
      return res.status(status).json({
        success: false,
        code: err.code || 'INTERNAL_ERROR',
        message: err.message,
      });
    }
  });

  return router;
}

