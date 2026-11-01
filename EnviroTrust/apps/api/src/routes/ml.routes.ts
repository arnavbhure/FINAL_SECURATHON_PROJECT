import { Router, type Request, type Response } from 'express';
import type { AuthService } from '../services/auth.service.js';
import type { MlAssessmentService } from '../services/ml-assessment.service.js';
import { authenticateUser } from '../middleware/auth.middleware.js';

export function createMlRouter(
  mlAssessmentService: MlAssessmentService,
  authService?: AuthService
): Router {
  const router = Router();
  const mlRepo = mlAssessmentService.getAssessmentRepo();

  // GET /api/v1/ml/health (Sanitized public health probe - no internal IPs or tokens)
  router.get('/health', async (_req: Request, res: Response) => {
    try {
      const health = await mlAssessmentService.checkHealth();
      return res.status(200).json({
        success: true,
        enabled: health.enabled,
        reachable: health.reachable,
        ready: Boolean(health.ready),
        modelVersion: health.modelVersion || null,
        status: health.enabled ? (health.reachable ? 'CONNECTED' : 'UNREACHABLE') : 'DISABLED',
        message: health.enabled
          ? (health.reachable ? 'Remote ML inference service is reachable' : 'Remote ML service is currently offline or unreachable over LAN')
          : 'ML integration is disabled via configuration',
      });
    } catch {
      return res.status(500).json({
        success: false,
        code: 'HEALTH_CHECK_ERROR',
        message: 'Unable to evaluate ML service status',
      });
    }
  });

  // Apply authentication to all dashboard read APIs below
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
  ): { authorized: boolean; siteId?: string | undefined } {
    const user = req.user;
    if (!user) {
      // Unauthenticated fallback in mock tests without authService
      return { authorized: true, siteId: requestedSite };
    }

    if (user.role === 'PLATFORM_ADMIN') {
      return { authorized: true, siteId: requestedSite ? requestedSite.trim() : undefined };
    }

    // Operator or Auditor: strictly restricted to assigned site memberships
    if (requestedSite) {
      const site = requestedSite.trim();
      if (!user.sites.includes(site)) {
        res.status(403).json({
          success: false,
          code: 'FORBIDDEN_SITE_ACCESS',
          message: `Access denied: user '${user.email}' is not authorized to access site '${site}'`,
        });
        return { authorized: false, siteId: undefined };
      }
      return { authorized: true, siteId: site };
    }

    // Default to first assigned site if none requested
    return { authorized: true, siteId: user.sites[0] };
  }

  // GET /api/v1/ml/assessments/latest
  router.get('/assessments/latest', async (req: Request, res: Response) => {
    try {
      const requestedSite = (req.query['siteId'] as string) || (req.headers['x-site-id'] as string);
      const auth = authorizeSite(req, res, requestedSite);
      if (!auth.authorized) return;

      const limit = Math.min(Math.max(Number(req.query['limit']) || 50, 1), 200);
      const assessments = await mlRepo.getLatestAssessments(auth.siteId, limit);

      return res.status(200).json({
        success: true,
        count: assessments.length,
        assessments,
      });
    } catch (err) {
      return res.status(500).json({
        success: false,
        code: 'INTERNAL_ERROR',
        message: (err as Error).message,
      });
    }
  });

  // GET /api/v1/ml/assessments/sensor/:sensorId
  router.get('/assessments/sensor/:sensorId', async (req: Request, res: Response) => {
    try {
      const rawSensorId = req.params['sensorId'];
      if (!rawSensorId) {
        return res.status(400).json({ success: false, code: 'MISSING_PARAM', message: 'sensorId is required' });
      }
      const sensorId = String(rawSensorId);

      const requestedSite = (req.query['siteId'] as string) || (req.headers['x-site-id'] as string);
      const auth = authorizeSite(req, res, requestedSite);
      if (!auth.authorized) return;

      const limit = Math.min(Math.max(Number(req.query['limit']) || 50, 1), 200);
      const assessments = await mlRepo.getAssessmentHistoryForSensor(sensorId, auth.siteId, limit);

      return res.status(200).json({
        success: true,
        sensorId,
        count: assessments.length,
        assessments,
      });
    } catch (err) {
      return res.status(500).json({
        success: false,
        code: 'INTERNAL_ERROR',
        message: (err as Error).message,
      });
    }
  });

  // GET /api/v1/ml/assessments/reading/:readingId
  router.get('/assessments/reading/:readingId', async (req: Request, res: Response) => {
    try {
      const rawReadingId = req.params['readingId'];
      if (!rawReadingId) {
        return res.status(400).json({ success: false, code: 'MISSING_PARAM', message: 'readingId is required' });
      }
      const readingId = String(rawReadingId);

      const assessment = await mlRepo.getAssessmentByReadingId(readingId);
      if (assessment) {
        // Enforce site authorization on the retrieved assessment
        const auth = authorizeSite(req, res, assessment.site_code || assessment.site_id);
        if (!auth.authorized) return;

        return res.status(200).json({
          success: true,
          assessment,
        });
      }

      // Check if reading exists
      const reading = await mlRepo.getTelemetryReading(readingId);
      if (!reading) {
        return res.status(404).json({
          success: false,
          code: 'READING_NOT_FOUND',
          message: `Telemetry reading '${readingId}' not found`,
        });
      }

      const auth = authorizeSite(req, res, reading.site_code);
      if (!auth.authorized) return;

      return res.status(200).json({
        success: true,
        assessment: null,
        message: 'Assessment is pending or in progress',
      });
    } catch (err) {
      return res.status(500).json({
        success: false,
        code: 'INTERNAL_ERROR',
        message: (err as Error).message,
      });
    }
  });

  // GET /api/v1/ml/series/cod
  router.get('/series/cod', async (req: Request, res: Response) => {
    try {
      const requestedSite = (req.query['siteId'] as string) || (req.headers['x-site-id'] as string);
      const auth = authorizeSite(req, res, requestedSite);
      if (!auth.authorized) return;

      if (!auth.siteId) {
        return res.status(400).json({
          success: false,
          code: 'SITE_REQUIRED',
          message: 'siteId query parameter is required',
        });
      }

      const sensorId = req.query['sensorId'] as string | undefined;
      const from = req.query['from'] as string | undefined;
      const to = req.query['to'] as string | undefined;
      const limit = Math.min(Math.max(Number(req.query['limit']) || 500, 1), 1000);

      const series = await mlRepo.getCodSeries(auth.siteId, sensorId, from, to, limit);

      return res.status(200).json({
        success: true,
        siteId: auth.siteId,
        count: series.length,
        series,
      });
    } catch (err) {
      return res.status(500).json({
        success: false,
        code: 'INTERNAL_ERROR',
        message: (err as Error).message,
      });
    }
  });

  // GET /api/v1/ml/series/residuals
  router.get('/series/residuals', async (req: Request, res: Response) => {
    try {
      const requestedSite = (req.query['siteId'] as string) || (req.headers['x-site-id'] as string);
      const auth = authorizeSite(req, res, requestedSite);
      if (!auth.authorized) return;

      if (!auth.siteId) {
        return res.status(400).json({
          success: false,
          code: 'SITE_REQUIRED',
          message: 'siteId query parameter is required',
        });
      }

      const sensorId = req.query['sensorId'] as string | undefined;
      const from = req.query['from'] as string | undefined;
      const to = req.query['to'] as string | undefined;
      const limit = Math.min(Math.max(Number(req.query['limit']) || 500, 1), 1000);

      const series = await mlRepo.getCodSeries(auth.siteId, sensorId, from, to, limit);
      const residualSeries = series.map((s) => ({
        readingId: s.readingId,
        siteId: s.siteId,
        sensorId: s.sensorId,
        measuredAt: s.measuredAt,
        actualCod: s.actualCod,
        predictedCod: s.predictedCod,
        residual: s.residual,
        threshold: s.threshold,
        severity: s.severity,
        status: s.status,
        modelVersion: s.modelVersion,
      }));

      return res.status(200).json({
        success: true,
        siteId: auth.siteId,
        count: residualSeries.length,
        series: residualSeries,
      });
    } catch (err) {
      return res.status(500).json({
        success: false,
        code: 'INTERNAL_ERROR',
        message: (err as Error).message,
      });
    }
  });

  // GET /api/v1/ml/jobs/status
  router.get('/jobs/status', async (req: Request, res: Response) => {
    try {
      const requestedSite = (req.query['siteId'] as string) || (req.headers['x-site-id'] as string);
      const auth = authorizeSite(req, res, requestedSite);
      if (!auth.authorized) return;

      const summary = await mlRepo.getJobStatusSummary(auth.siteId);

      return res.status(200).json({
        success: true,
        siteId: auth.siteId || 'ALL',
        summary,
      });
    } catch (err) {
      return res.status(500).json({
        success: false,
        code: 'INTERNAL_ERROR',
        message: (err as Error).message,
      });
    }
  });

  // GET /api/v1/ml/tamper/alerts
  router.get('/tamper/alerts', async (req: Request, res: Response) => {
    try {
      const status = req.query['status'] as string | undefined;
      const severity = req.query['severity'] as string | undefined;
      const deviceId = req.query['deviceId'] as string | undefined;

      const alerts = await mlAssessmentService.getMlClient().getTamperAlerts({
        status,
        severity,
        device_id: deviceId,
      });

      return res.status(200).json({
        success: true,
        count: alerts.length,
        alerts,
      });
    } catch (err) {
      return res.status(500).json({
        success: false,
        code: 'TAMPER_ALERTS_ERROR',
        message: (err as Error).message,
      });
    }
  });

  // GET /api/v1/ml/tamper/devices/:deviceId
  router.get('/tamper/devices/:deviceId', async (req: Request, res: Response) => {
    try {
      const deviceId = req.params['deviceId'] as string;
      const deviceStatus = await mlAssessmentService.getMlClient().getDeviceTamperStatus(deviceId);

      return res.status(200).json({
        success: true,
        deviceId,
        status: deviceStatus,
      });
    } catch (err) {
      return res.status(500).json({
        success: false,
        code: 'DEVICE_TAMPER_ERROR',
        message: (err as Error).message,
      });
    }
  });

  // POST /api/v1/ml/tamper/events
  router.post('/tamper/events', async (req: Request, res: Response) => {
    try {
      const result = await mlAssessmentService.getMlClient().ingestTamperEvent(req.body);
      return res.status(200).json({
        success: true,
        result,
      });
    } catch (err) {
      return res.status(500).json({
        success: false,
        code: 'TAMPER_INGEST_ERROR',
        message: (err as Error).message,
      });
    }
  });

  // GET /api/v1/ml/gateway/status
  router.get('/gateway/status', async (_req: Request, res: Response) => {
    try {
      const gatewayStatus = await mlAssessmentService.getMlClient().getGatewayStatus();
      return res.status(200).json({
        success: true,
        gateway: gatewayStatus,
      });
    } catch (err) {
      return res.status(500).json({
        success: false,
        code: 'GATEWAY_STATUS_ERROR',
        message: (err as Error).message,
      });
    }
  });

  return router;
}
