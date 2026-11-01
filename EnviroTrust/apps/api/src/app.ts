import express, { type Request, type Response, type NextFunction } from 'express';
import cors from 'cors';
import helmet from 'helmet';
import cookieParser from 'cookie-parser';
import { loadApiEnvironment, type ApiEnvironment } from './env.js';
import { getDbPool } from './db/connection.js';
import { AuthService } from './services/auth.service.js';
import { createAuthRouter } from './routes/auth.routes.js';
import { createAdminRouter } from './routes/admin.routes.js';
import { createInternalAuthRouter } from './routes/internal-auth.routes.js';
import { createIngestionRouter } from './routes/ingestion.routes.js';
import { createSensorHealthRouter, createHeartbeatRouter } from './routes/sensor-health.routes.js';
import { createMonitoringRouter } from './routes/monitoring.routes.js';
import { MlAssessmentService } from './services/ml-assessment.service.js';
import { createMlRouter } from './routes/ml.routes.js';
import { AlertService } from './services/alert.service.js';
import { createAlertRouter } from './routes/alert.routes.js';
import { createTamperRouter } from './routes/tamper.routes.js';
import { createWitnessRouter } from './routes/witness.routes.js';
import { createAttackLabRouter } from './routes/attack-lab.routes.js';
import { AttackLabEngine } from './attack-lab/engine.js';
import { isAttackLabEnabled, loadAttackLabConfig } from './attack-lab/config.js';

export function createApiApp(options: {
  authService?: AuthService;
  mlAssessmentService?: MlAssessmentService;
  alertService?: AlertService;
  env?: ApiEnvironment;
  attackLabEngine?: AttackLabEngine;
} = {}) {
  const env = options.env || loadApiEnvironment();
  const pool = getDbPool();
  const authService = options.authService || new AuthService(pool, env);
  const mlAssessmentService = options.mlAssessmentService || new MlAssessmentService(pool, env);
  const alertService = options.alertService || new AlertService(pool);
  const app = express();

  // Basic security middleware
  app.use(helmet());
  app.use(
    cors({
      origin: env.WEB_ORIGIN,
      credentials: true,
    })
  );
  app.use(express.json({ limit: '1mb' }));
  app.use(cookieParser());

  // Root health check
  app.get('/health', (_req: Request, res: Response) => {
    res.status(200).json({
      status: 'UP',
      service: 'envirotrust-api',
      timestamp: new Date().toISOString(),
    });
  });

  // Versioned API health check
  app.get('/api/v1/health', (_req: Request, res: Response) => {
    res.status(200).json({
      status: 'UP',
      service: 'envirotrust-api',
      version: '1.0.0',
      timestamp: new Date().toISOString(),
      environment: env.NODE_ENV,
      demoMode: env.DEMO_MODE,
      mlEnabled: env.ML_ENABLED,
      attackLabEnabled: isAttackLabEnabled(env),
    });
  });

  // Authentication routes
  app.use('/api/v1/auth', createAuthRouter(authService, env));

  // Administrative user management routes (Strictly PLATFORM_ADMIN)
  app.use('/api/v1/admin', createAdminRouter(authService));

  // Internal service-to-service routes (Guarded by INTERNAL_AUTH_SECRET)
  app.use('/api/v1/internal/auth', createInternalAuthRouter(authService, env));

  // Ingestion routes (Machine identities authenticated via Ed25519 signatures, NOT human JWTs)
  app.use('/api/v1/ingestion', createIngestionRouter());

  // Sensor health and availability routes (Authenticated human users, site-scoped)
  app.use('/api/v1/sensors', createSensorHealthRouter(authService));

  // Heartbeat history routes (Authenticated human users, site-scoped)
  app.use('/api/v1/heartbeats', createHeartbeatRouter(authService));

  // ML assessment routes (Authenticated human users, site-scoped)
  app.use('/api/v1/ml', createMlRouter(mlAssessmentService, authService));

  // Alert and incident management routes (Authenticated human users, site-scoped)
  app.use('/api/v1/alerts', createAlertRouter(alertService, authService));

  // Physical tamper ingestion routes (Machine identities authenticated via Ed25519 signatures)
  app.use('/api/v1/tamper', createTamperRouter());

  // Witness verification and read proxy routes (Primary to Witness proxy)
  app.use('/api/v1/witness', createWitnessRouter(env));

  // Monitoring read routes (Readings, overview, security events, audit chain)
  app.use('/api/v1/monitoring', createMonitoringRouter(authService, pool));

  // Demo-only Attack Simulation Lab. Not mounted at all unless DEMO_MODE=true, ATTACK_LAB_ENABLED=true
  // and NODE_ENV is not production; scenario execution re-checks database identities on every run.
  let attackLabEngine: AttackLabEngine | undefined;
  if (isAttackLabEnabled(env)) {
    attackLabEngine = options.attackLabEngine || new AttackLabEngine(loadAttackLabConfig(env), pool);
    app.use('/api/v1/demo/attack-lab', createAttackLabRouter(authService, attackLabEngine));
  }

  // 404 handler
  app.use((_req: Request, res: Response) => {
    res.status(404).json({
      success: false,
      code: 'NOT_FOUND',
      message: 'Resource not found',
      timestamp: new Date().toISOString(),
    });
  });

  // Centralized error handler
  app.use((err: Error, _req: Request, res: Response, _next: NextFunction) => {
    const isProduction = env.NODE_ENV === 'production';
    res.status(500).json({
      success: false,
      code: 'INTERNAL_ERROR',
      message: isProduction ? 'An internal server error occurred.' : err.message,
      timestamp: new Date().toISOString(),
    });
  });

  return { app, env, authService, mlAssessmentService, alertService, attackLabEngine };
}
