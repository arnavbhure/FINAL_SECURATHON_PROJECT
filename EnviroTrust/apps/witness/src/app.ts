import express, { type Request, type Response, type NextFunction } from 'express';
import cors from 'cors';
import helmet from 'helmet';
import type { Pool } from 'pg';
import { loadWitnessEnvironment, type WitnessEnvironment } from './env.js';
import { getWitnessDbPool } from './db/connection.js';
import { WitnessIngestionService } from './services/witness-ingestion.service.js';
import { createWitnessRoutes } from './routes/witness.routes.js';

export function createWitnessApp(customPool?: Pool, customEnv?: WitnessEnvironment) {
  const env = customEnv || loadWitnessEnvironment();
  const pool = customPool || getWitnessDbPool(env.WITNESS_DATABASE_URL);
  const ingestionService = new WitnessIngestionService(pool, env);

  const app = express();

  app.use(helmet());
  app.use(
    cors({
      origin: [
        'http://localhost:5173',
        'http://127.0.0.1:5173',
        'http://localhost:3000',
        'http://localhost:4000',
        env.WEB_ORIGIN || 'http://localhost:5173',
      ],
      credentials: true,
      methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
      allowedHeaders: ['Content-Type', 'Authorization', 'x-witness-token', 'x-site-id', 'x-client-type'],
    })
  );
  app.use(express.json({ limit: '1mb' }));

  // Root health check
  app.get('/health', (_req: Request, res: Response) => {
    res.status(200).json({
      status: 'UP',
      service: 'envirotrust-witness',
      timestamp: new Date().toISOString(),
    });
  });

  // Versioned Witness health check
  app.get('/witness/v1/health', (_req: Request, res: Response) => {
    res.status(200).json({
      status: 'UP',
      service: 'envirotrust-witness',
      version: '1.0.0',
      witnessId: env.WITNESS_ID,
      displayName: env.WITNESS_DISPLAY_NAME,
      checkpointInterval: env.WITNESS_CHECKPOINT_EVERY,
      timestamp: new Date().toISOString(),
    });
  });

  // Mount API routes
  app.use('/witness/v1', createWitnessRoutes(ingestionService, env));

  // 404 handler
  app.use((_req: Request, res: Response) => {
    res.status(404).json({
      success: false,
      code: 'NOT_FOUND',
      message: 'Resource not found on witness service',
      timestamp: new Date().toISOString(),
    });
  });

  // Centralized error handler
  app.use((err: Error, _req: Request, res: Response, _next: NextFunction) => {
    const isProduction = env.NODE_ENV === 'production';
    res.status(500).json({
      success: false,
      code: 'INTERNAL_ERROR',
      message: isProduction ? 'An internal witness service error occurred.' : err.message,
      timestamp: new Date().toISOString(),
    });
  });

  return { app, env, pool, ingestionService };
}
