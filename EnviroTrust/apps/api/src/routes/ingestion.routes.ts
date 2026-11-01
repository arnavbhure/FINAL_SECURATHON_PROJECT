import crypto from 'node:crypto';
import { Router, type Request, type Response } from 'express';
import { IngestionService } from '../services/ingestion.service.js';
import { getDbPool } from '../db/connection.js';

export function createIngestionRouter(): Router {
  const router = Router();
  const pool = getDbPool();
  const ingestionService = new IngestionService(pool);

  // POST /api/v1/ingestion/readings
  router.post('/readings', async (req: Request, res: Response) => {
    const requestId = crypto.randomUUID();
    res.setHeader('X-Request-Id', requestId);

    try {
      const result = await ingestionService.ingestTelemetry(req.body, requestId);
      return res.status(result.status).json(result.body);
    } catch (err) {
      console.error('[ROUTE /readings] Unhandled error:', (err as Error).message);
      return res.status(500).json({
        success: false,
        code: 'INTERNAL_SERVER_ERROR',
        message: 'An unexpected internal error occurred',
        requestId,
      });
    }
  });

  // POST /api/v1/ingestion/operations-context
  router.post('/operations-context', async (req: Request, res: Response) => {
    const requestId = crypto.randomUUID();
    res.setHeader('X-Request-Id', requestId);

    try {
      const result = await ingestionService.ingestOperationsContext(req.body, requestId);
      return res.status(result.status).json(result.body);
    } catch (err) {
      console.error('[ROUTE /operations-context] Unhandled error:', (err as Error).message);
      return res.status(500).json({
        success: false,
        code: 'INTERNAL_SERVER_ERROR',
        message: 'An unexpected internal error occurred',
        requestId,
      });
    }
  });

  // POST /api/v1/ingestion/heartbeats
  router.post('/heartbeats', async (req: Request, res: Response) => {
    const requestId = crypto.randomUUID();
    res.setHeader('X-Request-Id', requestId);

    try {
      const result = await ingestionService.ingestHeartbeat(req.body, requestId);
      return res.status(result.status).json(result.body);
    } catch (err) {
      console.error('[ROUTE /heartbeats] Unhandled error:', (err as Error).message);
      return res.status(500).json({
        success: false,
        code: 'INTERNAL_SERVER_ERROR',
        message: 'An unexpected internal error occurred',
        requestId,
      });
    }
  });

  // POST /api/v1/ingestion/tamper
  router.post('/tamper', async (req: Request, res: Response) => {
    const requestId = crypto.randomUUID();
    res.setHeader('X-Request-Id', requestId);

    try {
      const result = await ingestionService.ingestTamper(req.body, requestId);
      return res.status(result.status).json(result.body);
    } catch (err) {
      console.error('[ROUTE /tamper] Unhandled error:', (err as Error).message);
      return res.status(500).json({
        success: false,
        code: 'INTERNAL_SERVER_ERROR',
        message: 'An unexpected internal error occurred',
        requestId,
      });
    }
  });

  // POST /api/v1/ingestion/tamper/events
  router.post('/tamper/events', async (req: Request, res: Response) => {
    const requestId = crypto.randomUUID();
    res.setHeader('X-Request-Id', requestId);

    try {
      const result = await ingestionService.ingestTamper(req.body, requestId);
      return res.status(result.status).json(result.body);
    } catch (err) {
      console.error('[ROUTE /tamper/events] Unhandled error:', (err as Error).message);
      return res.status(500).json({
        success: false,
        code: 'INTERNAL_SERVER_ERROR',
        message: 'An unexpected internal error occurred',
        requestId,
      });
    }
  });

  return router;
}

