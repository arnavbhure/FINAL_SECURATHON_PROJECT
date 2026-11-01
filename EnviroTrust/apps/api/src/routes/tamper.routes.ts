import crypto from 'node:crypto';
import { Router, type Request, type Response } from 'express';
import { IngestionService } from '../services/ingestion.service.js';
import { getDbPool } from '../db/connection.js';

export function createTamperRouter(ingestionService?: IngestionService): Router {
  const router = Router();
  const pool = getDbPool();
  const service = ingestionService || new IngestionService(pool);

  // POST /api/v1/tamper/events
  router.post('/events', async (req: Request, res: Response) => {
    const requestId = crypto.randomUUID();
    res.setHeader('X-Request-Id', requestId);

    try {
      const result = await service.ingestTamper(req.body, requestId);
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

