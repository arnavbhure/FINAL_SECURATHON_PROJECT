import { Router, type Request, type Response } from 'express';
import type { ApiEnvironment } from '../env.js';

export function createWitnessRouter(env: ApiEnvironment): Router {
  const router = Router();
  const witnessBase = env.WITNESS_BASE_URL.replace(/\/+$/, '');

  const getHeaders = (req: Request) => {
    const headers: Record<string, string> = {
      'Content-Type': 'application/json',
      Accept: 'application/json',
      'X-Witness-Token': env.WITNESS_SERVICE_TOKEN,
    };
    if (req.headers.authorization) {
      headers['Authorization'] = req.headers.authorization;
    }
    return headers;
  };

  // GET /checkpoints/latest/:stationId
  router.get('/checkpoints/latest/:stationId', async (req: Request, res: Response) => {
    try {
      const stationId = req.params['stationId'] as string;
      const targetUrl = `${witnessBase}/witness/v1/checkpoints/latest/${encodeURIComponent(stationId)}`;
      const witnessRes = await fetch(targetUrl, {
        method: 'GET',
        headers: getHeaders(req),
      });
      const data = await witnessRes.json().catch(() => ({}));
      return res.status(witnessRes.status).json(data);
    } catch (err: any) {
      return res.status(503).json({
        success: false,
        code: 'WITNESS_UNAVAILABLE',
        message: 'Simulated independent witness service is currently unreachable.',
        error: err.message,
      });
    }
  });

  // POST /verify/chain
  router.post('/verify/chain', async (req: Request, res: Response) => {
    try {
      const targetUrl = `${witnessBase}/witness/v1/verify/chain`;
      const witnessRes = await fetch(targetUrl, {
        method: 'POST',
        headers: getHeaders(req),
        body: JSON.stringify(req.body),
      });
      const data = await witnessRes.json().catch(() => ({}));
      return res.status(witnessRes.status).json(data);
    } catch (err: any) {
      return res.status(503).json({
        success: false,
        code: 'WITNESS_UNAVAILABLE',
        message: 'Simulated independent witness service is currently unreachable.',
        error: err.message,
      });
    }
  });

  // POST /verify/primary-record
  router.post('/verify/primary-record', async (req: Request, res: Response) => {
    try {
      const targetUrl = `${witnessBase}/witness/v1/verify/primary-record`;
      const witnessRes = await fetch(targetUrl, {
        method: 'POST',
        headers: getHeaders(req),
        body: JSON.stringify(req.body),
      });
      const data = await witnessRes.json().catch(() => ({}));
      return res.status(witnessRes.status).json(data);
    } catch (err: any) {
      return res.status(503).json({
        success: false,
        code: 'WITNESS_UNAVAILABLE',
        message: 'Simulated independent witness service is currently unreachable.',
        error: err.message,
      });
    }
  });

  // POST /tamper/events
  router.post('/tamper/events', async (req: Request, res: Response) => {
    try {
      const targetUrl = `${witnessBase}/witness/v1/tamper/events`;
      const witnessRes = await fetch(targetUrl, {
        method: 'POST',
        headers: getHeaders(req),
        body: JSON.stringify(req.body),
      });
      const data = await witnessRes.json().catch(() => ({}));
      return res.status(witnessRes.status).json(data);
    } catch (err: any) {
      return res.status(503).json({
        success: false,
        code: 'WITNESS_UNAVAILABLE',
        message: 'Simulated independent witness service is currently unreachable.',
        error: err.message,
      });
    }
  });

  return router;
}

