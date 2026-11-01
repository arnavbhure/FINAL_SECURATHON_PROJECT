import { Router, type Request, type Response } from 'express';
import type { AuthService } from '../services/auth.service.js';
import { authenticateUser, requireRoles } from '../middleware/auth.middleware.js';
import { AttackLabEngine } from '../attack-lab/engine.js';
import { isAuthorizedDemoAdmin } from '../attack-lab/config.js';
import { AttackLabError, type AttackLabRunRecord } from '../attack-lab/types.js';

/**
 * Demo-only Attack Simulation Lab routes. Mounted by app.ts only when DEMO_MODE=true,
 * ATTACK_LAB_ENABLED=true and NODE_ENV is not production.
 *
 * - Every role may read status, the scenario catalog and site-scoped run evidence.
 * - Only PLATFORM_ADMIN accounts on the explicit ATTACK_LAB_AUTHORIZED_ADMINS allowlist may start a run.
 * - A run request names one catalogued scenario ID; no URLs, payloads or scripts are accepted.
 */
export function createAttackLabRouter(authService: AuthService, engine: AttackLabEngine): Router {
  const router = Router();
  router.use(authenticateUser(authService));

  function sendError(res: Response, err: unknown): void {
    if (err instanceof AttackLabError) {
      res.status(err.httpStatus).json({ success: false, code: err.code, message: err.message, details: err.details ?? null });
      return;
    }
    console.error('[ATTACK_LAB_ROUTE]', (err as Error).message);
    res.status(500).json({ success: false, code: 'INTERNAL_ERROR', message: 'Attack Lab request failed' });
  }

  function canSeeRun(req: Request, run: AttackLabRunRecord): boolean {
    if (!req.user) return false;
    if (req.user.role === 'PLATFORM_ADMIN') return true;
    return req.user.sites.includes(run.siteCode);
  }

  router.get('/status', async (req: Request, res: Response) => {
    try {
      const status = await engine.status();
      res.json({ success: true, ...status, canExecute: isAuthorizedDemoAdmin(engine.config, req.user) });
    } catch (err) {
      sendError(res, err);
    }
  });

  router.get('/scenarios', (req: Request, res: Response) => {
    res.json({
      success: true,
      scenarios: engine.catalog(),
      canExecute: isAuthorizedDemoAdmin(engine.config, req.user),
    });
  });

  router.post('/scenarios/:scenarioId/runs', requireRoles('PLATFORM_ADMIN'), async (req: Request, res: Response) => {
    try {
      if (!isAuthorizedDemoAdmin(engine.config, req.user)) {
        throw new AttackLabError(
          'NOT_AUTHORIZED',
          'This administrator account is not on the Attack Lab demo allowlist (ATTACK_LAB_AUTHORIZED_ADMINS).',
          403
        );
      }
      const body = (req.body ?? {}) as Record<string, unknown>;
      const extraKeys = Object.keys(body).filter((k) => k !== 'confirm');
      if (extraKeys.length > 0 || (body['confirm'] !== undefined && typeof body['confirm'] !== 'boolean')) {
        res.status(400).json({
          success: false,
          code: 'INVALID_RUN_REQUEST',
          message: 'A run request may only contain an optional boolean "confirm". Scenario inputs are fixed server-side.',
        });
        return;
      }
      const user = req.user!;
      const { runId } = await engine.startRun(
        String(req.params['scenarioId']),
        { userId: user.sub, label: user.email, source: 'UI' },
        { confirm: body['confirm'] === true }
      );
      res.status(202).json({ success: true, runId });
    } catch (err) {
      sendError(res, err);
    }
  });

  router.get('/runs', async (req: Request, res: Response) => {
    try {
      const limit = req.query['limit'] ? Number(req.query['limit']) : 25;
      const scenarioId = typeof req.query['scenarioId'] === 'string' ? req.query['scenarioId'] : undefined;
      const siteCodes = req.user!.role === 'PLATFORM_ADMIN' ? undefined : req.user!.sites;
      const runs = await engine.runs.listRuns({
        limit: Number.isFinite(limit) ? limit : 25,
        ...(siteCodes ? { siteCodes } : {}),
        ...(scenarioId ? { scenarioId } : {}),
      });
      res.json({ success: true, runs });
    } catch (err) {
      sendError(res, err);
    }
  });

  router.get('/runs/:runId', async (req: Request, res: Response) => {
    try {
      const run = await engine.runs.getRun(String(req.params['runId']));
      if (!run || !canSeeRun(req, run)) {
        res.status(404).json({ success: false, code: 'NOT_FOUND', message: 'Run not found' });
        return;
      }
      res.json({ success: true, run });
    } catch (err) {
      sendError(res, err);
    }
  });

  return router;
}
