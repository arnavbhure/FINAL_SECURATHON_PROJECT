import { Router, type Request, type Response } from 'express';
import crypto from 'node:crypto';
import type { AuthService } from '../services/auth.service.js';
import type { ApiEnvironment } from '../env.js';

function timingSafeCompare(a: string, b: string): boolean {
  const bufA = Buffer.from(a, 'utf-8');
  const bufB = Buffer.from(b, 'utf-8');
  if (bufA.length !== bufB.length) {
    crypto.timingSafeEqual(bufA, bufA);
    return false;
  }
  return crypto.timingSafeEqual(bufA, bufB);
}

/**
 * Restricted Internal Service Router:
 * Strictly for authenticated server-to-server calls (e.g. Witness token introspection).
 * NEVER accessible publicly without dedicated service credential.
 */
export function createInternalAuthRouter(authService: AuthService, env: ApiEnvironment): Router {
  const router = Router();

  // Guard all internal routes with dedicated INTERNAL_AUTH_SECRET
  router.use((req: Request, res: Response, next) => {
    const customHeader = req.headers['x-internal-secret'];
    const authHeader = req.headers['authorization'];

    let providedSecret: string | undefined;
    if (typeof customHeader === 'string' && customHeader.trim().length > 0) {
      providedSecret = customHeader.trim();
    } else if (typeof authHeader === 'string' && authHeader.trim().length > 0) {
      const [scheme, token] = authHeader.trim().split(/\s+/);
      if (scheme?.toLowerCase() === 'bearer' && token) {
        providedSecret = token;
      }
    }

    if (!providedSecret || !timingSafeCompare(providedSecret, env.INTERNAL_AUTH_SECRET)) {
      res.status(401).json({
        success: false,
        code: 'UNAUTHORIZED_SERVICE',
        message: 'Valid service-to-service credential required for internal introspection.',
      });
      return;
    }

    next();
  });

  // POST /api/v1/internal/auth/introspect
  // Validates human access session and returns current authoritative user state
  router.post('/introspect', async (req: Request, res: Response) => {
    const { sid, sub } = req.body || {};

    if (!sid || typeof sid !== 'string' || !sub || typeof sub !== 'string') {
      res.status(400).json({
        success: false,
        code: 'MISSING_REQUIRED_FIELDS',
        message: 'sid and sub are required strings',
      });
      return;
    }

    try {
      const validated = await authService.validateSession(sid, sub);

      // Return current authorized user context (never returns password hashes or secrets)
      res.status(200).json({
        active: true,
        user: {
          id: validated.sub,
          email: validated.email,
          role: validated.role,
          fullName: validated.fullName,
          status: 'ACTIVE',
          sites: validated.sites,
        },
      });
    } catch (err: any) {
      const inactiveCodes = ['SESSION_REVOKED', 'SESSION_EXPIRED', 'ACCOUNT_DISABLED', 'USER_NOT_FOUND'];
      if (inactiveCodes.includes(err.code)) {
        res.status(200).json({
          active: false,
          code: err.code,
          message: err.message,
        });
        return;
      }

      res.status(500).json({
        success: false,
        code: 'INTERNAL_ERROR',
        message: err.message || 'An error occurred during session introspection',
      });
    }
  });

  return router;
}

