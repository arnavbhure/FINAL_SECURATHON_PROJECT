import type { Request, Response, NextFunction } from 'express';
import crypto from 'node:crypto';
import jwt from 'jsonwebtoken';
import type { WitnessEnvironment } from '../env.js';
import { getWitnessJwtPublicKey } from '../crypto/jwt-keys.js';

export interface WitnessPrincipal {
  type: 'SERVICE' | 'HUMAN';
  sub?: string;
  email?: string;
  role: 'PLATFORM_ADMIN' | 'FACTORY_OPERATOR' | 'REGULATOR_AUDITOR';
  sites: string[];
}

declare global {
  namespace Express {
    interface Request {
      witnessPrincipal?: WitnessPrincipal;
    }
  }
}

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
 * Middleware: Authenticates access to Witness read & verification APIs.
 * Accepts either:
 * 1. Internal witness service token (for primary-to-witness server calls)
 * 2. Authenticated human user Bearer JWT (for auditors/operators/admins)
 *
 * For human users:
 * - Verifies ES256 cryptographic signature, issuer, audience, and algorithm.
 * - Introspects session state with the Primary API via dedicated INTERNAL_AUTH_SECRET.
 * - Strictly enforces session active status, user status, and fresh role & site scopes.
 * - Fails closed (503) if the Primary API is unavailable or times out.
 */
export function authenticateWitnessAccess(env: WitnessEnvironment) {
  return async (req: Request, res: Response, next: NextFunction): Promise<void> => {
    // 1. Check for Service Token (Header x-witness-token or Bearer matching WITNESS_SERVICE_TOKEN)
    const customHeader = req.headers['x-witness-token'];
    const authHeader = req.headers['authorization'];

    if (
      typeof customHeader === 'string' &&
      (timingSafeCompare(customHeader, env.WITNESS_SERVICE_TOKEN) ||
        timingSafeCompare(customHeader, env.WITNESS_INGESTION_TOKEN))
    ) {
      req.witnessPrincipal = {
        type: 'SERVICE',
        role: 'PLATFORM_ADMIN',
        sites: [],
      };
      next();
      return;
    }

    if (!authHeader || typeof authHeader !== 'string') {
      res.status(401).json({
        success: false,
        code: 'UNAUTHORIZED',
        message: 'Authentication required to access witness records and verification services',
      });
      return;
    }

    const [scheme, token] = authHeader.trim().split(/\s+/);
    if (scheme?.toLowerCase() !== 'bearer' || !token) {
      res.status(401).json({
        success: false,
        code: 'INVALID_TOKEN_FORMAT',
        message: 'Invalid authorization format. Expected: Bearer <token>',
      });
      return;
    }

    // Check if token is the service token or ingestion token
    if (
      timingSafeCompare(token, env.WITNESS_SERVICE_TOKEN) ||
      timingSafeCompare(token, env.WITNESS_INGESTION_TOKEN)
    ) {
      req.witnessPrincipal = {
        type: 'SERVICE',
        role: 'PLATFORM_ADMIN',
        sites: [],
      };
      next();
      return;
    }

    // 2. Validate Human JWT via asymmetric public key (ES256)
    let decoded: {
      sub: string;
      sid?: string;
      email: string;
      role: 'PLATFORM_ADMIN' | 'FACTORY_OPERATOR' | 'REGULATOR_AUDITOR';
      sites: string[];
    };

    try {
      const publicKey = getWitnessJwtPublicKey();
      decoded = jwt.verify(token, publicKey, {
        algorithms: ['ES256'],
        issuer: 'envirotrust-api',
        audience: 'envirotrust-web',
      }) as typeof decoded;
    } catch (err: any) {
      const isExpired = err.name === 'TokenExpiredError';
      res.status(401).json({
        success: false,
        code: isExpired ? 'TOKEN_EXPIRED' : 'INVALID_TOKEN',
        message: isExpired
          ? 'Access token has expired. Please refresh your session.'
          : 'Invalid or forged witness authorization token.',
      });
      return;
    }

    // Session identifier must be present for session-tracked human access
    if (!decoded.sid || !decoded.sub) {
      res.status(401).json({
        success: false,
        code: 'SESSION_REVOKED',
        message: 'Access token lacks session identifier. Please re-authenticate.',
      });
      return;
    }

    // 3. Introspect active session with Primary API (Fail Closed)
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), env.INTROSPECTION_TIMEOUT_MS);

    let introRes: globalThis.Response;
    try {
      introRes = await fetch(`${env.PRIMARY_API_URL}/api/v1/internal/auth/introspect`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'X-Internal-Secret': env.INTERNAL_AUTH_SECRET,
        },
        body: JSON.stringify({ sid: decoded.sid, sub: decoded.sub }),
        signal: controller.signal,
      });
    } catch {
      // Primary API is down, unreachable, or timed out: Fail Closed
      res.status(503).json({
        success: false,
        code: 'INTROSPECTION_UNAVAILABLE',
        message: 'Unable to verify session with primary authentication service. Request failed closed.',
      });
      return;
    } finally {
      clearTimeout(timeoutId);
    }

    if (introRes.status === 401 || introRes.status === 403) {
      res.status(503).json({
        success: false,
        code: 'INTROSPECTION_FAILED',
        message: 'Witness failed to authenticate with primary authentication service.',
      });
      return;
    }

    if (!introRes.ok) {
      res.status(503).json({
        success: false,
        code: 'INTROSPECTION_UNAVAILABLE',
        message: 'Primary authentication service returned an error during session introspection.',
      });
      return;
    }

    const introData = (await introRes.json().catch(() => ({}))) as any;
    if (!introData.active || !introData.user) {
      if (introData.code === 'ACCOUNT_DISABLED') {
        res.status(403).json({
          success: false,
          code: 'ACCOUNT_DISABLED',
          message: introData.message || 'Account has been deactivated.',
        });
        return;
      }
      res.status(401).json({
        success: false,
        code: introData.code || 'SESSION_REVOKED',
        message: introData.message || 'Access session has been revoked. Please log in again.',
      });
      return;
    }

    // Attach fresh authoritative principal context from Primary DB (not stale JWT claims!)
    req.witnessPrincipal = {
      type: 'HUMAN',
      sub: introData.user.id,
      email: introData.user.email,
      role: introData.user.role,
      sites: Array.isArray(introData.user.sites) ? introData.user.sites : [],
    };
    next();
  };
}

/**
 * Rate Limiter for Witness Verification operations (in-memory sliding window).
 */
const verificationRateLimits = new Map<string, { count: number; resetAt: number }>();

export function witnessVerificationRateLimiter(maxRequests = 60, windowMs = 60000) {
  return (req: Request, res: Response, next: NextFunction): void => {
    const key = req.ip || req.socket.remoteAddress || 'unknown';
    const now = Date.now();
    const entry = verificationRateLimits.get(key) || { count: 0, resetAt: now + windowMs };

    if (now > entry.resetAt) {
      entry.count = 1;
      entry.resetAt = now + windowMs;
    } else {
      entry.count += 1;
    }

    verificationRateLimits.set(key, entry);

    if (entry.count > maxRequests) {
      res.status(429).json({
        success: false,
        code: 'RATE_LIMITED',
        message: 'Too many verification requests. Please slow down.',
      });
      return;
    }

    next();
  };
}

/**
 * Input sanitization to prevent SSRF and arbitrary parameter injection on reconciliation endpoints.
 */
export function validateReconciliationInput(req: Request, res: Response, next: NextFunction): void {
  const { messageId, payloadHash, signature } = req.body || {};

  const uuidRegex = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
  const hex64Regex = /^[0-9a-f]{64}$/i;

  if (!messageId || typeof messageId !== 'string' || !uuidRegex.test(messageId)) {
    res.status(400).json({
      success: false,
      code: 'INVALID_MESSAGE_ID',
      message: 'messageId must be a valid UUID string',
    });
    return;
  }

  if (!payloadHash || typeof payloadHash !== 'string' || !hex64Regex.test(payloadHash)) {
    res.status(400).json({
      success: false,
      code: 'INVALID_PAYLOAD_HASH',
      message: 'payloadHash must be a 64-character hexadecimal SHA-256 string',
    });
    return;
  }

  if (!signature || typeof signature !== 'string' || signature.length > 256) {
    res.status(400).json({
      success: false,
      code: 'INVALID_SIGNATURE',
      message: 'signature must be a valid Base64 string under 256 characters',
    });
    return;
  }

  next();
}
