import type { Request, Response, NextFunction } from 'express';
import type { AuthService, AuthTokenPayload } from '../services/auth.service.js';
import type { UserRole } from '../repositories/user.repository.js';

// Extend Express Request type with authenticated user
declare global {
  namespace Express {
    interface Request {
      user?: AuthTokenPayload;
    }
  }
}

/**
 * Middleware: Verifies Bearer JWT access token and attaches user payload.
 */
export function authenticateUser(authService: AuthService) {
  return async (req: Request, res: Response, next: NextFunction): Promise<void> => {
    let token: string | undefined;

    const authHeader = req.headers['authorization'];
    if (authHeader && typeof authHeader === 'string') {
      const [scheme, t] = authHeader.trim().split(/\s+/);
      if (scheme?.toLowerCase() === 'bearer' && t) {
        token = t;
      } else {
        res.status(401).json({
          success: false,
          code: 'INVALID_TOKEN_FORMAT',
          message: 'Invalid authorization format. Expected: Bearer <token>',
        });
        return;
      }
    }

    // Fallback: extract token from browser cookie (envirotrust_jwt)
    if (!token && req.cookies) {
      if (typeof req.cookies['envirotrust_jwt'] === 'string' && req.cookies['envirotrust_jwt'].trim()) {
        token = req.cookies['envirotrust_jwt'].trim();
      } else if (typeof req.cookies['jwt'] === 'string' && req.cookies['jwt'].trim()) {
        token = req.cookies['jwt'].trim();
      }
    }

    if (!token) {
      res.status(401).json({
        success: false,
        code: 'UNAUTHORIZED',
        message: 'Authentication required (Bearer token header or valid session cookie)',
      });
      return;
    }

    try {
      const payload = authService.verifyAccessToken(token);

      // Immediate session revocation check: if sid is present, ensure session is active in DB
      if (payload.sid) {
        const validated = await authService.validateSession(payload.sid, payload.sub);
        req.user = validated;
      } else {
        req.user = payload;
      }

      next();
    } catch (err: any) {
      if (err.code === 'ACCOUNT_DISABLED') {
        res.status(403).json({
          success: false,
          code: 'ACCOUNT_DISABLED',
          message: err.message,
        });
        return;
      }
      if (err.code === 'SESSION_REVOKED') {
        res.status(401).json({
          success: false,
          code: 'SESSION_REVOKED',
          message: 'Access session has been revoked. Please log in again.',
        });
        return;
      }
      const isExpired = err.name === 'TokenExpiredError' || err.code === 'SESSION_EXPIRED';
      res.status(401).json({
        success: false,
        code: isExpired ? 'TOKEN_EXPIRED' : 'INVALID_TOKEN',
        message: isExpired
          ? 'Access token has expired. Please refresh your session.'
          : err.message || 'Invalid or forged access token.',
      });
    }
  };
}

/**
 * Middleware: Requires the user to hold one of the specified roles.
 */
export function requireRoles(...roles: UserRole[]) {
  return (req: Request, res: Response, next: NextFunction): void => {
    if (!req.user) {
      res.status(401).json({
        success: false,
        code: 'UNAUTHORIZED',
        message: 'Authentication required',
      });
      return;
    }

    if (!roles.includes(req.user.role)) {
      res.status(403).json({
        success: false,
        code: 'FORBIDDEN_ROLE',
        message: `Access denied. Requires one of roles: ${roles.join(', ')}`,
      });
      return;
    }

    next();
  };
}

/**
 * Helper: Extracts requested site code/id from query, headers, or route params.
 */
export function extractRequestedSite(req: Request): string | undefined {
  if (typeof req.params['siteId'] === 'string' && req.params['siteId'].trim().length > 0) {
    return req.params['siteId'].trim();
  }
  if (typeof req.query['siteId'] === 'string' && req.query['siteId'].trim().length > 0) {
    return req.query['siteId'].trim();
  }
  const headerSite = req.headers['x-site-id'];
  if (typeof headerSite === 'string' && headerSite.trim().length > 0) {
    return headerSite.trim();
  }
  return undefined;
}

/**
 * Middleware: Enforces site-scoped authorization.
 * PLATFORM_ADMIN can access all sites.
 * FACTORY_OPERATOR and REGULATOR_AUDITOR can only access assigned sites.
 * Client-provided ?siteId= or X-Site-Id header is strictly validated against permitted sites.
 */
export function requireSiteAccess(siteExtractor?: (req: Request) => string | undefined) {
  return (req: Request, res: Response, next: NextFunction): void => {
    if (!req.user) {
      res.status(401).json({
        success: false,
        code: 'UNAUTHORIZED',
        message: 'Authentication required',
      });
      return;
    }

    // Platform administrators have global access to all registered sites
    if (req.user.role === 'PLATFORM_ADMIN') {
      next();
      return;
    }

    const requestedSite = siteExtractor ? siteExtractor(req) : extractRequestedSite(req);

    // If an explicit site was requested, verify user has membership
    if (requestedSite) {
      const hasAccess = req.user.sites.includes(requestedSite);
      if (!hasAccess) {
        res.status(403).json({
          success: false,
          code: 'FORBIDDEN_SITE_ACCESS',
          message: `Access denied: user '${req.user.email}' is not authorized to access site '${requestedSite}'`,
        });
        return;
      }
    }

    next();
  };
}

