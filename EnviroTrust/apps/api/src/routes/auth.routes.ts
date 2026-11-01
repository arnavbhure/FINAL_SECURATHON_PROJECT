import { Router, type Request, type Response } from 'express';
import type { AuthService } from '../services/auth.service.js';
import type { ApiEnvironment } from '../env.js';
import { authenticateUser } from '../middleware/auth.middleware.js';

export function createAuthRouter(authService: AuthService, env: ApiEnvironment): Router {
  const router = Router();
  const cookieName = env.REFRESH_COOKIE_NAME;
  const csrfCookieName = 'envirotrust_csrf';
  const jwtCookieName = 'envirotrust_jwt';

  // Helper to extract refresh token exclusively from HttpOnly cookie for browser routes
  function extractCookieRefreshToken(req: Request): string | undefined {
    if (req.cookies && typeof req.cookies[cookieName] === 'string') {
      return req.cookies[cookieName];
    }
    return undefined;
  }

  // Helper to set HttpOnly refresh cookie
  function setRefreshCookie(res: Response, token: string): void {
    res.cookie(cookieName, token, {
      httpOnly: true,
      secure: env.COOKIE_SECURE,
      sameSite: env.COOKIE_SAME_SITE,
      path: '/api/v1/auth',
      maxAge: env.JWT_REFRESH_TTL_DAYS * 24 * 60 * 60 * 1000,
    });
  }

  // Helper to set readable CSRF cookie (Double Submit Cookie Pattern)
  function setCsrfCookie(res: Response, token: string): void {
    res.cookie(csrfCookieName, token, {
      httpOnly: false, // Must be readable by client-side script to send in header
      secure: env.COOKIE_SECURE,
      sameSite: env.COOKIE_SAME_SITE,
      path: '/',
      maxAge: env.JWT_REFRESH_TTL_DAYS * 24 * 60 * 60 * 1000,
    });
  }

  // Helper to set browser-accessible JWT cookie for persistent sessions
  function setJwtCookie(res: Response, token: string): void {
    res.cookie(jwtCookieName, token, {
      httpOnly: false, // Accessible to frontend script so sessions survive page reload
      secure: env.COOKIE_SECURE,
      sameSite: env.COOKIE_SAME_SITE,
      path: '/',
      maxAge: env.JWT_ACCESS_TTL_MINUTES * 60 * 1000,
    });
  }

  // Helper to clear refresh, CSRF, and JWT cookies
  function clearAuthCookies(res: Response): void {
    res.clearCookie(cookieName, {
      httpOnly: true,
      secure: env.COOKIE_SECURE,
      sameSite: env.COOKIE_SAME_SITE,
      path: '/api/v1/auth',
    });
    res.clearCookie(csrfCookieName, {
      httpOnly: false,
      secure: env.COOKIE_SECURE,
      sameSite: env.COOKIE_SAME_SITE,
      path: '/',
    });
    res.clearCookie(jwtCookieName, {
      httpOnly: false,
      secure: env.COOKIE_SECURE,
      sameSite: env.COOKIE_SAME_SITE,
      path: '/',
    });
  }

  // Verify Origin header against configured frontend origin to prevent cross-site request attacks
  function verifyOrigin(req: Request): boolean {
    const origin = req.headers['origin'];
    if (typeof origin === 'string' && origin.trim().length > 0) {
      const lower = origin.trim().toLowerCase();
      return (
        lower === env.WEB_ORIGIN.toLowerCase() ||
        lower === 'http://localhost:5173' ||
        lower === 'http://127.0.0.1:5173' ||
        lower === 'http://localhost:4000' ||
        lower === 'http://127.0.0.1:4000'
      );
    }
    const referer = req.headers['referer'];
    if (typeof referer === 'string' && referer.trim().length > 0) {
      try {
        const refOrigin = new URL(referer).origin.toLowerCase();
        return (
          refOrigin === env.WEB_ORIGIN.toLowerCase() ||
          refOrigin === 'http://localhost:5173' ||
          refOrigin === 'http://127.0.0.1:5173' ||
          refOrigin === 'http://localhost:4000' ||
          refOrigin === 'http://127.0.0.1:4000'
        );
      } catch {
        return false;
      }
    }
    return true;
  }

  // Verify Double-Submit CSRF protection for cookie-authenticated operations
  function verifyCsrfToken(req: Request): boolean {
    const cookieCsrf = req.cookies?.[csrfCookieName];
    const headerCsrf = req.headers['x-csrf-token'];

    if (!cookieCsrf || !headerCsrf || cookieCsrf !== headerCsrf) {
      return false;
    }
    return true;
  }

  // POST /api/v1/auth/login
  router.post('/login', async (req: Request, res: Response) => {
    const { email, password } = req.body || {};

    if (!email || typeof email !== 'string' || !password || typeof password !== 'string') {
      res.status(400).json({
        success: false,
        code: 'INVALID_CREDENTIALS_FORMAT',
        message: 'Both email and password are required strings',
      });
      return;
    }

    try {
      const clientIp = typeof req.ip === 'string' ? req.ip : req.socket.remoteAddress;
      const userAgent = typeof req.headers['user-agent'] === 'string' ? req.headers['user-agent'] : undefined;
      const ctx: { ip?: string | undefined; userAgent?: string | undefined } = {
        ip: clientIp,
        userAgent,
      };

      const result = await authService.login(email, password, ctx);

      // Refresh token is stored EXCLUSIVELY in HttpOnly cookie; NEVER returned in JSON response body
      setRefreshCookie(res, result.refreshToken);
      setCsrfCookie(res, result.csrfToken);
      setJwtCookie(res, result.accessToken);

      res.status(200).json({
        success: true,
        message: 'Login successful',
        accessToken: result.accessToken,
        csrfToken: result.csrfToken,
        user: result.user,
      });
    } catch (err: any) {
      const status = err.statusCode || 500;
      res.status(status).json({
        success: false,
        code: err.code || 'AUTHENTICATION_FAILED',
        message: err.message || 'An error occurred during authentication',
      });
    }
  });

  // POST /api/v1/auth/refresh (Browser flow: cookie-based with CSRF and Origin protection)
  router.post('/refresh', async (req: Request, res: Response) => {
    // 1. Origin header verification against configured frontend origin
    if (!verifyOrigin(req)) {
      res.status(403).json({
        success: false,
        code: 'FORBIDDEN_ORIGIN',
        message: 'Request origin is not authorized.',
      });
      return;
    }

    // 2. Double-Submit CSRF verification for cookie-authenticated refresh requests
    if (!verifyCsrfToken(req)) {
      res.status(403).json({
        success: false,
        code: 'CSRF_VALIDATION_FAILED',
        message: 'CSRF token missing or mismatch. Pass matching X-CSRF-Token header.',
      });
      return;
    }

    // 3. Extract token exclusively from HttpOnly cookie
    const rawRefreshToken = extractCookieRefreshToken(req);

    if (!rawRefreshToken) {
      res.status(401).json({
        success: false,
        code: 'MISSING_REFRESH_TOKEN',
        message: 'Refresh token cookie is required',
      });
      return;
    }

    try {
      const clientIp = typeof req.ip === 'string' ? req.ip : req.socket.remoteAddress;
      const userAgent = typeof req.headers['user-agent'] === 'string' ? req.headers['user-agent'] : undefined;
      const ctx: { ip?: string | undefined; userAgent?: string | undefined } = {
        ip: clientIp,
        userAgent,
      };

      const result = await authService.refresh(rawRefreshToken, ctx);

      // Rotate HttpOnly cookie and CSRF cookie
      setRefreshCookie(res, result.refreshToken);
      setCsrfCookie(res, result.csrfToken);
      setJwtCookie(res, result.accessToken);

      // Refresh token is NEVER returned in JSON response body
      res.status(200).json({
        success: true,
        message: 'Token refreshed successfully',
        accessToken: result.accessToken,
        csrfToken: result.csrfToken,
        user: result.user,
      });
    } catch (err: any) {
      clearAuthCookies(res);
      const status = err.statusCode || 401;
      res.status(status).json({
        success: false,
        code: err.code || 'REFRESH_FAILED',
        message: err.message || 'Failed to refresh token',
      });
    }
  });

  // POST /api/v1/auth/token/refresh (Explicit non-browser programmatic / CLI refresh endpoint)
  router.post('/token/refresh', async (req: Request, res: Response) => {
    const clientType = req.headers['x-client-type'];
    if (!clientType || (clientType !== 'non-browser' && clientType !== 'cli')) {
      res.status(400).json({
        success: false,
        code: 'INVALID_CLIENT_TYPE',
        message: 'This endpoint is strictly for non-browser clients. Header X-Client-Type: non-browser required.',
      });
      return;
    }

    const { refreshToken: rawRefreshToken } = req.body || {};
    if (!rawRefreshToken || typeof rawRefreshToken !== 'string') {
      res.status(400).json({
        success: false,
        code: 'MISSING_REFRESH_TOKEN',
        message: 'refreshToken is required in JSON body',
      });
      return;
    }

    try {
      const clientIp = typeof req.ip === 'string' ? req.ip : req.socket.remoteAddress;
      const userAgent = typeof req.headers['user-agent'] === 'string' ? req.headers['user-agent'] : undefined;
      const ctx = { ip: clientIp, userAgent };

      const result = await authService.refresh(rawRefreshToken, ctx);

      res.status(200).json({
        success: true,
        message: 'Token refreshed successfully',
        accessToken: result.accessToken,
        refreshToken: result.refreshToken,
        user: result.user,
      });
    } catch (err: any) {
      const status = err.statusCode || 401;
      res.status(status).json({
        success: false,
        code: err.code || 'REFRESH_FAILED',
        message: err.message || 'Failed to refresh token',
      });
    }
  });

  // POST /api/v1/auth/logout (Browser flow: cookie-based with CSRF and Origin protection)
  router.post('/logout', async (req: Request, res: Response) => {
    if (!verifyOrigin(req)) {
      res.status(403).json({
        success: false,
        code: 'FORBIDDEN_ORIGIN',
        message: 'Request origin is not authorized.',
      });
      return;
    }

    if (!verifyCsrfToken(req)) {
      res.status(403).json({
        success: false,
        code: 'CSRF_VALIDATION_FAILED',
        message: 'CSRF token missing or mismatch. Pass matching X-CSRF-Token header.',
      });
      return;
    }

    const rawRefreshToken = extractCookieRefreshToken(req);

    try {
      const clientIp = typeof req.ip === 'string' ? req.ip : req.socket.remoteAddress;
      const userAgent = typeof req.headers['user-agent'] === 'string' ? req.headers['user-agent'] : undefined;
      const ctx: { ip?: string | undefined; userAgent?: string | undefined } = {
        ip: clientIp,
        userAgent,
      };

      await authService.logout(rawRefreshToken, ctx);
    } catch {
      // Ignore errors on logout
    } finally {
      clearAuthCookies(res);
      res.status(200).json({
        success: true,
        message: 'Logout successful',
      });
    }
  });

  // GET /api/v1/auth/me
  router.get('/me', authenticateUser(authService), async (req: Request, res: Response) => {
    if (!req.user) {
      res.status(401).json({ success: false, code: 'UNAUTHORIZED', message: 'Authentication required' });
      return;
    }

    try {
      const me = await authService.getMe(req.user.sub);
      res.status(200).json({
        success: true,
        user: me,
      });
    } catch (err: any) {
      const status = err.statusCode || 500;
      res.status(status).json({
        success: false,
        code: err.code || 'INTERNAL_ERROR',
        message: err.message,
      });
    }
  });

  return router;
}
