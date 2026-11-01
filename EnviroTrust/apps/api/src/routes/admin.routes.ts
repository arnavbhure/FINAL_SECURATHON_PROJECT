import { Router, type Request, type Response } from 'express';
import type { AuthService } from '../services/auth.service.js';
import { authenticateUser, requireRoles } from '../middleware/auth.middleware.js';
import type { UserRole, UserStatus } from '../repositories/user.repository.js';

export function createAdminRouter(authService: AuthService): Router {
  const router = Router();

  // All administrative routes strictly require PLATFORM_ADMIN role
  router.use(authenticateUser(authService));
  router.use(requireRoles('PLATFORM_ADMIN'));

  // GET /api/v1/admin/users - List all users
  router.get('/users', async (_req: Request, res: Response) => {
    try {
      const users = await authService.listUsers();
      res.status(200).json({
        success: true,
        count: users.length,
        users,
      });
    } catch (err: any) {
      res.status(500).json({
        success: false,
        code: 'INTERNAL_ERROR',
        message: err.message,
      });
    }
  });

  // POST /api/v1/admin/users - Create a new human user
  router.post('/users', async (req: Request, res: Response) => {
    const { fullName, email, password, role, sites } = req.body || {};

    if (!fullName || typeof fullName !== 'string' || !email || typeof email !== 'string' || !password || typeof password !== 'string' || !role) {
      res.status(400).json({
        success: false,
        code: 'MISSING_REQUIRED_FIELDS',
        message: 'fullName, email, password, and role are required',
      });
      return;
    }

    try {
      const clientIp = typeof req.ip === 'string' ? req.ip : req.socket.remoteAddress;
      const userAgent = typeof req.headers['user-agent'] === 'string' ? req.headers['user-agent'] : undefined;
      const ctx = { ip: clientIp, userAgent };

      const user = await authService.createUser(
        req.user!,
        {
          fullName,
          email,
          password,
          role: role as UserRole,
          sites: Array.isArray(sites) ? sites : [],
        },
        ctx
      );

      res.status(201).json({
        success: true,
        message: 'User created successfully',
        user,
      });
    } catch (err: any) {
      const status = err.statusCode || 500;
      res.status(status).json({
        success: false,
        code: err.code || 'USER_CREATION_FAILED',
        message: err.message,
      });
    }
  });

  // PATCH /api/v1/admin/users/:userId/status - Enable or disable an account
  router.patch('/users/:userId/status', async (req: Request, res: Response) => {
    const rawUserId = req.params['userId'];
    const userId = Array.isArray(rawUserId) ? rawUserId[0] : rawUserId;
    const { status } = req.body || {};

    if (!userId) {
      res.status(400).json({ success: false, code: 'INVALID_PARAMETER', message: 'userId is required' });
      return;
    }

    if (status !== 'ACTIVE' && status !== 'DISABLED') {
      res.status(400).json({
        success: false,
        code: 'INVALID_STATUS',
        message: 'status must be ACTIVE or DISABLED',
      });
      return;
    }

    try {
      const clientIp = typeof req.ip === 'string' ? req.ip : req.socket.remoteAddress;
      const userAgent = typeof req.headers['user-agent'] === 'string' ? req.headers['user-agent'] : undefined;
      const ctx = { ip: clientIp, userAgent };

      const result = await authService.setUserStatus(req.user!, userId, status as UserStatus, ctx);

      res.status(200).json({
        success: true,
        message: `User status updated to ${status}`,
        user: result,
      });
    } catch (err: any) {
      const statusCode = err.statusCode || 500;
      res.status(statusCode).json({
        success: false,
        code: err.code || 'STATUS_UPDATE_FAILED',
        message: err.message,
      });
    }
  });

  // PATCH /api/v1/admin/users/:userId/role - Change user role
  router.patch('/users/:userId/role', async (req: Request, res: Response) => {
    const rawUserId = req.params['userId'];
    const userId = Array.isArray(rawUserId) ? rawUserId[0] : rawUserId;
    const { role } = req.body || {};

    if (!userId) {
      res.status(400).json({ success: false, code: 'INVALID_PARAMETER', message: 'userId is required' });
      return;
    }

    const validRoles: UserRole[] = ['PLATFORM_ADMIN', 'FACTORY_OPERATOR', 'REGULATOR_AUDITOR'];
    if (!validRoles.includes(role)) {
      res.status(400).json({
        success: false,
        code: 'INVALID_ROLE',
        message: `role must be one of: ${validRoles.join(', ')}`,
      });
      return;
    }

    try {
      const clientIp = typeof req.ip === 'string' ? req.ip : req.socket.remoteAddress;
      const userAgent = typeof req.headers['user-agent'] === 'string' ? req.headers['user-agent'] : undefined;
      const ctx = { ip: clientIp, userAgent };

      const result = await authService.setUserRole(req.user!, userId, role as UserRole, ctx);

      res.status(200).json({
        success: true,
        message: `User role updated to ${role}`,
        user: result,
      });
    } catch (err: any) {
      const statusCode = err.statusCode || 500;
      res.status(statusCode).json({
        success: false,
        code: err.code || 'ROLE_UPDATE_FAILED',
        message: err.message,
      });
    }
  });

  // POST /api/v1/admin/users/:userId/sites - Assign a site membership
  router.post('/users/:userId/sites', async (req: Request, res: Response) => {
    const rawUserId = req.params['userId'];
    const userId = Array.isArray(rawUserId) ? rawUserId[0] : rawUserId;
    const { siteCode } = req.body || {};

    if (!userId || !siteCode || typeof siteCode !== 'string') {
      res.status(400).json({
        success: false,
        code: 'MISSING_REQUIRED_FIELDS',
        message: 'userId parameter and siteCode in body are required',
      });
      return;
    }

    try {
      const clientIp = typeof req.ip === 'string' ? req.ip : req.socket.remoteAddress;
      const userAgent = typeof req.headers['user-agent'] === 'string' ? req.headers['user-agent'] : undefined;
      const ctx = { ip: clientIp, userAgent };

      const result = await authService.addUserSite(req.user!, userId, siteCode.trim(), ctx);

      res.status(200).json({
        success: true,
        message: `Site '${siteCode}' assigned to user`,
        user: result,
      });
    } catch (err: any) {
      const statusCode = err.statusCode || 500;
      res.status(statusCode).json({
        success: false,
        code: err.code || 'SITE_ASSIGNMENT_FAILED',
        message: err.message,
      });
    }
  });

  // DELETE /api/v1/admin/users/:userId/sites/:siteCode - Revoke site membership
  router.delete('/users/:userId/sites/:siteCode', async (req: Request, res: Response) => {
    const rawUserId = req.params['userId'];
    const userId = Array.isArray(rawUserId) ? rawUserId[0] : rawUserId;
    const rawSiteCode = req.params['siteCode'];
    const siteCode = Array.isArray(rawSiteCode) ? rawSiteCode[0] : rawSiteCode;

    if (!userId || !siteCode) {
      res.status(400).json({
        success: false,
        code: 'MISSING_REQUIRED_FIELDS',
        message: 'userId and siteCode parameters are required',
      });
      return;
    }

    try {
      const clientIp = typeof req.ip === 'string' ? req.ip : req.socket.remoteAddress;
      const userAgent = typeof req.headers['user-agent'] === 'string' ? req.headers['user-agent'] : undefined;
      const ctx = { ip: clientIp, userAgent };

      const result = await authService.removeUserSite(req.user!, userId, siteCode.trim(), ctx);

      res.status(200).json({
        success: true,
        message: `Site '${siteCode}' removed from user`,
        user: result,
      });
    } catch (err: any) {
      const statusCode = err.statusCode || 500;
      res.status(statusCode).json({
        success: false,
        code: err.code || 'SITE_REMOVAL_FAILED',
        message: err.message,
      });
    }
  });

  // GET /api/v1/admin/audit-events - Query administrative and authentication audit records
  router.get('/audit-events', async (req: Request, res: Response) => {
    try {
      const limit = req.query['limit'] ? parseInt(req.query['limit'] as string, 10) : 50;
      const offset = req.query['offset'] ? parseInt(req.query['offset'] as string, 10) : 0;
      const action = req.query['action'] as string | undefined;
      const userId = req.query['userId'] as string | undefined;

      const events = await authService.queryAuditEvents({ limit, offset, action, userId });

      res.status(200).json({
        success: true,
        count: events.length,
        events,
      });
    } catch (err: any) {
      res.status(500).json({
        success: false,
        code: 'AUDIT_QUERY_FAILED',
        message: err.message,
      });
    }
  });

  return router;
}

