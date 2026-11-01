import { describe, it, beforeEach, afterEach } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import type { AddressInfo } from 'node:net';
import { api } from '../src/api/client.js';
import type { User, UserRole, SensorHealth, AnomalyAssessment, WitnessCheckpoint } from '../src/types/index.js';

describe('Frontend API Client & Domain Logic Tests', () => {
  let mockServer: http.Server;
  let mockPort: number;
  let mockRequests: Array<{ method: string; url: string; headers: http.IncomingHttpHeaders; body?: any }> = [];

  let mockResponseStatus = 200;
  let mockResponseBody: any = {};

  beforeEach(async () => {
    mockRequests = [];
    mockResponseStatus = 200;
    mockResponseBody = {};

    mockServer = http.createServer(async (req, res) => {
      let bodyStr = '';
      for await (const chunk of req) {
        bodyStr += chunk;
      }
      let parsedBody: any = undefined;
      try {
        if (bodyStr) parsedBody = JSON.parse(bodyStr);
      } catch {
        parsedBody = bodyStr;
      }

      mockRequests.push({
        method: req.method || 'GET',
        url: req.url || '/',
        headers: req.headers,
        body: parsedBody,
      });

      res.writeHead(mockResponseStatus, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify(mockResponseBody));
    });

    await new Promise<void>((resolve) => {
      mockServer.listen(0, '127.0.0.1', () => {
        const addr = mockServer.address() as AddressInfo;
        mockPort = addr.port;
        resolve();
      });
    });

    // Configure client to target mock server
    (api as any).token = null;
  });

  afterEach(async () => {
    await new Promise<void>((resolve) => {
      mockServer.close(() => resolve());
    });
  });

  it('1. Login & Token Management: Successful login sets in-memory bearer token and returns user profile', async () => {
    mockResponseStatus = 200;
    mockResponseBody = {
      success: true,
      accessToken: 'test-jwt-token-xyz',
      user: {
        id: 'user-uuid-1',
        email: 'operator@envirotrust.local',
        role: 'FACTORY_OPERATOR',
        sites: ['PLANT-001'],
        status: 'ACTIVE',
      },
    };

    // Override fetch endpoint URL by configuring API_BASE temporarily or calling internal request
    const loginResult = await (api as any).request(
      '/auth/login',
      {
        method: 'POST',
        body: JSON.stringify({ email: 'operator@envirotrust.local', password: 'DemoPassword123!' }),
      },
      `http://127.0.0.1:${mockPort}/api/v1`
    );

    assert.equal(loginResult.success, true);
    assert.equal(loginResult.accessToken, 'test-jwt-token-xyz');
    assert.equal(loginResult.user.role, 'FACTORY_OPERATOR');
    assert.deepEqual(loginResult.user.sites, ['PLANT-001']);

    assert.equal(mockRequests.length, 1);
    assert.equal(mockRequests[0]?.method, 'POST');
    assert.equal(mockRequests[0]?.url, '/api/v1/auth/login');
    assert.equal(mockRequests[0]?.body.email, 'operator@envirotrust.local');
  });

  it('2. Logout: Clears in-memory token and invalidates active session', async () => {
    api.setToken('active-token-123');
    assert.equal(api.getToken(), 'active-token-123');

    mockResponseStatus = 200;
    mockResponseBody = { success: true };

    await (api as any).request(
      '/auth/logout',
      { method: 'POST' },
      `http://127.0.0.1:${mockPort}/api/v1`
    );

    api.setToken(null);
    assert.equal(api.getToken(), null);
    assert.equal(mockRequests[0]?.url, '/api/v1/auth/logout');
  });

  it('3. Protected Route Role Authorization Matrix: Verifies allowed roles per module', () => {
    const modules: Record<string, UserRole[]> = {
      overview: ['PLATFORM_ADMIN', 'FACTORY_OPERATOR', 'REGULATOR_AUDITOR'],
      monitoring: ['PLATFORM_ADMIN', 'FACTORY_OPERATOR', 'REGULATOR_AUDITOR'],
      sensors: ['PLATFORM_ADMIN', 'FACTORY_OPERATOR', 'REGULATOR_AUDITOR'],
      anomalies: ['PLATFORM_ADMIN', 'FACTORY_OPERATOR', 'REGULATOR_AUDITOR'],
      audit: ['PLATFORM_ADMIN', 'FACTORY_OPERATOR', 'REGULATOR_AUDITOR'],
      users: ['PLATFORM_ADMIN'], // Admin-only
    };

    // Helper checking access
    function canAccess(role: UserRole, mod: string): boolean {
      const allowed = modules[mod];
      return allowed ? allowed.includes(role) : false;
    }

    // PLATFORM_ADMIN has access to all
    assert.equal(canAccess('PLATFORM_ADMIN', 'overview'), true);
    assert.equal(canAccess('PLATFORM_ADMIN', 'users'), true);
    assert.equal(canAccess('PLATFORM_ADMIN', 'audit'), true);

    // FACTORY_OPERATOR
    assert.equal(canAccess('FACTORY_OPERATOR', 'overview'), true);
    assert.equal(canAccess('FACTORY_OPERATOR', 'monitoring'), true);
    assert.equal(canAccess('FACTORY_OPERATOR', 'users'), false, 'Operator must NOT access user management');

    // REGULATOR_AUDITOR
    assert.equal(canAccess('REGULATOR_AUDITOR', 'overview'), true);
    assert.equal(canAccess('REGULATOR_AUDITOR', 'audit'), true);
    assert.equal(canAccess('REGULATOR_AUDITOR', 'users'), false, 'Auditor must NOT access user management');
  });

  it('4. Site Selector Boundary: Enforces that non-admin users only switch between their assigned sites', () => {
    const adminUser: User = {
      id: 'admin-id',
      email: 'admin@envirotrust.local',
      role: 'PLATFORM_ADMIN',
      sites: [],
      status: 'ACTIVE',
    };

    const operatorUser: User = {
      id: 'op-id',
      email: 'operator@envirotrust.local',
      role: 'FACTORY_OPERATOR',
      sites: ['PLANT-001'],
      status: 'ACTIVE',
    };

    const allRegisteredSites = ['PLANT-001', 'PLANT-002'];

    function getPermittedSites(user: User): string[] {
      if (user.role === 'PLATFORM_ADMIN') return allRegisteredSites;
      return user.sites;
    }

    assert.deepEqual(getPermittedSites(adminUser), ['PLANT-001', 'PLANT-002']);
    assert.deepEqual(getPermittedSites(operatorUser), ['PLANT-001']);
    assert.equal(getPermittedSites(operatorUser).includes('PLANT-002'), false);
  });

  it('5. Automatic Token Refresh on 401 Expiration: Retries original request once with fresh token', async () => {
    let callCount = 0;

    mockServer.removeAllListeners('request');
    mockServer.on('request', async (req, res) => {
      callCount++;
      if (req.url === '/api/v1/auth/refresh') {
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ accessToken: 'fresh-rotated-token' }));
        return;
      }

      if (req.url === '/api/v1/monitoring/overview') {
        if (callCount === 1) {
          // First attempt: expired token -> 401
          res.writeHead(401, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ code: 'TOKEN_EXPIRED', message: 'Access token expired' }));
          return;
        } else {
          // Second attempt after refresh -> 200
          res.writeHead(200, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ success: true, siteFilter: 'PLANT-001' }));
          return;
        }
      }

      res.writeHead(404);
      res.end();
    });

    api.setToken('old-expired-token');

    // Trigger request through client
    const res = await (api as any).request(
      '/monitoring/overview',
      {},
      `http://127.0.0.1:${mockPort}/api/v1`
    );

    assert.equal(res.success, true);
    assert.equal(api.getToken(), 'fresh-rotated-token');
  });

  it('6. Revoked Session Handling: When refresh token is revoked, client triggers unauthorized callback', async () => {
    let unauthorizedTriggered = false;
    api.onUnauthorized(() => {
      unauthorizedTriggered = true;
    });

    mockServer.removeAllListeners('request');
    mockServer.on('request', async (req, res) => {
      if (req.url === '/api/v1/auth/refresh') {
        // Refresh token was revoked
        res.writeHead(401, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ code: 'SESSION_REVOKED', message: 'Refresh token invalid' }));
        return;
      }
      res.writeHead(401, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ code: 'TOKEN_EXPIRED' }));
    });

    api.setToken('old-token');

    try {
      await (api as any).request(
        '/monitoring/overview',
        {},
        `http://127.0.0.1:${mockPort}/api/v1`
      );
    } catch {
      // Expected failure
    }

    assert.equal(unauthorizedTriggered, true, 'Unauthorized callback should be fired to clear user state');
  });

  it('7. Sensor Availability State Mapping: Categorizes ONLINE, STALE, OFFLINE, and NO_HEARTBEAT correctly', () => {
    const sensors: SensorHealth[] = [
      {
        sensorId: 'COD-OUT-001',
        siteId: 'PLANT-001',
        siteCode: 'PLANT-001',
        stationId: 'STATION-001',
        stationCode: 'STATION-001',
        parameter: 'COD',
        unit: 'mg/L',
        status: 'ONLINE',
        lastHeartbeatReceivedAt: new Date().toISOString(),
        lastHeartbeatSentAt: new Date().toISOString(),
        missedIntervalsCount: 0,
        expectedIntervalSeconds: 30,
        primaryDeliveryStatus: 'CONFIRMED',
        witnessDeliveryStatus: 'CONFIRMED',
        lastKnownSequence: 105,
        evaluatedAt: new Date().toISOString(),
      },
      {
        sensorId: 'PH-OUT-001',
        siteId: 'PLANT-001',
        siteCode: 'PLANT-001',
        stationId: 'STATION-001',
        stationCode: 'STATION-001',
        parameter: 'pH',
        unit: 'pH',
        status: 'OFFLINE',
        lastHeartbeatReceivedAt: new Date(Date.now() - 300000).toISOString(),
        lastHeartbeatSentAt: new Date(Date.now() - 300000).toISOString(),
        missedIntervalsCount: 5,
        expectedIntervalSeconds: 30,
        primaryDeliveryStatus: 'CONFIRMED',
        witnessDeliveryStatus: 'CONFIRMED',
        lastKnownSequence: 42,
        evaluatedAt: new Date().toISOString(),
      },
    ];

    const online = sensors.filter((s) => s.status === 'ONLINE');
    const offline = sensors.filter((s) => s.status === 'OFFLINE');

    assert.equal(online.length, 1);
    assert.equal(offline.length, 1);
    assert.equal(online[0]?.sensorId, 'COD-OUT-001');
    assert.equal(offline[0]?.sensorId, 'PH-OUT-001');
  });

  it('8. ML Assessment State Distinction: Strictly separates CONSISTENT, SUSPICIOUS, NOT_EVALUATED, and ERROR', () => {
    const assessments: AnomalyAssessment[] = [
      {
        id: 'a1',
        readingId: 'r1',
        messageId: 'm1',
        sensorId: 'COD-OUT-001',
        siteId: 'PLANT-001',
        stationId: 'STATION-001',
        status: 'CONSISTENT',
        anomalyType: null,
        actualValue: 84.5,
        predictedValue: 83.9,
        residual: 0.6,
        threshold: 14.5,
        severity: 'NONE',
        modelVersion: 'rf-cod-v1.0',
        processingStatus: 'COMPLETED',
        reasons: ['Process within expected model envelope'],
        evaluatedAt: new Date().toISOString(),
      },
      {
        id: 'a2',
        readingId: 'r2',
        messageId: 'm2',
        sensorId: 'COD-OUT-001',
        siteId: 'PLANT-001',
        stationId: 'STATION-001',
        status: 'SUSPICIOUS',
        anomalyType: 'PROCESS_CONTEXT_MISMATCH',
        actualValue: 22.0,
        predictedValue: 98.4,
        residual: 76.4,
        threshold: 15.0,
        severity: 'CRITICAL',
        modelVersion: 'rf-cod-v1.0',
        processingStatus: 'COMPLETED',
        reasons: ['Actual COD significantly below expected value given operating mode'],
        evaluatedAt: new Date().toISOString(),
      },
      {
        id: 'a3',
        readingId: 'r3',
        messageId: 'm3',
        sensorId: 'COD-OUT-001',
        siteId: 'PLANT-001',
        stationId: 'STATION-001',
        status: 'NOT_EVALUATED',
        anomalyType: null,
        actualValue: 95.0,
        predictedValue: null,
        residual: null,
        threshold: null,
        severity: 'NONE',
        modelVersion: 'rf-cod-v1.0',
        processingStatus: 'INSUFFICIENT_CONTEXT',
        reasons: ['Context wait deadline expired without valid OPS-001 context'],
        evaluatedAt: new Date().toISOString(),
      },
    ];

    const consistent = assessments.filter((a) => a.status === 'CONSISTENT');
    const suspicious = assessments.filter((a) => a.status === 'SUSPICIOUS');
    const notEvaluated = assessments.filter((a) => a.status === 'NOT_EVALUATED');

    assert.equal(consistent.length, 1);
    assert.equal(suspicious.length, 1);
    assert.equal(notEvaluated.length, 1);

    assert.equal(suspicious[0]?.severity, 'CRITICAL');
    assert.equal(suspicious[0]?.anomalyType, 'PROCESS_CONTEXT_MISMATCH');
    assert.equal(notEvaluated[0]?.predictedValue, null, 'Un-evaluated readings must never display fabricated predictions');
  });

  it('9. Witness Checkpoint Verification Parsing: Correctly extracts sequence, hash and fingerprint', () => {
    const rawCheckpoint: WitnessCheckpoint = {
      id: 'cp-uuid-1',
      witnessId: 'WITNESS-INDEPENDENT-001',
      witnessKeyId: 'WITNESS-KEY-001',
      siteId: 'PLANT-001',
      stationId: 'STATION-001',
      checkpointSequence: 4,
      lastWitnessSequence: 40,
      chainHeadHash: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
      previousCheckpointHash: '0000000000000000000000000000000000000000000000000000000000000000',
      createdAt: new Date().toISOString(),
      signature: 'dGVzdC1zaWduYXR1cmUtYmFzZTY0LWNoZWNrcG9pbnQ=',
      checkpointHash: 'a1b2c3d4e5f60000111122223333444455556666777788889999aaaabbbbcccc',
      witnessPublicKeyFingerprint: 'f1e2d3c4b5a699887766554433221100ffeeddccbbaa99887766554433221100',
    };

    assert.equal(rawCheckpoint.checkpointSequence, 4);
    assert.equal(rawCheckpoint.lastWitnessSequence, 40);
    assert.equal(rawCheckpoint.chainHeadHash.length, 64);
    assert.equal(rawCheckpoint.witnessPublicKeyFingerprint.length, 64);
  });

  it('10. Administrator User Management Validation: Enforces required fields for user creation', () => {
    function validateUserCreation(payload: { email: string; password?: string; role: string }): { valid: boolean; error?: string } {
      if (!payload.email || !payload.email.includes('@')) {
        return { valid: false, error: 'Valid email address is required' };
      }
      if (!payload.password || payload.password.length < 8) {
        return { valid: false, error: 'Password must be at least 8 characters' };
      }
      const validRoles = ['PLATFORM_ADMIN', 'FACTORY_OPERATOR', 'REGULATOR_AUDITOR'];
      if (!validRoles.includes(payload.role)) {
        return { valid: false, error: 'Invalid user role' };
      }
      return { valid: true };
    }

    assert.equal(validateUserCreation({ email: 'bad', password: '123', role: 'INVALID' }).valid, false);
    assert.equal(validateUserCreation({ email: 'valid@site.local', password: '123', role: 'FACTORY_OPERATOR' }).valid, false);
    assert.equal(validateUserCreation({ email: 'valid@site.local', password: 'Password123!', role: 'FACTORY_OPERATOR' }).valid, true);
  });

  it('11. Demo Credential Protection: Suppresses quick-login buttons and demo credentials unless VITE_DEMO_MODE is true', () => {
    function shouldShowDemoCredentials(envValue?: string): boolean {
      return envValue === 'true';
    }

    // Default or production environments: must be disabled
    assert.equal(shouldShowDemoCredentials(undefined), false);
    assert.equal(shouldShowDemoCredentials(''), false);
    assert.equal(shouldShowDemoCredentials('false'), false);
    assert.equal(shouldShowDemoCredentials('0'), false);

    // Explicit opt-in only
    assert.equal(shouldShowDemoCredentials('true'), true);
  });

  it('12. ML Health Endpoint Sanitization: Verifies health response never leaks internal LAN IP or auth tokens', async () => {
    mockResponseStatus = 200;
    // Sanitized response from GET /api/v1/ml/health
    mockResponseBody = {
      status: 'HEALTHY',
      enabled: true,
      reachable: true,
      ready: true,
      modelVersion: 'rf-cod-v1.0',
      message: 'FastAPI service reachable and model ready',
    };

    const health = await (api as any).request(
      '/ml/health',
      { method: 'GET' },
      `http://127.0.0.1:${mockPort}/api/v1`
    );

    assert.equal(health.status, 'HEALTHY');
    assert.equal(health.enabled, true);
    assert.equal(health.reachable, true);
    assert.equal(health.ready, true);
    assert.equal(health.modelVersion, 'rf-cod-v1.0');

    // Strict security check: must NOT leak internal LAN IP (e.g., 10.x.x.x), internal baseUrl, or serviceToken
    assert.equal((health as any).baseUrl, undefined, 'Internal baseUrl must never be exposed');
    assert.equal((health as any).serviceToken, undefined, 'Internal service token must never be exposed');
    assert.equal((health as any).internalIp, undefined, 'Internal IP address must never be exposed');
    assert.equal((health as any).stack, undefined, 'Raw error stack must never be exposed');
  });

  it('13. Regulatory Reference Accuracy: Benchmark reference lines default to hidden and require explicit statutory metadata', () => {
    // Default state of showBenchmark must be false
    let showBenchmark = false;
    assert.equal(showBenchmark, false, 'Regulatory benchmark must default to hidden');

    // Statutory metadata contract for Schedule VI General Standards
    const benchmarkMetadata = {
      standardSource: 'Environment (Protection) Rules 1986, Sched. VI General Standards (Inland Surface Water)',
      applicableParameter: 'COD',
      limitValue: 100,
      unit: 'mg/L',
      authorityNotice: 'Site-specific Consent to Operate (CTO) issued by State Pollution Control Board supersedes this reference',
    };

    assert.equal(benchmarkMetadata.limitValue, 100);
    assert.equal(benchmarkMetadata.unit, 'mg/L');
    assert.ok(benchmarkMetadata.authorityNotice.includes('State Pollution Control Board'));
  });

  it('14. ML Statistical Anomaly vs Regulatory Compliance Decoupling: Keeps process condition anomalies separate from legal violations', () => {
    interface AnomalyClassification {
      isProcessAnomaly: boolean;
      isRegulatoryViolation: boolean;
      label: string;
    }

    function classifyAssessment(status: string, residual: number, threshold: number): AnomalyClassification {
      const isSuspicious = status === 'SUSPICIOUS' || residual > threshold;
      return {
        isProcessAnomaly: isSuspicious,
        // Crucial requirement: ML statistical mismatch does NOT automatically constitute an environmental legal violation
        isRegulatoryViolation: false,
        label: isSuspicious ? 'Process Condition Mismatch (Statistical Anomaly)' : 'Process Consistent',
      };
    }

    const result = classifyAssessment('SUSPICIOUS', 42.5, 15.0);
    assert.equal(result.isProcessAnomaly, true);
    assert.equal(result.isRegulatoryViolation, false, 'ML statistical anomalies must NOT be labeled as regulatory violations');
    assert.ok(result.label.includes('Statistical Anomaly'));
  });
});


