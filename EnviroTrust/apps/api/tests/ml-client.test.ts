import { describe, it, before, after } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import { MlClient, MlClientError } from '../src/services/ml-client.js';
import type { MlAnalysisRequest } from '@envirotrust/contracts';

describe('ML Client — FastAPI HTTP Transport & Contract Validation Tests', () => {
  let mockServer: http.Server;
  let serverPort: number;
  let lastAuthHeader: string | undefined;
  let lastRequestBody: unknown;
  let mockResponseStatus = 200;
  let mockResponseBody: unknown;
  let mockDelayMs = 0;

  before(async () => {
    mockServer = http.createServer(async (req, res) => {
      lastAuthHeader = req.headers['authorization'];
      let bodyStr = '';
      for await (const chunk of req) {
        bodyStr += chunk;
      }
      try {
        lastRequestBody = bodyStr ? JSON.parse(bodyStr) : undefined;
      } catch {
        lastRequestBody = bodyStr;
      }

      if (mockDelayMs > 0) {
        await new Promise((resolve) => setTimeout(resolve, mockDelayMs));
      }

      if (req.url === '/ml/v1/health' && req.method === 'GET') {
        res.writeHead(mockResponseStatus, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify(mockResponseBody));
        return;
      }

      if (req.url === '/ml/v1/analyze/cod' && req.method === 'POST') {
        res.writeHead(mockResponseStatus, { 'Content-Type': 'application/json' });
        if (typeof mockResponseBody === 'string') {
          res.end(mockResponseBody);
        } else {
          res.end(JSON.stringify(mockResponseBody));
        }
        return;
      }

      res.writeHead(404, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: 'Not found' }));
    });

    await new Promise<void>((resolve) => {
      mockServer.listen(0, '127.0.0.1', () => {
        const addr = mockServer.address() as { port: number };
        serverPort = addr.port;
        resolve();
      });
    });
  });

  after(async () => {
    await new Promise<void>((resolve) => {
      mockServer.close(() => resolve());
    });
  });

  const validRequest: MlAnalysisRequest = {
    readingId: 'a1b2c3d4-1111-2222-3333-444455556666',
    siteId: 'PLANT-001',
    stationId: 'STATION-001',
    sensorId: 'COD-OUT-001',
    actualCod: 85.5,
    measuredAt: new Date().toISOString(),
    contextVerified: true,
    context: {
      productionRate: 450.0,
      wastewaterFlow: 12000.0,
      treatmentDose: 35.0,
      energyConsumption: 520.0,
      operatingMode: 'NORMAL',
    },
    recentCodReadings: [82.0, 83.5, 84.0, 85.5],
  };

  it('1. GET /ml/v1/health returns reachable and model readiness', async () => {
    mockResponseStatus = 200;
    mockResponseBody = { status: 'ok', ready: true, modelVersion: 'rf-cod-v1.0' };
    mockDelayMs = 0;

    const client = new MlClient({
      baseUrl: `http://127.0.0.1:${serverPort}`,
      timeoutMs: 2000,
      serviceToken: 'test-service-token-123',
    });

    const health = await client.healthCheck();
    assert.equal(health.reachable, true);
    assert.equal(health.ready, true);
    assert.equal(health.modelVersion, 'rf-cod-v1.0');
    assert.equal(lastAuthHeader, 'Bearer test-service-token-123');
  });

  it('2. GET /ml/v1/health reports unreachable when service returns 500 error', async () => {
    mockResponseStatus = 500;
    mockResponseBody = { error: 'Internal failure' };

    const client = new MlClient({
      baseUrl: `http://127.0.0.1:${serverPort}`,
      timeoutMs: 2000,
    });

    const health = await client.healthCheck();
    assert.equal(health.reachable, false);
    assert.match(health.error || '', /HTTP 500/);
  });

  it('3. POST /ml/v1/analyze/cod successfully validates and returns schema-compliant ML result', async () => {
    mockResponseStatus = 200;
    mockResponseBody = {
      readingId: validRequest.readingId,
      status: 'CONSISTENT',
      anomalyType: null,
      actualCod: 85.5,
      predictedCod: 84.8,
      absoluteResidual: 0.7,
      residualThreshold: 15.0,
      modelVersion: 'rf-cod-v1.0',
      reasons: ['Residual 0.70 is within normal threshold of 15.00'],
      evaluatedAt: new Date().toISOString(),
    };

    const client = new MlClient({
      baseUrl: `http://127.0.0.1:${serverPort}`,
      timeoutMs: 2000,
      serviceToken: 'token-secret-xyz',
    });

    const result = await client.analyzeCod(validRequest);
    assert.equal(result.status, 'CONSISTENT');
    assert.equal(result.readingId, validRequest.readingId);
    assert.equal(result.predictedCod, 84.8);
    assert.equal(result.absoluteResidual, 0.7);
    assert.equal(lastAuthHeader, 'Bearer token-secret-xyz');
    assert.deepEqual(lastRequestBody, validRequest);
  });

  it('4. Rejects outgoing request that violates canonical JSON schema (e.g. missing context)', async () => {
    const client = new MlClient({
      baseUrl: `http://127.0.0.1:${serverPort}`,
    });

    const invalidReq = { ...validRequest, context: undefined } as unknown as MlAnalysisRequest;

    await assert.rejects(
      async () => client.analyzeCod(invalidReq),
      (err: Error) => {
        assert(err instanceof MlClientError);
        assert.equal(err.code, 'ML_INVALID_REQUEST');
        return true;
      }
    );
  });

  it('5. Rejects incoming response that violates canonical result schema (e.g. missing required modelVersion)', async () => {
    mockResponseStatus = 200;
    mockResponseBody = {
      readingId: validRequest.readingId,
      status: 'CONSISTENT',
      // Missing modelVersion, reasons, evaluatedAt
    };

    const client = new MlClient({
      baseUrl: `http://127.0.0.1:${serverPort}`,
    });

    await assert.rejects(
      async () => client.analyzeCod(validRequest),
      (err: Error) => {
        assert(err instanceof MlClientError);
        assert.equal(err.code, 'ML_INVALID_RESPONSE');
        return true;
      }
    );
  });

  it('6. Rejects malformed non-JSON response from FastAPI', async () => {
    mockResponseStatus = 200;
    mockResponseBody = '<html><body>Bad Gateway</body></html>';

    const client = new MlClient({
      baseUrl: `http://127.0.0.1:${serverPort}`,
    });

    await assert.rejects(
      async () => client.analyzeCod(validRequest),
      (err: Error) => {
        assert(err instanceof MlClientError);
        assert.equal(err.code, 'ML_INVALID_RESPONSE');
        assert.match(err.message, /malformed non-JSON/);
        return true;
      }
    );
  });

  it('7. Handles request timeout when ML service takes longer than ML_TIMEOUT_MS', async () => {
    mockDelayMs = 200;
    mockResponseStatus = 200;
    mockResponseBody = {
      readingId: validRequest.readingId,
      status: 'CONSISTENT',
      anomalyType: null,
      actualCod: 85.5,
      predictedCod: 85.0,
      absoluteResidual: 0.5,
      residualThreshold: 15.0,
      modelVersion: 'rf-cod-v1.0',
      reasons: [],
      evaluatedAt: new Date().toISOString(),
    };

    const client = new MlClient({
      baseUrl: `http://127.0.0.1:${serverPort}`,
      timeoutMs: 50, // Short timeout to trigger abort
    });

    await assert.rejects(
      async () => client.analyzeCod(validRequest),
      (err: Error) => {
        assert(err instanceof MlClientError);
        assert.equal(err.code, 'ML_TIMEOUT');
        return true;
      }
    );

    mockDelayMs = 0;
  });

  it('8. Handles HTTP 401 Unauthorized when service token is rejected by ML service', async () => {
    mockResponseStatus = 401;
    mockResponseBody = { detail: 'Invalid or missing service token' };

    const client = new MlClient({
      baseUrl: `http://127.0.0.1:${serverPort}`,
      serviceToken: 'wrong-token',
    });

    await assert.rejects(
      async () => client.analyzeCod(validRequest),
      (err: Error) => {
        assert(err instanceof MlClientError);
        assert.equal(err.code, 'ML_HTTP_ERROR');
        assert.equal(err.status, 401);
        return true;
      }
    );
  });

  it('9. Handles connection refusal (ECONNREFUSED) when ML service is offline', async () => {
    // Port 1 is reserved and guaranteed not listening
    const client = new MlClient({
      baseUrl: 'http://127.0.0.1:1',
      timeoutMs: 500,
    });

    await assert.rejects(
      async () => client.analyzeCod(validRequest),
      (err: Error) => {
        assert(err instanceof MlClientError);
        assert.equal(err.code, 'ML_NETWORK_ERROR');
        return true;
      }
    );
  });
});

