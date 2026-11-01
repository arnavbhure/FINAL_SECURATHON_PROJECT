import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { loadPublicKey, verifyPayloadSignature, verifyPayloadSignatureWithReason } from '@envirotrust/crypto';
import { OpsContextSimulator, getDefaultOpsKeyDir } from '../src/index.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const rootDir = path.resolve(__dirname, '../../..');

describe('Operations Simulator — Context Envelope Generation and Signing', () => {
  const keyDir = getDefaultOpsKeyDir(rootDir);
  const pubKey = loadPublicKey(path.join(keyDir, 'public.pem'));

  it('generates schema-valid and cryptographically verifiable NORMAL context envelope', () => {
    const sim = new OpsContextSimulator({ keyDir });
    const env = sim.generateContext({ mode: 'NORMAL' });

    assert.equal(env.payload.schemaVersion, 1);
    assert.equal(env.payload.eventType, 'OPERATIONS_CONTEXT');
    assert.equal(env.payload.sourceId, 'OPS-001');
    assert.equal(env.payload.operatingMode, 'NORMAL');
    assert.ok(env.payload.productionRate >= 400 && env.payload.productionRate <= 500);

    const verifyRes = verifyPayloadSignatureWithReason(env.payload, env.signature, pubKey);
    assert.equal(verifyRes.valid, true);

    const serialized = JSON.stringify(env);
    assert.ok(!serialized.includes('PRIVATE KEY'));
  });

  it('generates schema-valid and cryptographically verifiable HIGH_LOAD context envelope', () => {
    const sim = new OpsContextSimulator({ keyDir });
    const env = sim.generateContext({ mode: 'HIGH_LOAD' });

    assert.equal(env.payload.operatingMode, 'HIGH_LOAD');
    assert.ok(env.payload.productionRate >= 750 && env.payload.productionRate <= 950);

    const verifyRes = verifyPayloadSignatureWithReason(env.payload, env.signature, pubKey);
    assert.equal(verifyRes.valid, true);
  });

  it('rejects verification if productionRate is altered', () => {
    const sim = new OpsContextSimulator({ keyDir });
    const env = sim.generateContext({ mode: 'NORMAL' });

    const tampered = { ...env.payload, productionRate: 9999.0 };
    assert.equal(verifyPayloadSignature(tampered, env.signature, pubKey), false);
  });

  it('rejects verification if operatingMode is altered', () => {
    const sim = new OpsContextSimulator({ keyDir });
    const env = sim.generateContext({ mode: 'NORMAL' });

    const tampered = { ...env.payload, operatingMode: 'HIGH_LOAD' };
    assert.equal(verifyPayloadSignature(tampered, env.signature, pubKey), false);
  });

  it('rejects verification if OPS context is verified under a sensor public key (source separation)', () => {
    const sim = new OpsContextSimulator({ keyDir });
    const env = sim.generateContext({ mode: 'NORMAL' });

    const sensorPubKey = loadPublicKey(path.join(rootDir, 'local-secrets', 'sensor-keys', 'COD-OUT-001', 'public.pem'));
    assert.equal(verifyPayloadSignature(env.payload, env.signature, sensorPubKey), false);
  });

  it('sendOpsContext dispatches signed envelope to target HTTP endpoint', async () => {
    const sim = new OpsContextSimulator({ keyDir });
    const http = await import('node:http');
    let receivedBody: unknown;

    const testServer = http.createServer((req, res) => {
      let bodyStr = '';
      req.on('data', (chunk) => {
        bodyStr += chunk;
      });
      req.on('end', () => {
        receivedBody = JSON.parse(bodyStr);
        res.writeHead(201, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ success: true, readingId: 'ops-123' }));
      });
    });

    await new Promise<void>((resolve) => testServer.listen(0, resolve));
    const port = (testServer.address() as { port: number }).port;
    const targetUrl = `http://127.0.0.1:${port}/test/ops`;

    try {
      const result = await sim.sendOpsContext(targetUrl);
      assert.equal(result.ok, true);
      assert.equal(result.status, 201);
      assert.ok(receivedBody);
      assert.equal(
        (receivedBody as { payload: { sourceId: string } }).payload.sourceId,
        'OPS-001'
      );
    } finally {
      await new Promise<void>((resolve) => testServer.close(() => resolve()));
    }
  });

  it('sendOpsContext retries on network error with the identical envelope', async () => {
    const sim = new OpsContextSimulator({ keyDir });
    const http = await import('node:http');
    let attempts = 0;
    const messageIdsSeen: string[] = [];

    const testServer = http.createServer((req, res) => {
      attempts++;
      let bodyStr = '';
      req.on('data', (chunk) => {
        bodyStr += chunk;
      });
      req.on('end', () => {
        const parsed = JSON.parse(bodyStr);
        messageIdsSeen.push(parsed.payload.messageId);
        if (attempts === 1) {
          res.destroy();
        } else {
          res.writeHead(200, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ success: true }));
        }
      });
    });

    await new Promise<void>((resolve) => testServer.listen(0, resolve));
    const port = (testServer.address() as { port: number }).port;
    const targetUrl = `http://127.0.0.1:${port}/test/retry-ops`;

    try {
      const result = await sim.sendOpsContext(targetUrl, undefined, 2, 50);
      assert.equal(result.ok, true);
      assert.equal(attempts, 2);
      assert.equal(messageIdsSeen.length, 2);
      assert.equal(messageIdsSeen[0], messageIdsSeen[1]);
    } finally {
      await new Promise<void>((resolve) => testServer.close(() => resolve()));
    }
  });
});

