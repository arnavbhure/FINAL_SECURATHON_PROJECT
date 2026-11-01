import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { loadPublicKey, verifyPayloadSignature, verifyPayloadSignatureWithReason } from '@envirotrust/crypto';
import { SensorDevice, getDefaultKeyDir } from '../src/index.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const rootDir = path.resolve(__dirname, '../../..');

describe('Sensor Simulator — Telemetry and Heartbeat Generation', () => {
  const sensorIds: Array<'PH-OUT-001' | 'COD-OUT-001' | 'TSS-OUT-001'> = ['PH-OUT-001', 'COD-OUT-001', 'TSS-OUT-001'];

  for (const sensorId of sensorIds) {
    it(`generates schema-valid and cryptographically verifiable telemetry for ${sensorId}`, () => {
      const keyDir = getDefaultKeyDir(rootDir, sensorId);
      const device = new SensorDevice({ sensorId, keyDir });
      const pubKey = loadPublicKey(path.join(keyDir, 'public.pem'));

      const reading = device.generateReading();

      // Contract checks
      assert.equal(reading.payload.schemaVersion, 1);
      assert.equal(reading.payload.eventType, 'TELEMETRY');
      assert.equal(reading.payload.sensorId, sensorId);
      assert.ok(reading.payload.messageId);
      assert.equal(reading.payload.sequence, 1);
      assert.ok(reading.payload.bootId);

      // Value check
      assert.match(reading.payload.value, /^-?(0|[1-9][0-9]*)(\.[0-9]+)?$/);

      // Signature verification
      const verifyRes = verifyPayloadSignatureWithReason(reading.payload, reading.signature, pubKey);
      assert.equal(verifyRes.valid, true);

      // Private key isolation
      const serialized = JSON.stringify(reading);
      assert.ok(!serialized.includes('PRIVATE KEY'));
    });

    it(`generates schema-valid and cryptographically verifiable heartbeats for ${sensorId}`, () => {
      const keyDir = getDefaultKeyDir(rootDir, sensorId);
      const device = new SensorDevice({ sensorId, keyDir });
      const pubKey = loadPublicKey(path.join(keyDir, 'public.pem'));

      const hb = device.generateHeartbeat();

      assert.equal(hb.payload.schemaVersion, 1);
      assert.equal(hb.payload.eventType, 'HEARTBEAT');
      assert.equal(hb.payload.sensorId, sensorId);
      assert.equal(hb.payload.heartbeatSequence, 1);

      const isValid = verifyPayloadSignature(hb.payload, hb.signature, pubKey);
      assert.equal(isValid, true);
    });
  }

  it('strictly increments sequence numbers monotonically within the same bootId', () => {
    const keyDir = getDefaultKeyDir(rootDir, 'COD-OUT-001');
    const device = new SensorDevice({ sensorId: 'COD-OUT-001', keyDir });

    const r1 = device.generateReading();
    const r2 = device.generateReading();
    const r3 = device.generateReading();

    assert.equal(r1.payload.sequence, 1);
    assert.equal(r2.payload.sequence, 2);
    assert.equal(r3.payload.sequence, 3);
    assert.equal(r1.payload.bootId, r2.payload.bootId);
    assert.notEqual(r1.payload.messageId, r2.payload.messageId);
  });

  it('rejects verification if reading measurement value is altered', () => {
    const keyDir = getDefaultKeyDir(rootDir, 'COD-OUT-001');
    const device = new SensorDevice({ sensorId: 'COD-OUT-001', keyDir });
    const pubKey = loadPublicKey(path.join(keyDir, 'public.pem'));

    const envelope = device.generateReading();
    const tamperedPayload = { ...envelope.payload, value: '999.99' };

    assert.equal(verifyPayloadSignature(tamperedPayload, envelope.signature, pubKey), false);
  });

  it('rejects verification if heartbeat sequence is altered', () => {
    const keyDir = getDefaultKeyDir(rootDir, 'TSS-OUT-001');
    const device = new SensorDevice({ sensorId: 'TSS-OUT-001', keyDir });
    const pubKey = loadPublicKey(path.join(keyDir, 'public.pem'));

    const hb = device.generateHeartbeat();
    const tamperedHb = { ...hb.payload, heartbeatSequence: 999 };

    assert.equal(verifyPayloadSignature(tamperedHb, hb.signature, pubKey), false);
  });

  it('rejects verification under a different sensor public key (cross-sensor impersonation)', () => {
    const codDir = getDefaultKeyDir(rootDir, 'COD-OUT-001');
    const phDir = getDefaultKeyDir(rootDir, 'PH-OUT-001');

    const codDevice = new SensorDevice({ sensorId: 'COD-OUT-001', keyDir: codDir });
    const phPubKey = loadPublicKey(path.join(phDir, 'public.pem'));

    const codReading = codDevice.generateReading();

    // Verifying COD reading with pH public key must fail
    assert.equal(verifyPayloadSignature(codReading.payload, codReading.signature, phPubKey), false);
  });

  it('sendReading dispatches signed envelope to target HTTP endpoint', async () => {
    const keyDir = getDefaultKeyDir(rootDir, 'PH-OUT-001');
    const device = new SensorDevice({ sensorId: 'PH-OUT-001', keyDir });

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
        res.end(JSON.stringify({ success: true, readingId: 'test-reading-123' }));
      });
    });

    await new Promise<void>((resolve) => testServer.listen(0, resolve));
    const port = (testServer.address() as { port: number }).port;
    const targetUrl = `http://127.0.0.1:${port}/test/readings`;

    try {
      const result = await device.sendReading(targetUrl);
      assert.equal(result.ok, true);
      assert.equal(result.status, 201);
      assert.ok(receivedBody);
      assert.equal(
        (receivedBody as { payload: { sensorId: string } }).payload.sensorId,
        'PH-OUT-001'
      );
    } finally {
      await new Promise<void>((resolve) => testServer.close(() => resolve()));
    }
  });

  it('sendReading retries on network error with the identical envelope', async () => {
    const keyDir = getDefaultKeyDir(rootDir, 'COD-OUT-001');
    const device = new SensorDevice({ sensorId: 'COD-OUT-001', keyDir });

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
          // Fail on first attempt
          res.destroy();
        } else {
          res.writeHead(200, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ success: true }));
        }
      });
    });

    await new Promise<void>((resolve) => testServer.listen(0, resolve));
    const port = (testServer.address() as { port: number }).port;
    const targetUrl = `http://127.0.0.1:${port}/test/retry`;

    try {
      const result = await device.sendReading(targetUrl, undefined, 2, 50);
      assert.equal(result.ok, true);
      assert.equal(attempts, 2);
      // Verify identical messageId reused across retries
      assert.equal(messageIdsSeen.length, 2);
      assert.equal(messageIdsSeen[0], messageIdsSeen[1]);
    } finally {
      await new Promise<void>((resolve) => testServer.close(() => resolve()));
    }
  });
});

