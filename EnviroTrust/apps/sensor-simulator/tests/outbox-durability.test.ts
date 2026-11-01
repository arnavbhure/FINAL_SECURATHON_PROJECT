import { describe, it, before, after } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import http, { type Server } from 'node:http';
import type { AddressInfo } from 'node:net';
import { fileURLToPath } from 'node:url';
import { SensorDevice } from '../src/sensor.js';
import { OutboxManager } from '@envirotrust/crypto';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const rootDir = path.resolve(__dirname, '../../..');

describe('Sensor Simulator — Durable Outbox & Offline Resiliency Tests', () => {
  let primaryServer: Server;
  let witnessServer: Server;
  let primaryUrl: string;
  let witnessUrl: string;
  let primaryHeartbeatUrl: string;
  let witnessHeartbeatUrl: string;

  let primaryAccept = true;
  let witnessAccept = true;
  let primaryReceivedCount = 0;
  let witnessReceivedCount = 0;

  const testOutboxDir = path.resolve(rootDir, 'local-secrets/test-outbox');

  before(async () => {
    // Create test outbox directory
    if (fs.existsSync(testOutboxDir)) {
      fs.rmSync(testOutboxDir, { recursive: true, force: true });
    }
    fs.mkdirSync(testOutboxDir, { recursive: true });

    // Mock Primary HTTP Server
    primaryServer = http.createServer((_req, res) => {
      if (primaryAccept) {
        primaryReceivedCount++;
        res.writeHead(201, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ success: true, status: 'ACCEPTED' }));
      } else {
        res.writeHead(503, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ success: false, code: 'SERVICE_UNAVAILABLE' }));
      }
    });

    await new Promise<void>((resolve) => {
      primaryServer.listen(0, () => {
        const addr = primaryServer.address() as AddressInfo;
        primaryUrl = `http://127.0.0.1:${addr.port}/primary/readings`;
        primaryHeartbeatUrl = `http://127.0.0.1:${addr.port}/primary/heartbeats`;
        resolve();
      });
    });

    // Mock Witness HTTP Server
    witnessServer = http.createServer((_req, res) => {
      if (witnessAccept) {
        witnessReceivedCount++;
        res.writeHead(201, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ success: true, status: 'ACCEPTED' }));
      } else {
        res.writeHead(500, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ success: false, code: 'INTERNAL_ERROR' }));
      }
    });

    await new Promise<void>((resolve) => {
      witnessServer.listen(0, () => {
        const addr = witnessServer.address() as AddressInfo;
        witnessUrl = `http://127.0.0.1:${addr.port}/witness/readings`;
        witnessHeartbeatUrl = `http://127.0.0.1:${addr.port}/witness/heartbeats`;
        resolve();
      });
    });
  });

  after(async () => {
    await new Promise<void>((resolve) => primaryServer.close(() => resolve()));
    await new Promise<void>((resolve) => witnessServer.close(() => resolve()));
    if (fs.existsSync(testOutboxDir)) {
      fs.rmSync(testOutboxDir, { recursive: true, force: true });
    }
  });

  it('1. Persists envelope to durable outbox when witness destination fails', async () => {
    primaryAccept = true;
    witnessAccept = false; // Witness fails

    const keyDir = path.resolve(rootDir, 'local-secrets/sensor-keys/PH-OUT-001');
    const outboxManager = new OutboxManager(testOutboxDir);

    const device = new SensorDevice({
      sensorId: 'PH-OUT-001',
      keyDir,
      outboxManager,
    });

    const result = await device.sendHeartbeatDual(primaryHeartbeatUrl, witnessHeartbeatUrl, {
      retryCount: 1,
      retryBaseMs: 50,
    });

    assert.equal(result.primary.status, 'PRIMARY_ACCEPTED');
    assert.equal(result.witness.status, 'WITNESS_FAILED');

    // Verify outbox file was written
    const files = fs.readdirSync(testOutboxDir);
    assert.equal(files.length, 1);
    const savedEntry = outboxManager.getEntry(result.envelope.payload.messageId);
    assert.ok(savedEntry);
    assert.equal(savedEntry.primary.status, 'ACCEPTED');
    assert.equal(savedEntry.witness.status, 'FAILED');
    assert.equal(savedEntry.envelopeType, 'HEARTBEAT');
  });

  it('2. Outbox files never contain private keys or secrets', () => {
    const files = fs.readdirSync(testOutboxDir);
    assert.ok(files.length > 0);
    for (const f of files) {
      const content = fs.readFileSync(path.join(testOutboxDir, f), 'utf-8');
      assert.ok(!content.includes('BEGIN PRIVATE KEY'), 'Outbox must never store private key PEM');
      assert.ok(!content.includes('BEGIN ED25519 PRIVATE KEY'), 'Outbox must never store private key');
      assert.ok(!content.includes('secret'), 'Outbox must not contain sensitive auth secrets');
    }
  });

  it('3. Outbox entries survive simulator restart and flushOutbox delivers pending records', async () => {
    // Simulator process restart: instantiate new SensorDevice with the same outboxDir
    const keyDir = path.resolve(rootDir, 'local-secrets/sensor-keys/PH-OUT-001');
    const restartedOutbox = new OutboxManager(testOutboxDir);

    const pendingBefore = restartedOutbox.listPendingEntries();
    assert.equal(pendingBefore.length, 1);

    const restartedDevice = new SensorDevice({
      sensorId: 'PH-OUT-001',
      keyDir,
      outboxManager: restartedOutbox,
    });

    // Reset counts and restore witness health
    primaryReceivedCount = 0;
    witnessReceivedCount = 0;
    primaryAccept = true;
    witnessAccept = true; // Witness recovered

    // Flush outbox
    const flushResult = await restartedDevice.flushOutbox(
      primaryUrl,
      primaryHeartbeatUrl,
      witnessUrl,
      witnessHeartbeatUrl
    );

    assert.equal(flushResult.flushed, 1);
    assert.equal(flushResult.remaining, 0);

    // Witness received the retry; primary was already accepted so primary should not receive another attempt
    assert.equal(witnessReceivedCount, 1);
    assert.equal(primaryReceivedCount, 0); // Skipped already-accepted primary

    // Outbox directory should now be empty
    const filesAfter = fs.readdirSync(testOutboxDir);
    assert.equal(filesAfter.length, 0);
  });
});
