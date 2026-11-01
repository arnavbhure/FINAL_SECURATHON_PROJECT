import { describe, it, before, after } from 'node:test';
import assert from 'node:assert/strict';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import type { Server } from 'node:http';
import type { AddressInfo } from 'node:net';
import crypto from 'node:crypto';
import { createApiApp } from '../src/app.js';
import { getDbPool, closeDbPool } from '../src/db/connection.js';
import { runMigrations } from '../src/db/migrate.js';
import { SensorDevice } from '@envirotrust/sensor-simulator';
import { registerKeysFromManifest } from '../src/services/key-registry.service.js';
import { SensorAvailabilityService } from '../src/services/sensor-availability.service.js';
import { seedDemoUsers } from '../src/db/seed.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const rootDir = path.resolve(__dirname, '../../..');

describe('Primary API — Signed Heartbeats & Sensor Availability Tests', () => {
  let server: Server;
  let baseUrl: string;
  let phDevice: SensorDevice;
  let operatorToken: string;

  before(async () => {
    const pool = getDbPool();
    await runMigrations(pool);
    await seedDemoUsers();
    const manifestPath = path.resolve(rootDir, 'local-secrets/provisioning/public-key-manifest.json');
    await registerKeysFromManifest(manifestPath, pool);

    const phKeyDir = path.resolve(rootDir, 'local-secrets/sensor-keys/PH-OUT-001');

    phDevice = new SensorDevice({
      sensorId: 'PH-OUT-001',
      keyDir: phKeyDir,
      bootId: `BOOT-HB-${crypto.randomUUID().slice(0, 8)}`,
      initialHeartbeatSequence: 1,
    });

    const { app } = createApiApp();
    await new Promise<void>((resolve) => {
      server = app.listen(0, () => {
        const addr = server.address() as AddressInfo;
        baseUrl = `http://127.0.0.1:${addr.port}`;
        resolve();
      });
    });

    // Obtain operator token for authenticated read endpoints
    const loginRes = await fetch(`${baseUrl}/api/v1/auth/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email: 'operator@envirotrust.local', password: 'DemoPassword123!' }),
    });
    const loginData = (await loginRes.json()) as any;
    operatorToken = loginData.accessToken;
  });

  after(async () => {
    await new Promise<void>((resolve) => {
      server.close(() => resolve());
    });
    await closeDbPool();
  });

  it('1. Ingests a valid signed heartbeat envelope and persists sequence cursor & audit event (201)', async () => {
    const envelope = phDevice.generateHeartbeat();

    const res = await fetch(`${baseUrl}/api/v1/ingestion/heartbeats`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(envelope),
    });

    assert.equal(res.status, 201);
    const body = (await res.json()) as any;
    assert.equal(body.success, true);
    assert.equal(body.status, 'ACCEPTED');
    assert.equal(body.messageId, envelope.payload.messageId);
    assert.equal(body.heartbeatSequence, envelope.payload.heartbeatSequence);
    assert.ok(body.receivedAt);
    assert.ok(body.primaryAuditSequence > 0);
    assert.ok(body.chainHeadHash);

    // Verify cursor updated in database
    const pool = getDbPool();
    const cursorRes = await pool.query<{ boot_id: string; last_heartbeat_sequence: string }>(
      `SELECT c.boot_id, c.last_heartbeat_sequence
       FROM sensor_heartbeat_cursors c
       JOIN sensors s ON s.id = c.sensor_id
       WHERE s.sensor_code = 'PH-OUT-001'`
    );
    assert.equal(cursorRes.rows.length, 1);
    assert.ok(cursorRes.rows[0]);
    assert.equal(cursorRes.rows[0].boot_id, phDevice.bootId);
    assert.equal(Number(cursorRes.rows[0].last_heartbeat_sequence), envelope.payload.heartbeatSequence);

    // Verify station audit event
    const auditRes = await pool.query<{ event_type: string; entity_id: string; message_id: string }>(
      `SELECT event_type, entity_id, message_id
       FROM audit_events
       WHERE message_id = $1 AND event_type = 'HEARTBEAT'`,
      [envelope.payload.messageId]
    );
    assert.equal(auditRes.rows.length, 1);
    assert.ok(auditRes.rows[0]);
    assert.equal(auditRes.rows[0].event_type, 'HEARTBEAT');
    assert.equal(auditRes.rows[0].entity_id, 'PH-OUT-001');
  });

  it('2. Handles idempotent duplicate heartbeat submission gracefully (200)', async () => {
    const envelope = phDevice.generateHeartbeat();

    const firstRes = await fetch(`${baseUrl}/api/v1/ingestion/heartbeats`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(envelope),
    });
    assert.equal(firstRes.status, 201);

    // Duplicate submission with identical signature
    const dupRes = await fetch(`${baseUrl}/api/v1/ingestion/heartbeats`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(envelope),
    });
    assert.equal(dupRes.status, 200);
    const body = (await dupRes.json()) as any;
    assert.equal(body.isDuplicate, true);
    assert.equal(body.messageId, envelope.payload.messageId);
  });

  it('3. Rejects replayed heartbeat sequence with higher sequence already seen (409)', async () => {
    const env1 = phDevice.generateHeartbeat(); // seq 3
    const env2 = phDevice.generateHeartbeat(); // seq 4

    // Deliver env2 first
    const res2 = await fetch(`${baseUrl}/api/v1/ingestion/heartbeats`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(env2),
    });
    assert.equal(res2.status, 201);

    // Attempt to deliver older env1
    const res1 = await fetch(`${baseUrl}/api/v1/ingestion/heartbeats`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(env1),
    });
    assert.equal(res1.status, 409);
    const body = (await res1.json()) as any;
    assert.equal(body.code, 'REPLAYED_SEQUENCE');
  });

  it('4. Rejects heartbeat with modified payload or invalid signature (401)', async () => {
    const envelope = phDevice.generateHeartbeat();
    (envelope.payload as any).bootId = 'BOOT-TAMPERED';

    const res = await fetch(`${baseUrl}/api/v1/ingestion/heartbeats`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(envelope),
    });

    assert.equal(res.status, 401);
    const body = (await res.json()) as any;
    assert.equal(body.code, 'INVALID_SIGNATURE');
  });

  it('5. Availability state machine evaluates ONLINE -> STALE -> OFFLINE based on server receivedAt & sentAt', () => {
    const service = new SensorAvailabilityService(getDbPool(), {
      intervalSeconds: 10,
      staleIntervals: 2,
      offlineIntervals: 3,
    });

    const now = new Date('2026-10-31T12:00:00.000Z');

    // 1. Never received
    const neverRes = service.evaluateStatus(null, now);
    assert.equal(neverRes.currentStatus, 'OFFLINE');
    assert.equal(neverRes.statusReason, 'NO_HEARTBEAT_EVER_RECEIVED');

    // 2. Recent receipt (10s ago, sent 10s ago) -> ONLINE
    const onlineRes = service.evaluateStatus(
      new Date('2026-10-31T11:59:50.000Z'),
      now,
      new Date('2026-10-31T11:59:50.000Z')
    );
    assert.equal(onlineRes.currentStatus, 'ONLINE');
    assert.equal(onlineRes.statusReason, 'HEARTBEAT_RECEIVED');

    // 3. Exactly at stale boundary (20s ago) -> ONLINE
    const boundaryOnline = service.evaluateStatus(
      new Date('2026-10-31T11:59:40.000Z'),
      now,
      new Date('2026-10-31T11:59:40.000Z')
    );
    assert.equal(boundaryOnline.currentStatus, 'ONLINE');

    // 4. Delayed receipt (25s ago) -> STALE
    const staleRes = service.evaluateStatus(
      new Date('2026-10-31T11:59:35.000Z'),
      now,
      new Date('2026-10-31T11:59:35.000Z')
    );
    assert.equal(staleRes.currentStatus, 'STALE');
    assert.equal(staleRes.statusReason, 'HEARTBEAT_DELAYED');

    // 5. Lost receipt (35s ago) -> OFFLINE
    const offlineRes = service.evaluateStatus(
      new Date('2026-10-31T11:59:25.000Z'),
      now,
      new Date('2026-10-31T11:59:25.000Z')
    );
    assert.equal(offlineRes.currentStatus, 'OFFLINE');
    assert.equal(offlineRes.statusReason, 'SENSOR_COMMUNICATION_LOST');
    assert.ok(offlineRes.explanation.includes('Missing communication does not prove physical sensor shutdown'));

    // 6. DELAYED HEARTBEAT FINDING (Prompt 5 Issue A):
    // Packet received 1 second ago, but sentAt was 2 hours ago!
    // Must NOT evaluate to ONLINE simply because it arrived just now!
    const delayedHeartbeatRes = service.evaluateStatus(
      new Date('2026-10-31T11:59:59.000Z'), // received 1s ago
      now,
      new Date('2026-10-31T09:59:59.000Z')  // sent 2 hours ago!
    );
    assert.equal(delayedHeartbeatRes.currentStatus, 'OFFLINE');
    assert.equal(delayedHeartbeatRes.statusReason, 'HEARTBEAT_DELAYED');
    assert.ok(delayedHeartbeatRes.explanation.includes('Delayed heartbeats do not establish current liveness'));
  });

  it('6. GET /api/v1/sensors/health returns list of sensor availability with valid authorization', async () => {
    const res = await fetch(`${baseUrl}/api/v1/sensors/health`, {
      headers: { Authorization: `Bearer ${operatorToken}` },
    });
    assert.equal(res.status, 200);
    const body = (await res.json()) as any;
    assert.equal(body.success, true);
    assert.ok(Array.isArray(body.sensors));
    assert.ok(body.sensors.length >= 3);

    const phSummary = body.sensors.find((s: any) => s.sensorCode === 'PH-OUT-001');
    assert.ok(phSummary);
    assert.equal(phSummary.currentStatus, 'ONLINE');
    assert.ok(phSummary.lastHeartbeatReceivedAt);
    assert.equal(phSummary.expectedIntervalSeconds, 10);
  });

  it('7. GET /api/v1/sensors/:sensorId/health returns single sensor availability with valid authorization', async () => {
    const res = await fetch(`${baseUrl}/api/v1/sensors/PH-OUT-001/health`, {
      headers: { Authorization: `Bearer ${operatorToken}` },
    });
    assert.equal(res.status, 200);
    const body = (await res.json()) as any;
    assert.equal(body.success, true);
    assert.equal(body.sensor.sensorCode, 'PH-OUT-001');
    assert.equal(body.sensor.currentStatus, 'ONLINE');
  });

  it('8. Site-scoped authorization prevents accessing sensors from unauthorized site', async () => {
    // Correct site header (PLANT-001)
    const resOk = await fetch(`${baseUrl}/api/v1/sensors/PH-OUT-001/health`, {
      headers: {
        Authorization: `Bearer ${operatorToken}`,
        'x-site-id': 'PLANT-001',
      },
    });
    assert.equal(resOk.status, 200);

    // Mismatched site header
    const resForbidden = await fetch(`${baseUrl}/api/v1/sensors/PH-OUT-001/health`, {
      headers: {
        Authorization: `Bearer ${operatorToken}`,
        'x-site-id': 'SITE-DIFFERENT-999',
      },
    });
    assert.equal(resForbidden.status, 403);
    const body = (await resForbidden.json()) as any;
    assert.equal(body.code, 'FORBIDDEN_SITE_ACCESS');
  });

  it('9. GET /api/v1/heartbeats/history returns heartbeat records for a sensor with valid authorization', async () => {
    const res = await fetch(`${baseUrl}/api/v1/heartbeats/history?sensorId=PH-OUT-001&limit=10`, {
      headers: { Authorization: `Bearer ${operatorToken}` },
    });
    assert.equal(res.status, 200);
    const body = (await res.json()) as any;
    assert.equal(body.success, true);
    assert.equal(body.sensorCode, 'PH-OUT-001');
    assert.ok(body.heartbeats.length >= 2);
    assert.equal(body.heartbeats[0].verificationStatus, 'VALID');
  });

  it('10. Backend restart recomputation: state is immediately computed from database without ephemeral timers', async () => {
    const { app: freshApp } = createApiApp();
    let freshServer: Server;
    let freshUrl = '';

    await new Promise<void>((resolve) => {
      freshServer = freshApp.listen(0, () => {
        const addr = freshServer.address() as AddressInfo;
        freshUrl = `http://127.0.0.1:${addr.port}`;
        resolve();
      });
    });

    try {
      const res = await fetch(`${freshUrl}/api/v1/sensors/PH-OUT-001/health`, {
        headers: { Authorization: `Bearer ${operatorToken}` },
      });
      assert.equal(res.status, 200);
      const body = (await res.json()) as any;
      assert.equal(body.success, true);
      assert.equal(body.sensor.sensorCode, 'PH-OUT-001');
      assert.equal(body.sensor.currentStatus, 'ONLINE');
      assert.ok(body.sensor.lastHeartbeatReceivedAt);
    } finally {
      await new Promise<void>((resolve) => {
        freshServer.close(() => resolve());
      });
    }
  });

  it('11. SENSOR_RECOVERED auditability (Prompt 5 Issue B): transition from OFFLINE to ONLINE is persistently recorded', async () => {
    const pool = getDbPool();

    // 1. Artificially advance cursor to OFFLINE state (60 seconds ago)
    const oldTimestamp = new Date(Date.now() - 60000);
    await pool.query(
      `UPDATE sensor_heartbeat_cursors
       SET last_received_at = $1, last_sent_at = $1
       FROM sensors s
       WHERE s.id = sensor_heartbeat_cursors.sensor_id AND s.sensor_code = 'PH-OUT-001'`,
      [oldTimestamp.toISOString()]
    );

    // Verify status is currently OFFLINE
    const preHealthRes = await fetch(`${baseUrl}/api/v1/sensors/PH-OUT-001/health`, {
      headers: { Authorization: `Bearer ${operatorToken}` },
    });
    const preBody = (await preHealthRes.json()) as any;
    assert.equal(preBody.sensor.currentStatus, 'OFFLINE');

    // 2. Submit fresh valid heartbeat -> triggers OFFLINE -> ONLINE recovery!
    const freshEnvelope = phDevice.generateHeartbeat();
    const ingestRes = await fetch(`${baseUrl}/api/v1/ingestion/heartbeats`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(freshEnvelope),
    });
    assert.equal(ingestRes.status, 201);

    // 3. Verify status restored to ONLINE
    const postHealthRes = await fetch(`${baseUrl}/api/v1/sensors/PH-OUT-001/health`, {
      headers: { Authorization: `Bearer ${operatorToken}` },
    });
    const postBody = (await postHealthRes.json()) as any;
    assert.equal(postBody.sensor.currentStatus, 'ONLINE');

    // 4. Verify durable transition record exists in sensor_state_transitions table
    const transitionRes = await pool.query<{
      from_status: string;
      to_status: string;
      reason: string;
    }>(
      `SELECT t.from_status, t.to_status, t.reason
       FROM sensor_state_transitions t
       JOIN sensors s ON s.id = t.sensor_id
       WHERE s.sensor_code = 'PH-OUT-001' AND t.reason = 'SENSOR_RECOVERED'
       ORDER BY t.occurred_at DESC
       LIMIT 1`
    );
    assert.ok(transitionRes.rows.length >= 1, 'Expected durable state transition row');
    assert.equal(transitionRes.rows[0]?.from_status, 'OFFLINE');
    assert.equal(transitionRes.rows[0]?.to_status, 'ONLINE');
    assert.equal(transitionRes.rows[0]?.reason, 'SENSOR_RECOVERED');

    // 5. Verify SENSOR_STATE_TRANSITION audit event in audit_events
    const auditRes = await pool.query<{ event_type: string; entity_id: string }>(
      `SELECT event_type, entity_id
       FROM audit_events
       WHERE event_type = 'SENSOR_STATE_TRANSITION' AND entity_id = 'PH-OUT-001'
       ORDER BY event_sequence DESC
       LIMIT 1`
    );
    assert.ok(auditRes.rows.length >= 1, 'Expected SENSOR_STATE_TRANSITION audit event');
    assert.equal(auditRes.rows[0]?.event_type, 'SENSOR_STATE_TRANSITION');
  });

  it('12. Delayed heartbeat does not push cursor timestamps backwards when a newer heartbeat exists', async () => {
    const pool = getDbPool();
    const sensorRes = await pool.query<{ id: string }>(
      "SELECT id FROM sensors WHERE sensor_code = 'PH-OUT-001'"
    );
    const sensorIdUuid = sensorRes.rows[0]?.id;
    assert.ok(sensorIdUuid);

    // Read current cursor timestamp
    const cursorBefore = await pool.query<{
      last_sent_at: Date;
      last_received_at: Date;
    }>(
      'SELECT last_sent_at, last_received_at FROM sensor_heartbeat_cursors WHERE sensor_id = $1',
      [sensorIdUuid]
    );
    const cursorSentAt = cursorBefore.rows[0]?.last_sent_at.getTime();
    assert.ok(cursorSentAt);

    // Generate a delayed heartbeat with sentAt in the past (60s ago, transitDelay > 30s)
    const oldSentAt = new Date(Date.now() - 60000).toISOString();
    const delayedEnvelope = phDevice.generateHeartbeat({ sentAt: oldSentAt });

    const delayedRes = await fetch(`${baseUrl}/api/v1/ingestion/heartbeats`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(delayedEnvelope),
    });
    assert.equal(delayedRes.status, 201);

    // Verify cursor last_sent_at was NOT pushed backwards
    const cursorAfter = await pool.query<{
      last_sent_at: Date;
      last_received_at: Date;
    }>(
      'SELECT last_sent_at, last_received_at FROM sensor_heartbeat_cursors WHERE sensor_id = $1',
      [sensorIdUuid]
    );
    assert.ok(cursorAfter.rows[0]!.last_sent_at.getTime() >= cursorSentAt);
  });
});
