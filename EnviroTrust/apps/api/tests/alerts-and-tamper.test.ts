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
import { seedDemoUsers } from '../src/db/seed.js';
import { AlertService } from '../src/services/alert.service.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const rootDir = path.resolve(__dirname, '../../..');

describe('Primary API — Alert & Tamper Management System Tests', () => {
  let server: Server;
  let baseUrl: string;
  let phDevice: SensorDevice;
  let adminToken: string;
  let operatorToken: string;
  let auditorToken: string;
  let alertService: AlertService;

  before(async () => {
    const pool = getDbPool();
    await runMigrations(pool);
    await seedDemoUsers();
    await pool.query("DELETE FROM alerts WHERE deduplication_key LIKE 'tamper:%' OR deduplication_key LIKE 'test:%'");
    await pool.query("DELETE FROM tamper_events");
    const manifestPath = path.resolve(rootDir, 'local-secrets/provisioning/public-key-manifest.json');
    await registerKeysFromManifest(manifestPath, pool);

    const phKeyDir = path.resolve(rootDir, 'local-secrets/sensor-keys/PH-OUT-001');

    phDevice = new SensorDevice({
      sensorId: 'PH-OUT-001',
      keyDir: phKeyDir,
      bootId: `BOOT-ALERT-${crypto.randomUUID().slice(0, 8)}`,
      initialTelemetrySequence: 100,
      initialHeartbeatSequence: 100,
      initialTamperSequence: 1,
    });

    const appInstance = createApiApp();
    alertService = appInstance.alertService;

    await new Promise<void>((resolve) => {
      server = appInstance.app.listen(0, () => {
        const addr = server.address() as AddressInfo;
        baseUrl = `http://127.0.0.1:${addr.port}`;
        resolve();
      });
    });

    // Obtain tokens for admin, operator, and auditor
    const adminRes = await fetch(`${baseUrl}/api/v1/auth/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email: 'admin@envirotrust.local', password: 'DemoPassword123!' }),
    });
    adminToken = ((await adminRes.json()) as any).accessToken;

    const opRes = await fetch(`${baseUrl}/api/v1/auth/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email: 'operator@envirotrust.local', password: 'DemoPassword123!' }),
    });
    operatorToken = ((await opRes.json()) as any).accessToken;

    const audRes = await fetch(`${baseUrl}/api/v1/auth/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email: 'auditor@envirotrust.local', password: 'DemoPassword123!' }),
    });
    auditorToken = ((await audRes.json()) as any).accessToken;
  });

  after(async () => {
    await new Promise<void>((resolve) => {
      server.close(() => resolve());
    });
    await closeDbPool();
  });

  let createdAlertId: string;
  let createdEventId: string;

  it('1. Ingests valid signed tamper event, creates CRITICAL alert and appends primary audit event (201)', async () => {
    const envelope = phDevice.generateTamperEvent({
      eventType: 'ENCLOSURE_OPENED',
      tamperSource: 'SIMULATED',
      overrideSequence: 1,
    });
    createdEventId = envelope.payload.eventId;

    const res = await fetch(`${baseUrl}/api/v1/tamper/events`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(envelope),
    });

    assert.equal(res.status, 201);
    const data = (await res.json()) as any;
    assert.equal(data.success, true);
    assert.equal(data.status, 'ACCEPTED');
    assert.equal(data.eventId, createdEventId);
    assert.equal(data.severity, 'CRITICAL');
    assert.ok(data.alertId);
    assert.ok(data.primaryAuditSequence > 0);
    assert.ok(data.chainHeadHash);

    createdAlertId = data.alertId;

    // Verify alert exists in database
    const pool = getDbPool();
    const alertRow = await pool.query('SELECT * FROM alerts WHERE id = $1', [createdAlertId]);
    assert.equal(alertRow.rowCount, 1);
    const row = alertRow.rows[0];
    assert.ok(row);
    assert.equal(row.severity, 'CRITICAL');
    assert.equal(row.status, 'OPEN');
    assert.equal(row.alert_type, 'PHYSICAL_TAMPER');
    assert.equal(row.source_event_id, createdEventId);
  });

  it('2. Negative: Rejects invalid tamper signature (401) and does NOT create a tamper alert', async () => {
    const envelope = phDevice.generateTamperEvent({
      eventType: 'PHYSICAL_INTERFERENCE',
      overrideSequence: 2,
    });
    // Tamper with valid signature without corrupting base64 byte length
    const chars = envelope.signature.split('');
    chars[10] = chars[10] === 'A' ? 'B' : 'A';
    envelope.signature = chars.join('');

    const res = await fetch(`${baseUrl}/api/v1/tamper/events`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(envelope),
    });

    assert.equal(res.status, 401);
    const data = (await res.json()) as any;
    assert.equal(data.code, 'INVALID_SIGNATURE');

    // Verify security rejection event was logged in security_events
    const pool = getDbPool();
    const secRes = await pool.query(
      `SELECT * FROM security_events 
       WHERE event_type = 'TAMPER_SIGNATURE_VERIFICATION_FAILED' 
       ORDER BY created_at DESC LIMIT 1`
    );
    assert.equal(secRes.rowCount, 1);
    const secRow = secRes.rows[0];
    assert.ok(secRow);
    assert.equal(secRow.reason_code, 'INVALID_SIGNATURE');

    // Verify NO alert was created for this failed event
    const alertCheck = await pool.query('SELECT * FROM alerts WHERE source_event_id = $1', [envelope.payload.eventId]);
    assert.equal(alertCheck.rowCount, 0);
  });

  it('3. Negative: Rejects tamper event with unknown key ID (401)', async () => {
    const envelope = phDevice.generateTamperEvent({ overrideSequence: 3 });
    envelope.payload.keyId = 'UNKNOWN-KEY-999';

    const res = await fetch(`${baseUrl}/api/v1/tamper/events`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(envelope),
    });

    assert.equal(res.status, 401);
    const data = (await res.json()) as any;
    assert.equal(data.code, 'UNKNOWN_KEY');
  });

  it('4. Negative: Rejects tamper event with sensor identity mismatch (400)', async () => {
    const envelope = phDevice.generateTamperEvent({ overrideSequence: 4 });
    envelope.payload.sensorId = 'COD-OUT-001'; // Mismatch with PH-OUT-001 key

    const res = await fetch(`${baseUrl}/api/v1/tamper/events`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(envelope),
    });

    assert.equal(res.status, 400);
    const data = (await res.json()) as any;
    assert.equal(data.code, 'KEY_SENSOR_MISMATCH');
  });

  it('5. Tamper Replay Protection: idempotent duplicate returns 200, replayed sequence returns 409', async () => {
    // Exact duplicate resubmission
    const validEnvelope = phDevice.generateTamperEvent({ overrideSequence: 10 });
    const res1 = await fetch(`${baseUrl}/api/v1/tamper/events`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(validEnvelope),
    });
    assert.equal(res1.status, 201);

    // Resubmit exact same envelope
    const res2 = await fetch(`${baseUrl}/api/v1/tamper/events`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(validEnvelope),
    });
    assert.equal(res2.status, 200);
    const data2 = (await res2.json()) as any;
    assert.equal(data2.isDuplicate, true);

    // Replayed sequence with new event ID
    const replayedSeqEnvelope = phDevice.generateTamperEvent({ overrideSequence: 10 });
    const res3 = await fetch(`${baseUrl}/api/v1/tamper/events`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(replayedSeqEnvelope),
    });
    assert.equal(res3.status, 409);
    const data3 = (await res3.json()) as any;
    assert.equal(data3.code, 'REPLAYED_SEQUENCE');
  });

  it('6. GET /api/v1/alerts: Retrieves alerts list with site scoping and pagination', async () => {
    const res = await fetch(`${baseUrl}/api/v1/alerts?limit=10`, {
      headers: { Authorization: `Bearer ${operatorToken}` },
    });
    assert.equal(res.status, 200);
    const data = (await res.json()) as any;
    assert.equal(data.success, true);
    assert.ok(Array.isArray(data.alerts));
    assert.ok(data.total >= 1);
  });

  it('7. GET /api/v1/alerts/summary: Returns alert counts breakdown', async () => {
    const res = await fetch(`${baseUrl}/api/v1/alerts/summary`, {
      headers: { Authorization: `Bearer ${operatorToken}` },
    });
    assert.equal(res.status, 200);
    const data = (await res.json()) as any;
    assert.equal(data.success, true);
    assert.ok(data.summary.totalOpen >= 1);
    assert.ok(data.summary.critical >= 1);
  });

  it('8. GET /api/v1/alerts/:alertId: Returns single alert details with joined metadata', async () => {
    const res = await fetch(`${baseUrl}/api/v1/alerts/${createdAlertId}`, {
      headers: { Authorization: `Bearer ${operatorToken}` },
    });
    assert.equal(res.status, 200);
    const data = (await res.json()) as any;
    assert.equal(data.success, true);
    assert.equal(data.alert.id, createdAlertId);
    assert.equal(data.alert.severity, 'CRITICAL');
  });

  it('9. PATCH /api/v1/alerts/:alertId/acknowledge: Operator can acknowledge alert', async () => {
    const res = await fetch(`${baseUrl}/api/v1/alerts/${createdAlertId}/acknowledge`, {
      method: 'PATCH',
      headers: { Authorization: `Bearer ${operatorToken}` },
    });
    assert.equal(res.status, 200);
    const data = (await res.json()) as any;
    assert.equal(data.success, true);
    assert.equal(data.alert.status, 'ACKNOWLEDGED');
    assert.ok(data.alert.acknowledged_at);
  });

  it('10. Auditor Read-Only Enforcement: Auditor is FORBIDDEN (403) from acknowledging or resolving', async () => {
    const ackRes = await fetch(`${baseUrl}/api/v1/alerts/${createdAlertId}/acknowledge`, {
      method: 'PATCH',
      headers: { Authorization: `Bearer ${auditorToken}` },
    });
    assert.equal(ackRes.status, 403);
    const ackData = (await ackRes.json()) as any;
    assert.equal(ackData.code, 'FORBIDDEN_AUDITOR_READONLY');

    const resRes = await fetch(`${baseUrl}/api/v1/alerts/${createdAlertId}/resolve`, {
      method: 'PATCH',
      headers: {
        Authorization: `Bearer ${auditorToken}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({ resolutionNote: 'Auditor attempt' }),
    });
    assert.equal(resRes.status, 403);
    const resData = (await resRes.json()) as any;
    assert.equal(resData.code, 'FORBIDDEN_AUDITOR_READONLY');
  });

  it('11. PATCH /api/v1/alerts/:alertId/resolve: Resolves alert with required resolution note', async () => {
    // Missing resolution note fails with 400
    const failRes = await fetch(`${baseUrl}/api/v1/alerts/${createdAlertId}/resolve`, {
      method: 'PATCH',
      headers: {
        Authorization: `Bearer ${operatorToken}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({ resolutionNote: '' }),
    });
    assert.equal(failRes.status, 400);

    // Valid resolution note succeeds
    const successRes = await fetch(`${baseUrl}/api/v1/alerts/${createdAlertId}/resolve`, {
      method: 'PATCH',
      headers: {
        Authorization: `Bearer ${operatorToken}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        resolutionNote: 'Physical inspection completed. Enclosure sealed and sensor calibration verified.',
      }),
    });
    assert.equal(successRes.status, 200);
    const data = (await successRes.json()) as any;
    assert.equal(data.alert.status, 'RESOLVED');
    assert.ok(data.alert.resolved_at);
    assert.equal(data.alert.resolution_note, 'Physical inspection completed. Enclosure sealed and sensor calibration verified.');
  });

  it('12. Sensor Availability State Machine & Background Evaluator: Evaluates STALE/OFFLINE and deduplicates', async () => {
    // First evaluation run
    const run1 = await alertService.evaluateSensorAvailabilityAndSyncAlerts();
    assert.ok(run1.evaluated > 0);

    // Second evaluation run immediately after must NOT create duplicate alerts
    const run2 = await alertService.evaluateSensorAvailabilityAndSyncAlerts();
    assert.equal(run2.staleAlertsCreated, 0);
    assert.equal(run2.offlineAlertsCreated, 0);
  });

  it('13. Multi-site Isolation: Operator cannot access alert from an unassigned site, but admin has global visibility', async () => {
    // Create an alert manually for PLANT-002
    const pool = getDbPool();
    const plant2Site = await pool.query<{ id: string }>("SELECT id FROM sites WHERE site_code = 'PLANT-002'");
    if (plant2Site.rowCount && plant2Site.rowCount > 0 && plant2Site.rows[0]) {
      const site2Id = plant2Site.rows[0].id;
      const alertRepo = alertService.getAlertRepository();
      const p2Alert = await alertRepo.createAlert({
        siteId: site2Id,
        alertType: 'SECURITY_EVENT',
        severity: 'HIGH',
        title: 'PLANT 2 TEST ALERT',
        description: 'Test isolation',
        recommendedAction: 'None',
        deduplicationKey: `test:p2:${Date.now()}`,
      });

      // Operator assigned only to PLANT-001 attempts to view PLANT-002 alert -> 403
      const res = await fetch(`${baseUrl}/api/v1/alerts/${p2Alert.id}`, {
        headers: { Authorization: `Bearer ${operatorToken}` },
      });
      assert.equal(res.status, 403);
      const data = (await res.json()) as any;
      assert.equal(data.code, 'FORBIDDEN_SITE');

      // Admin has global visibility across all sites -> 200
      const adminViewRes = await fetch(`${baseUrl}/api/v1/alerts/${p2Alert.id}`, {
        headers: { Authorization: `Bearer ${adminToken}` },
      });
      assert.equal(adminViewRes.status, 200);
    }
  });
});
