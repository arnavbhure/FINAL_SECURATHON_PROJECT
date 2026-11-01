import { describe, it, before, after } from 'node:test';
import assert from 'node:assert/strict';
import type { Server } from 'node:http';
import type { AddressInfo } from 'node:net';
import path from 'node:path';
import fs from 'node:fs';
import { fileURLToPath } from 'node:url';
import jwt from 'jsonwebtoken';
import { createApiApp } from '../../api/src/app.js';
import { getDbPool, closeDbPool } from '../../api/src/db/connection.js';
import { runMigrations } from '../../api/src/db/migrate.js';
import { seedDemoUsers } from '../../api/src/db/seed.js';
import { createWitnessApp } from '../src/app.js';
import { loadWitnessEnvironment, type WitnessEnvironment } from '../src/env.js';
import { getWitnessDbPool, closeWitnessDbPool } from '../src/db/connection.js';
import { SensorDevice } from '@envirotrust/sensor-simulator';
import { generateJwtKeyPair } from '@envirotrust/crypto';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const rootDir = path.resolve(__dirname, '../../..');

describe('Simulated Witness — Human Authentication, Session Introspection, Revocation & RBAC', () => {
  let primaryServer: Server;
  let witnessServer: Server;
  let primaryBaseUrl: string;
  let witnessBaseUrl: string;
  let phSensor: SensorDevice;
  let adminToken: string;
  let auditorTokenPlant1: string;
  let auditorTokenPlant2Only: string;
  let lastMessageId: string;
  let lastPayloadHash: string;
  let lastSignature: string;
  const env = loadWitnessEnvironment();
  const testStationId = 'ETP-OUTLET-001';

  before(async () => {
    // 1. Initialize databases and seed users
    const primaryPool = getDbPool();
    await runMigrations(primaryPool);
    await seedDemoUsers();

    // 2. Start Primary API server
    const { app: primaryApp } = createApiApp();
    await new Promise<void>((resolve) => {
      primaryServer = primaryApp.listen(0, () => {
        const addr = primaryServer.address() as AddressInfo;
        primaryBaseUrl = `http://127.0.0.1:${addr.port}`;
        resolve();
      });
    });

    // 3. Start Witness Service configured to introspect with Primary API
    const witnessEnv: WitnessEnvironment = {
      ...loadWitnessEnvironment(),
      PRIMARY_API_URL: primaryBaseUrl,
      INTERNAL_AUTH_SECRET: 'internal_auth_introspection_secret_34567',
    };
    const { app: witnessApp } = createWitnessApp(undefined, witnessEnv);
    await new Promise<void>((resolve) => {
      witnessServer = witnessApp.listen(0, () => {
        const addr = witnessServer.address() as AddressInfo;
        witnessBaseUrl = `http://127.0.0.1:${addr.port}`;
        resolve();
      });
    });

    // 4. Acquire authentic access tokens backed by real sessions in primary DB
    async function loginUser(email: string, password = 'DemoPassword123!'): Promise<string> {
      const res = await fetch(`${primaryBaseUrl}/api/v1/auth/login`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email, password }),
      });
      const data = (await res.json()) as any;
      return data.accessToken;
    }

    adminToken = await loginUser('admin@envirotrust.local');
    auditorTokenPlant1 = await loginUser('auditor@envirotrust.local');

    // Create a dedicated PLANT-002 only auditor
    const plant2AuditorEmail = `auditor-plant2-${Date.now()}@envirotrust.local`;
    await fetch(`${primaryBaseUrl}/api/v1/admin/users`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${adminToken}`,
      },
      body: JSON.stringify({
        fullName: 'Plant 2 Auditor',
        email: plant2AuditorEmail,
        password: 'DemoPassword123!',
        role: 'REGULATOR_AUDITOR',
        sites: ['PLANT-002'],
      }),
    });
    auditorTokenPlant2Only = await loginUser(plant2AuditorEmail);

    // 5. Seed a verified telemetry event into witness
    const phKeyDir = path.resolve(rootDir, 'local-secrets/sensor-keys/PH-OUT-001');
    phSensor = new SensorDevice({ sensorId: 'PH-OUT-001', keyDir: phKeyDir });
    const reading = phSensor.generateReading();
    lastMessageId = reading.payload.messageId;
    lastSignature = reading.signature;

    const crypto = await import('node:crypto');
    const { canonicalizePayload } = await import('@envirotrust/crypto');
    lastPayloadHash = crypto.createHash('sha256').update(canonicalizePayload(reading.payload)).digest('hex');

    await fetch(`${witnessBaseUrl}/witness/v1/ingestion/readings`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-Witness-Token': env.WITNESS_INGESTION_TOKEN,
      },
      body: JSON.stringify(reading),
    });
  });

  after(async () => {
    await new Promise<void>((resolve) => {
      primaryServer.close(() => resolve());
    });
    await new Promise<void>((resolve) => {
      witnessServer.close(() => resolve());
    });
    await closeDbPool();
    await closeWitnessDbPool();
  });

  it('1. Unauthenticated requests to witness read & verification endpoints return 401', async () => {
    const resCp = await fetch(`${witnessBaseUrl}/witness/v1/checkpoints/${testStationId}/latest`);
    assert.equal(resCp.status, 401);

    const resEv = await fetch(`${witnessBaseUrl}/witness/v1/events/${lastMessageId}`);
    assert.equal(resEv.status, 401);

    const resChain = await fetch(`${witnessBaseUrl}/witness/v1/verify/chain`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ stationId: testStationId }),
    });
    assert.equal(resChain.status, 401);

    const resRecon = await fetch(`${witnessBaseUrl}/witness/v1/verify/primary-record`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ messageId: lastMessageId, payloadHash: lastPayloadHash, signature: lastSignature }),
    });
    assert.equal(resRecon.status, 401);
  });

  it('2. Auditor authorized for PLANT-001 can access witness checkpoint and event history', async () => {
    const resEv = await fetch(`${witnessBaseUrl}/witness/v1/events/${lastMessageId}`, {
      headers: { Authorization: `Bearer ${auditorTokenPlant1}` },
    });
    assert.equal(resEv.status, 200);
    const body = (await resEv.json()) as any;
    assert.equal(body.success, true);
    assert.equal(body.event.messageId, lastMessageId);
    assert.equal(body.event.siteCode, 'PLANT-001');

    assert.equal(body.event.privateKey, undefined);
    assert.equal(body.event.privateKeyPem, undefined);
  });

  it('3. Auditor NOT authorized for PLANT-001 is FORBIDDEN (403) from accessing PLANT-001 event', async () => {
    const resEv = await fetch(`${witnessBaseUrl}/witness/v1/events/${lastMessageId}`, {
      headers: { Authorization: `Bearer ${auditorTokenPlant2Only}` },
    });
    assert.equal(resEv.status, 403);
    const body = (await resEv.json()) as any;
    assert.equal(body.code, 'FORBIDDEN_SITE_ACCESS');
  });

  it('4. Reconcile endpoint: Anti-SSRF and strict input format validation', async () => {
    const badIdRes = await fetch(`${witnessBaseUrl}/witness/v1/verify/primary-record`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${auditorTokenPlant1}`,
      },
      body: JSON.stringify({
        messageId: 'http://malicious-internal-server.local/ssrf',
        payloadHash: lastPayloadHash,
        signature: lastSignature,
      }),
    });
    assert.equal(badIdRes.status, 400);
    const badIdBody = (await badIdRes.json()) as any;
    assert.equal(badIdBody.code, 'INVALID_MESSAGE_ID');

    const badHashRes = await fetch(`${witnessBaseUrl}/witness/v1/verify/primary-record`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${auditorTokenPlant1}`,
      },
      body: JSON.stringify({
        messageId: lastMessageId,
        payloadHash: 'not-a-64-char-hex-hash',
        signature: lastSignature,
      }),
    });
    assert.equal(badHashRes.status, 400);
    const badHashBody = (await badHashRes.json()) as any;
    assert.equal(badHashBody.code, 'INVALID_PAYLOAD_HASH');
  });

  it('5. Reconcile endpoint succeeds for matching validated data and detects cross-site restriction', async () => {
    const matchRes = await fetch(`${witnessBaseUrl}/witness/v1/verify/primary-record`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${auditorTokenPlant1}`,
      },
      body: JSON.stringify({
        messageId: lastMessageId,
        payloadHash: lastPayloadHash,
        signature: lastSignature,
      }),
    });
    assert.equal(matchRes.status, 200);
    const matchBody = (await matchRes.json()) as any;
    assert.equal(matchBody.status, 'MATCHED');
    assert.equal(matchBody.witnessObserved, true);

    const crossRes = await fetch(`${witnessBaseUrl}/witness/v1/verify/primary-record`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${auditorTokenPlant2Only}`,
      },
      body: JSON.stringify({
        messageId: lastMessageId,
        payloadHash: lastPayloadHash,
        signature: lastSignature,
      }),
    });
    assert.equal(crossRes.status, 403);
  });

  it('6. Asymmetric key separation: rejects symmetric tokens and tokens signed with unauthorized keys', async () => {
    const symmetricToken = jwt.sign(
      { sub: '00000000-0000-0000-0000-000000000001', role: 'PLATFORM_ADMIN', sites: ['PLANT-001'] },
      'shared-secret-attempting-symmetric-bypass',
      { algorithm: 'HS256', issuer: 'envirotrust-api', audience: 'envirotrust-web' }
    );

    const hs256Res = await fetch(`${witnessBaseUrl}/witness/v1/checkpoints/${testStationId}/latest`, {
      headers: { Authorization: `Bearer ${symmetricToken}` },
    });
    assert.equal(hs256Res.status, 401);

    const rogueKeyPair = generateJwtKeyPair();
    const rogueToken = jwt.sign(
      { sub: '00000000-0000-0000-0000-000000000001', role: 'PLATFORM_ADMIN', sites: ['PLANT-001'] },
      rogueKeyPair.privateKeyPem,
      { algorithm: 'ES256', issuer: 'envirotrust-api', audience: 'envirotrust-web' }
    );

    const rogueRes = await fetch(`${witnessBaseUrl}/witness/v1/checkpoints/${testStationId}/latest`, {
      headers: { Authorization: `Bearer ${rogueToken}` },
    });
    assert.equal(rogueRes.status, 401);
  });

  it('7. Previously issued access token stops working on Witness immediately after user logs out (401)', async () => {
    // 1. User logs in
    const email = `logout-witness-${Date.now()}@envirotrust.local`;
    await fetch(`${primaryBaseUrl}/api/v1/admin/users`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${adminToken}` },
      body: JSON.stringify({ fullName: 'Logout Subject', email, password: 'Password123!', role: 'REGULATOR_AUDITOR', sites: ['PLANT-001'] }),
    });

    const loginRes = await fetch(`${primaryBaseUrl}/api/v1/auth/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email, password: 'Password123!' }),
    });
    const loginData = (await loginRes.json()) as any;
    const token = loginData.accessToken;
    const csrf = loginData.csrfToken;
    const setCookies = loginRes.headers.getSetCookie ? loginRes.headers.getSetCookie() : [loginRes.headers.get('set-cookie') || ''];
    let refreshCookie = '';
    for (const sc of setCookies) {
      const match = sc.match(/envirotrust_refresh=([^;]+)/);
      if (match && match[1]) refreshCookie = match[1];
    }

    // 2. Token works on witness prior to logout
    const preRes = await fetch(`${witnessBaseUrl}/witness/v1/events/${lastMessageId}`, {
      headers: { Authorization: `Bearer ${token}` },
    });
    assert.equal(preRes.status, 200);

    // 3. User logs out on Primary API
    const logoutRes = await fetch(`${primaryBaseUrl}/api/v1/auth/logout`, {
      method: 'POST',
      headers: {
        Cookie: `envirotrust_refresh=${refreshCookie}; envirotrust_csrf=${csrf}`,
        'X-CSRF-Token': csrf,
        Origin: 'http://localhost:5173',
      },
    });
    assert.equal(logoutRes.status, 200);

    // 4. Token MUST BE REJECTED immediately by Witness!
    const postRes = await fetch(`${witnessBaseUrl}/witness/v1/events/${lastMessageId}`, {
      headers: { Authorization: `Bearer ${token}` },
    });
    assert.equal(postRes.status, 401);
    const postBody = (await postRes.json()) as any;
    assert.equal(postBody.code, 'SESSION_REVOKED');
  });

  it('8. Previously issued access token stops working on Witness immediately after user is disabled (403)', async () => {
    // 1. Create user and login
    const email = `disabled-witness-${Date.now()}@envirotrust.local`;
    const createRes = await fetch(`${primaryBaseUrl}/api/v1/admin/users`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${adminToken}` },
      body: JSON.stringify({ fullName: 'Deactivate Subject', email, password: 'Password123!', role: 'REGULATOR_AUDITOR', sites: ['PLANT-001'] }),
    });
    const createBody = (await createRes.json()) as any;
    const userId = createBody.user.id;

    const loginRes = await fetch(`${primaryBaseUrl}/api/v1/auth/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email, password: 'Password123!' }),
    });
    const token = ((await loginRes.json()) as any).accessToken;

    // 2. Token works initially
    const preRes = await fetch(`${witnessBaseUrl}/witness/v1/events/${lastMessageId}`, {
      headers: { Authorization: `Bearer ${token}` },
    });
    assert.equal(preRes.status, 200);

    // 3. Admin disables user
    const disableRes = await fetch(`${primaryBaseUrl}/api/v1/admin/users/${userId}/status`, {
      method: 'PATCH',
      headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${adminToken}` },
      body: JSON.stringify({ status: 'DISABLED' }),
    });
    assert.equal(disableRes.status, 200);

    // 4. Token MUST BE REJECTED immediately by Witness!
    const postRes = await fetch(`${witnessBaseUrl}/witness/v1/events/${lastMessageId}`, {
      headers: { Authorization: `Bearer ${token}` },
    });
    assert.ok(postRes.status === 401 || postRes.status === 403);
    const postBody = (await postRes.json()) as any;
    assert.ok(postBody.code === 'ACCOUNT_DISABLED' || postBody.code === 'SESSION_REVOKED');
  });

  it('9. Previously issued access token stops working on Witness immediately after user role is changed (401)', async () => {
    // 1. Create user with FACTORY_OPERATOR role and login
    const email = `role-witness-${Date.now()}@envirotrust.local`;
    const createRes = await fetch(`${primaryBaseUrl}/api/v1/admin/users`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${adminToken}` },
      body: JSON.stringify({ fullName: 'Role Subject', email, password: 'Password123!', role: 'FACTORY_OPERATOR', sites: ['PLANT-001'] }),
    });
    const createBody = (await createRes.json()) as any;
    const userId = createBody.user.id;

    const loginRes = await fetch(`${primaryBaseUrl}/api/v1/auth/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email, password: 'Password123!' }),
    });
    const token = ((await loginRes.json()) as any).accessToken;

    // 2. Admin changes role to REGULATOR_AUDITOR
    const roleRes = await fetch(`${primaryBaseUrl}/api/v1/admin/users/${userId}/role`, {
      method: 'PATCH',
      headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${adminToken}` },
      body: JSON.stringify({ role: 'REGULATOR_AUDITOR' }),
    });
    assert.equal(roleRes.status, 200);

    // 3. Old token MUST BE REJECTED immediately by Witness!
    const postRes = await fetch(`${witnessBaseUrl}/witness/v1/events/${lastMessageId}`, {
      headers: { Authorization: `Bearer ${token}` },
    });
    assert.equal(postRes.status, 401);
    const postBody = (await postRes.json()) as any;
    assert.equal(postBody.code, 'SESSION_REVOKED');
  });

  it('10. Previously issued access token stops working on Witness immediately after site membership is revoked', async () => {
    // 1. Create user assigned to PLANT-001 and login
    const email = `site-witness-${Date.now()}@envirotrust.local`;
    const createRes = await fetch(`${primaryBaseUrl}/api/v1/admin/users`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${adminToken}` },
      body: JSON.stringify({ fullName: 'Site Subject', email, password: 'Password123!', role: 'REGULATOR_AUDITOR', sites: ['PLANT-001'] }),
    });
    const createBody = (await createRes.json()) as any;
    const userId = createBody.user.id;

    const loginRes = await fetch(`${primaryBaseUrl}/api/v1/auth/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email, password: 'Password123!' }),
    });
    const token = ((await loginRes.json()) as any).accessToken;

    // 2. Token works initially
    const preRes = await fetch(`${witnessBaseUrl}/witness/v1/events/${lastMessageId}`, {
      headers: { Authorization: `Bearer ${token}` },
    });
    assert.equal(preRes.status, 200);

    // 3. Admin revokes site PLANT-001 membership
    const revokeSiteRes = await fetch(`${primaryBaseUrl}/api/v1/admin/users/${userId}/sites/PLANT-001`, {
      method: 'DELETE',
      headers: { Authorization: `Bearer ${adminToken}` },
    });
    assert.equal(revokeSiteRes.status, 200);

    // 4. Token MUST BE REJECTED immediately by Witness!
    const postRes = await fetch(`${witnessBaseUrl}/witness/v1/events/${lastMessageId}`, {
      headers: { Authorization: `Bearer ${token}` },
    });
    assert.equal(postRes.status, 401);
    const postBody = (await postRes.json()) as any;
    assert.equal(postBody.code, 'SESSION_REVOKED');
  });

  it('11. Refresh token reuse detection revokes all sessions on Witness immediately (401)', async () => {
    // 1. User logs in
    const email = `reuse-witness-${Date.now()}@envirotrust.local`;
    await fetch(`${primaryBaseUrl}/api/v1/admin/users`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${adminToken}` },
      body: JSON.stringify({ fullName: 'Reuse Subject', email, password: 'Password123!', role: 'REGULATOR_AUDITOR', sites: ['PLANT-001'] }),
    });

    const loginRes = await fetch(`${primaryBaseUrl}/api/v1/auth/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email, password: 'Password123!' }),
    });
    const loginData = (await loginRes.json()) as any;
    const initialToken = loginData.accessToken;
    const csrf = loginData.csrfToken;
    const setCookies = loginRes.headers.getSetCookie ? loginRes.headers.getSetCookie() : [loginRes.headers.get('set-cookie') || ''];
    let refreshCookie1 = '';
    for (const sc of setCookies) {
      const match = sc.match(/envirotrust_refresh=([^;]+)/);
      if (match && match[1]) refreshCookie1 = match[1];
    }

    // 2. Rotate token once
    const refreshRes = await fetch(`${primaryBaseUrl}/api/v1/auth/refresh`, {
      method: 'POST',
      headers: {
        Cookie: `envirotrust_refresh=${refreshCookie1}; envirotrust_csrf=${csrf}`,
        'X-CSRF-Token': csrf,
        Origin: 'http://localhost:5173',
      },
    });
    assert.equal(refreshRes.status, 200);

    // 3. Replay old refresh cookie: triggers REFRESH_TOKEN_REUSE_DETECTED
    const reuseRes = await fetch(`${primaryBaseUrl}/api/v1/auth/refresh`, {
      method: 'POST',
      headers: {
        Cookie: `envirotrust_refresh=${refreshCookie1}; envirotrust_csrf=${csrf}`,
        'X-CSRF-Token': csrf,
        Origin: 'http://localhost:5173',
      },
    });
    assert.equal(reuseRes.status, 401);

    // 4. Any previously issued access token MUST BE REJECTED immediately on Witness!
    const postRes = await fetch(`${witnessBaseUrl}/witness/v1/events/${lastMessageId}`, {
      headers: { Authorization: `Bearer ${initialToken}` },
    });
    assert.equal(postRes.status, 401);
    const postBody = (await postRes.json()) as any;
    assert.equal(postBody.code, 'SESSION_REVOKED');
  });

  it('12. Invalid service-to-service credentials on introspection fail closed (503 INTROSPECTION_FAILED)', async () => {
    // Spin up a witness app with invalid INTERNAL_AUTH_SECRET
    const badSecretEnv: WitnessEnvironment = {
      ...loadWitnessEnvironment(),
      PRIMARY_API_URL: primaryBaseUrl,
      INTERNAL_AUTH_SECRET: 'wrong-and-invalid-secret-key-00000',
    };
    const { app: badWitnessApp } = createWitnessApp(undefined, badSecretEnv);
    let badWitnessServer: Server;
    let badWitnessBaseUrl: string;

    await new Promise<void>((resolve) => {
      badWitnessServer = badWitnessApp.listen(0, () => {
        const addr = badWitnessServer.address() as AddressInfo;
        badWitnessBaseUrl = `http://127.0.0.1:${addr.port}`;
        resolve();
      });
    });

    try {
      const res = await fetch(`${badWitnessBaseUrl}/witness/v1/events/${lastMessageId}`, {
        headers: { Authorization: `Bearer ${auditorTokenPlant1}` },
      });
      assert.equal(res.status, 503);
      const body = (await res.json()) as any;
      assert.equal(body.code, 'INTROSPECTION_FAILED');
    } finally {
      await new Promise<void>((resolve) => badWitnessServer.close(() => resolve()));
    }
  });

  it('13. Introspection timeout or unavailable Primary API fails closed (503 INTROSPECTION_UNAVAILABLE)', async () => {
    // Spin up a witness app pointing to an unreachable Primary API port
    const unreachableEnv: WitnessEnvironment = {
      ...loadWitnessEnvironment(),
      PRIMARY_API_URL: 'http://127.0.0.1:59998',
      INTROSPECTION_TIMEOUT_MS: 300,
    };
    const { app: downWitnessApp } = createWitnessApp(undefined, unreachableEnv);
    let downWitnessServer: Server;
    let downWitnessBaseUrl: string;

    await new Promise<void>((resolve) => {
      downWitnessServer = downWitnessApp.listen(0, () => {
        const addr = downWitnessServer.address() as AddressInfo;
        downWitnessBaseUrl = `http://127.0.0.1:${addr.port}`;
        resolve();
      });
    });

    try {
      const res = await fetch(`${downWitnessBaseUrl}/witness/v1/events/${lastMessageId}`, {
        headers: { Authorization: `Bearer ${auditorTokenPlant1}` },
      });
      assert.equal(res.status, 503);
      const body = (await res.json()) as any;
      assert.equal(body.code, 'INTROSPECTION_UNAVAILABLE');
    } finally {
      await new Promise<void>((resolve) => downWitnessServer.close(() => resolve()));
    }
  });

  it('14. Cross-site access using stale or forged JWT claims is rejected (Witness enforces fresh Primary state)', async () => {
    // An attacker creates an ES256 token claiming sites: ['PLANT-001'],
    // but the token's sid and sub belong to the plant2-only auditor!
    const privKeyPath = path.resolve(rootDir, 'local-secrets/jwt-keys/private.pem');
    const privateKeyPem = fs.readFileSync(privKeyPath, 'utf-8');

    // Decode the valid plant2 auditor token to extract their real active sid and sub
    const decodedPlant2 = jwt.decode(auditorTokenPlant2Only) as any;

    const forgedClaimsToken = jwt.sign(
      {
        sub: decodedPlant2.sub,
        sid: decodedPlant2.sid,
        email: decodedPlant2.email,
        role: 'REGULATOR_AUDITOR',
        fullName: decodedPlant2.fullName,
        sites: ['PLANT-001'], // FORGED / STALE CLAIM: Attacker attempts to claim PLANT-001!
      },
      privateKeyPem,
      { expiresIn: '1h', algorithm: 'ES256', issuer: 'envirotrust-api', audience: 'envirotrust-web' }
    );

    // Witness introspects with Primary API, receives the real sites: ['PLANT-002'],
    // ignores the forged claim, and REJECTS access to PLANT-001 event!
    const res = await fetch(`${witnessBaseUrl}/witness/v1/events/${lastMessageId}`, {
      headers: { Authorization: `Bearer ${forgedClaimsToken}` },
    });
    assert.equal(res.status, 403);
    const body = (await res.json()) as any;
    assert.equal(body.code, 'FORBIDDEN_SITE_ACCESS');
  });

  it('15. Valid administrator accessing permitted global resources on Witness succeeds (200)', async () => {
    const res = await fetch(`${witnessBaseUrl}/witness/v1/events/${lastMessageId}`, {
      headers: { Authorization: `Bearer ${adminToken}` },
    });
    assert.equal(res.status, 200);
    const body = (await res.json()) as any;
    assert.equal(body.success, true);
    assert.equal(body.event.messageId, lastMessageId);
  });
});
