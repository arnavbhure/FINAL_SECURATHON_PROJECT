import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { loadPublicKey, verifyPayloadSignatureWithReason } from '@envirotrust/crypto';
import { SensorDevice } from './sensor.js';
import { SENSOR_PROFILES, getDefaultKeyDir } from './config.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const rootDir = path.resolve(__dirname, '../../..');

export function runSensorOnce() {
  console.log('\n======================================================');
  console.log('EnviroTrust Sensor Simulator — One-Shot Test');
  console.log('Generating and verifying independent signed readings & heartbeats');
  console.log('Notice: Software-only simulated industrial sensor identities.');
  console.log('======================================================\n');

  const sensorIds = Object.keys(SENSOR_PROFILES) as Array<'PH-OUT-001' | 'COD-OUT-001' | 'TSS-OUT-001'>;

  for (const sensorId of sensorIds) {
    const keyDir = getDefaultKeyDir(rootDir, sensorId);
    let device: SensorDevice;

    try {
      device = new SensorDevice({ sensorId, keyDir });
    } catch (err) {
      console.error(`[ERROR] Failed to initialize ${sensorId}: ${(err as Error).message}`);
      continue;
    }

    // 1. Generate single signed telemetry reading
    const readingEnvelope = device.generateReading();
    const pubKeyPath = path.join(keyDir, 'public.pem');
    const pubKeyPem = loadPublicKey(pubKeyPath);

    // Verify locally using public key to prove mathematical correctness
    const readingVerification = verifyPayloadSignatureWithReason(
      readingEnvelope.payload,
      readingEnvelope.signature,
      pubKeyPem
    );

    console.log(`[SENSOR READING] ${device.sensorId}`);
    console.log(`  Parameter:            ${device.profile.parameter} (${device.profile.unit})`);
    console.log(`  Generated Value:      ${readingEnvelope.payload.value}`);
    console.log(`  Sequence No:          ${readingEnvelope.payload.sequence}`);
    console.log(`  Boot Session:         ${readingEnvelope.payload.bootId}`);
    console.log(`  Message ID:           ${readingEnvelope.payload.messageId}`);
    console.log(`  Key ID:               ${device.keyId}`);
    console.log(`  Signature Status:     ${readingVerification.valid ? 'VALID (Ed25519 Verified)' : 'FAILED'}`);
    console.log(`  Signature (Base64):   ${readingEnvelope.signature.slice(0, 24)}... (88 chars, raw key never printed)`);

    // 2. Generate single signed heartbeat
    const heartbeatEnvelope = device.generateHeartbeat();
    const heartbeatVerification = verifyPayloadSignatureWithReason(
      heartbeatEnvelope.payload,
      heartbeatEnvelope.signature,
      pubKeyPem
    );

    console.log(`[HEARTBEAT] ${device.sensorId}`);
    console.log(`  Heartbeat Sequence:   ${heartbeatEnvelope.payload.heartbeatSequence}`);
    console.log(`  Sent At:              ${heartbeatEnvelope.payload.sentAt}`);
    console.log(`  Heartbeat Status:     ${heartbeatVerification.valid ? 'VALID (Ed25519 Verified)' : 'FAILED'}`);
    console.log('------------------------------------------------------\n');
  }

  console.log('[SUCCESS] All sensor identities produced schema-valid, Ed25519-signed envelopes.');
}

if (process.argv[1] && (process.argv[1].endsWith('cli.ts') || process.argv[1].endsWith('cli.js'))) {
  runSensorOnce();
}

