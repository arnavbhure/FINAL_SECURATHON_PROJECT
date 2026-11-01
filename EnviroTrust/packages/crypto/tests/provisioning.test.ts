import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import { execSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import type { PublicKeyManifest } from '../src/index.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const rootDir = path.resolve(__dirname, '../../..');

describe('Key Provisioning — Idempotency and Rotation CLI', () => {
  const tmpDir = path.join(os.tmpdir(), `envirotrust-prov-test-${Date.now()}`);

  it('provisions distinct Ed25519 key pairs for PH, COD, TSS, and OPS', () => {
    // Run CLI directly via tsx
    execSync(`npx tsx scripts/provision-keys.ts --base-dir="${tmpDir}"`, {
      encoding: 'utf-8',
      cwd: rootDir,
    });

    const sensorIds = ['PH-OUT-001', 'COD-OUT-001', 'TSS-OUT-001'];
    const fingerprints = new Set<string>();

    for (const sensorId of sensorIds) {
      const devDir = path.join(tmpDir, 'sensor-keys', sensorId);
      assert.ok(fs.existsSync(path.join(devDir, 'private.pem')));
      assert.ok(fs.existsSync(path.join(devDir, 'public.pem')));

      const meta = JSON.parse(fs.readFileSync(path.join(devDir, 'metadata.json'), 'utf-8')) as {
        publicKeyFingerprint: string;
        keyId: string;
      };
      assert.ok(meta.publicKeyFingerprint);
      assert.match(meta.keyId, /-V1$/);
      fingerprints.add(meta.publicKeyFingerprint);
    }

    // OPS-001 key pair
    const opsDir = path.join(tmpDir, 'ops-keys', 'OPS-001');
    assert.ok(fs.existsSync(path.join(opsDir, 'private.pem')));
    assert.ok(fs.existsSync(path.join(opsDir, 'public.pem')));
    const opsMeta = JSON.parse(fs.readFileSync(path.join(opsDir, 'metadata.json'), 'utf-8')) as {
      publicKeyFingerprint: string;
      keyId: string;
    };
    fingerprints.add(opsMeta.publicKeyFingerprint);

    // All 4 keys must be unique
    assert.equal(fingerprints.size, 4);

    // Manifest verification
    const manifestPath = path.join(tmpDir, 'provisioning', 'public-key-manifest.json');
    assert.ok(fs.existsSync(manifestPath));
    const manifest = JSON.parse(fs.readFileSync(manifestPath, 'utf-8')) as PublicKeyManifest;
    assert.equal(manifest.keys.length, 4);

    // Security hygiene: zero private keys in manifest
    const manifestRaw = fs.readFileSync(manifestPath, 'utf-8');
    assert.ok(!manifestRaw.includes('PRIVATE KEY'));
  });

  it('is strictly idempotent when run repeatedly without --rotate', () => {
    const phPrivBefore = fs.readFileSync(path.join(tmpDir, 'sensor-keys', 'PH-OUT-001', 'private.pem'), 'utf-8');

    // Run provisioning again without rotate
    execSync(`npx tsx scripts/provision-keys.ts --base-dir="${tmpDir}"`, {
      encoding: 'utf-8',
      cwd: rootDir,
    });

    const phPrivAfter = fs.readFileSync(path.join(tmpDir, 'sensor-keys', 'PH-OUT-001', 'private.pem'), 'utf-8');
    assert.equal(phPrivBefore, phPrivAfter);
  });

  it('rotates keys when --rotate is provided: generates new key ID and preserves old key files', () => {
    const phPrivV1 = fs.readFileSync(path.join(tmpDir, 'sensor-keys', 'PH-OUT-001', 'private.pem'), 'utf-8');
    const phPubV1 = fs.readFileSync(path.join(tmpDir, 'sensor-keys', 'PH-OUT-001', 'public.pem'), 'utf-8');

    // Rotate PH-OUT-001
    execSync(`npx tsx scripts/provision-keys.ts --base-dir="${tmpDir}" --rotate --target=PH-OUT-001`, {
      encoding: 'utf-8',
      cwd: rootDir,
    });

    const phPrivV2 = fs.readFileSync(path.join(tmpDir, 'sensor-keys', 'PH-OUT-001', 'private.pem'), 'utf-8');
    assert.notEqual(phPrivV1, phPrivV2);

    // Old files must be preserved with keyId in filename
    const preservedPriv = fs.readFileSync(path.join(tmpDir, 'sensor-keys', 'PH-OUT-001', 'private-PH-KEY-V1.pem'), 'utf-8');
    assert.equal(preservedPriv, phPrivV1);

    const preservedPub = fs.readFileSync(path.join(tmpDir, 'sensor-keys', 'PH-OUT-001', 'public-PH-KEY-V1.pem'), 'utf-8');
    assert.equal(preservedPub, phPubV1);

    // Metadata must reflect PH-KEY-V2 and contain history
    const meta = JSON.parse(fs.readFileSync(path.join(tmpDir, 'sensor-keys', 'PH-OUT-001', 'metadata.json'), 'utf-8')) as {
      keyId: string;
      history: Array<{ keyId: string }>;
    };
    assert.equal(meta.keyId, 'PH-KEY-V2');
    assert.equal(meta.history.length, 1);
    assert.equal(meta.history[0]?.keyId, 'PH-KEY-V1');

    // Cleanup temp dir
    fs.rmSync(tmpDir, { recursive: true, force: true });
  });
});
