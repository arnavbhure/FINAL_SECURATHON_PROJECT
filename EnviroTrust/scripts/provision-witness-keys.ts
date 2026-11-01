import fs from 'node:fs';
import path from 'node:path';
import { generateEd25519KeyPair } from '@envirotrust/crypto';

export interface WitnessKeyMetadata {
  witnessId: string;
  keyId: string;
  displayName: string;
  algorithm: 'Ed25519';
  publicKeyPem: string;
  fingerprint: string;
  createdAt: string;
  status: 'ACTIVE';
  rotatedAt?: string | null;
  previousKeyId?: string | null;
}

export function provisionWitnessKeys(options: { baseDir?: string; rotate?: boolean } = {}): {
  keyDir: string;
  keyId: string;
  fingerprint: string;
  action: 'CREATED' | 'ROTATED' | 'EXISTING';
} {
  const root = options.baseDir || process.cwd();
  const keyDir = path.resolve(root, 'local-secrets/witness-keys');
  const metadataPath = path.join(keyDir, 'metadata.json');
  const privateKeyPath = path.join(keyDir, 'private.pem');
  const publicKeyPath = path.join(keyDir, 'public.pem');

  fs.mkdirSync(keyDir, { recursive: true });

  const exists =
    fs.existsSync(metadataPath) && fs.existsSync(privateKeyPath) && fs.existsSync(publicKeyPath);

  if (exists && !options.rotate) {
    const existing = JSON.parse(fs.readFileSync(metadataPath, 'utf-8')) as WitnessKeyMetadata;
    console.log(`[WITNESS_KEY] Key ${existing.keyId} already exists. Fingerprint: ${existing.fingerprint}`);
    return {
      keyDir,
      keyId: existing.keyId,
      fingerprint: existing.fingerprint,
      action: 'EXISTING',
    };
  }

  let version = 1;
  let previousKeyId: string | null = null;

  if (exists && options.rotate) {
    const prev = JSON.parse(fs.readFileSync(metadataPath, 'utf-8')) as WitnessKeyMetadata;
    const match = prev.keyId.match(/WITNESS-KEY-V(\d+)/);
    if (match && match[1]) {
      version = parseInt(match[1], 10) + 1;
    }
    previousKeyId = prev.keyId;

    // Archive old keys
    const archiveDir = path.join(keyDir, 'archive', prev.keyId);
    fs.mkdirSync(archiveDir, { recursive: true });
    fs.copyFileSync(privateKeyPath, path.join(archiveDir, 'private.pem'));
    fs.copyFileSync(publicKeyPath, path.join(archiveDir, 'public.pem'));
    fs.copyFileSync(metadataPath, path.join(archiveDir, 'metadata.json'));
  }

  const keyId = `WITNESS-KEY-V${version}`;
  const keyPair = generateEd25519KeyPair();
  const now = new Date().toISOString();

  // Write private key with restrictive permissions
  fs.writeFileSync(privateKeyPath, keyPair.privateKeyPem, { encoding: 'utf-8', mode: 0o600 });
  fs.writeFileSync(publicKeyPath, keyPair.publicKeyPem, { encoding: 'utf-8', mode: 0o644 });

  const metadata: WitnessKeyMetadata = {
    witnessId: 'WITNESS-001',
    keyId,
    displayName: 'Simulated Independent Witness',
    algorithm: 'Ed25519',
    publicKeyPem: keyPair.publicKeyPem,
    fingerprint: keyPair.fingerprint,
    createdAt: now,
    status: 'ACTIVE',
    ...(previousKeyId ? { previousKeyId, rotatedAt: now } : {}),
  };

  fs.writeFileSync(metadataPath, JSON.stringify(metadata, null, 2), { encoding: 'utf-8', mode: 0o644 });

  console.log(`[WITNESS_KEY] Generated witness key ${keyId}. Fingerprint: ${keyPair.fingerprint}`);
  return {
    keyDir,
    keyId,
    fingerprint: keyPair.fingerprint,
    action: options.rotate ? 'ROTATED' : 'CREATED',
  };
}

// CLI execution
if (process.argv[1] && process.argv[1].endsWith('provision-witness-keys.ts')) {
  const rotate = process.argv.includes('--rotate');
  const baseDirArg = process.argv.find((a) => a.startsWith('--base-dir='));
  const baseDir = baseDirArg ? baseDirArg.split('=')[1] : undefined;

  provisionWitnessKeys({ baseDir, rotate });
}

