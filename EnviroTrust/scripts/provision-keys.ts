import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { generateEd25519KeyPair, calculatePublicKeyFingerprint, generateJwtKeyPair } from '@envirotrust/crypto';
import type { IdentityType, PublicKeyManifest, PublicKeyManifestEntry } from '@envirotrust/crypto';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const rootDir = path.resolve(__dirname, '..');
const defaultSecretsDir = path.join(rootDir, 'local-secrets');

interface DeviceProvisioningConfig {
  identityType: IdentityType;
  identityId: string;
  categoryDir: 'sensor-keys' | 'ops-keys';
  siteId: string;
  stationId: string;
  parameter: 'pH' | 'COD' | 'TSS' | null;
  baseKeyPrefix: string;
}

const DEVICES_TO_PROVISION: DeviceProvisioningConfig[] = [
  {
    identityType: 'SENSOR',
    identityId: 'PH-OUT-001',
    categoryDir: 'sensor-keys',
    siteId: 'PLANT-001',
    stationId: 'ETP-OUTLET-001',
    parameter: 'pH',
    baseKeyPrefix: 'PH-KEY',
  },
  {
    identityType: 'SENSOR',
    identityId: 'COD-OUT-001',
    categoryDir: 'sensor-keys',
    siteId: 'PLANT-001',
    stationId: 'ETP-OUTLET-001',
    parameter: 'COD',
    baseKeyPrefix: 'COD-KEY',
  },
  {
    identityType: 'SENSOR',
    identityId: 'TSS-OUT-001',
    categoryDir: 'sensor-keys',
    siteId: 'PLANT-001',
    stationId: 'ETP-OUTLET-001',
    parameter: 'TSS',
    baseKeyPrefix: 'TSS-KEY',
  },
  {
    identityType: 'OPERATIONS_SOURCE',
    identityId: 'OPS-001',
    categoryDir: 'ops-keys',
    siteId: 'PLANT-001',
    stationId: 'ETP-OUTLET-001',
    parameter: null,
    baseKeyPrefix: 'OPS-KEY',
  },
];

interface StoredMetadata {
  keyId: string;
  identityType: IdentityType;
  identityId: string;
  siteId: string;
  stationId: string;
  parameter?: 'pH' | 'COD' | 'TSS' | null;
  algorithm: 'Ed25519';
  publicKeyFingerprint: string;
  createdAt: string;
  status: 'ACTIVE' | 'REVOKED';
  history?: Array<{
    keyId: string;
    publicKeyFingerprint: string;
    createdAt: string;
    rotatedAt: string;
  }>;
}

export function provisionKeys(options: { rotate?: boolean; targetIdentity?: string; baseDir?: string } = {}) {
  const baseDir = options.baseDir || defaultSecretsDir;
  const isRotate = Boolean(options.rotate);
  const targetId = options.targetIdentity;

  console.log(`\n======================================================`);
  console.log(`EnviroTrust Cryptographic Key Provisioning`);
  console.log(`Mode: ${isRotate ? 'ROTATION (--rotate)' : 'IDEMPOTENT PROVISIONING'}`);
  console.log(`Destination: ${baseDir}`);
  console.log(`======================================================\n`);

  // Ensure directories exist
  const sensorKeysDir = path.join(baseDir, 'sensor-keys');
  const opsKeysDir = path.join(baseDir, 'ops-keys');
  const provisioningDir = path.join(baseDir, 'provisioning');

  fs.mkdirSync(sensorKeysDir, { recursive: true });
  fs.mkdirSync(opsKeysDir, { recursive: true });
  fs.mkdirSync(provisioningDir, { recursive: true });

  const devices = targetId
    ? DEVICES_TO_PROVISION.filter((d) => d.identityId.toLowerCase() === targetId.toLowerCase())
    : DEVICES_TO_PROVISION;

  if (devices.length === 0) {
    console.error(`No configured device found matching target: ${targetId}`);
    return;
  }

  const manifestKeys: PublicKeyManifestEntry[] = [];

  for (const dev of devices) {
    const devDir = path.join(baseDir, dev.categoryDir, dev.identityId);
    fs.mkdirSync(devDir, { recursive: true });

    const privateKeyPath = path.join(devDir, 'private.pem');
    const publicKeyPath = path.join(devDir, 'public.pem');
    const metadataPath = path.join(devDir, 'metadata.json');

    const keysExist = fs.existsSync(privateKeyPath) && fs.existsSync(publicKeyPath) && fs.existsSync(metadataPath);

    if (keysExist && !isRotate) {
      // Idempotent: load existing metadata and public key
      const existingMeta = JSON.parse(fs.readFileSync(metadataPath, 'utf-8')) as StoredMetadata;
      const publicKeyPem = fs.readFileSync(publicKeyPath, 'utf-8');
      const fingerprint = calculatePublicKeyFingerprint(publicKeyPem);

      console.log(`[EXISTING] ${dev.identityId}`);
      console.log(`  Key ID:      ${existingMeta.keyId}`);
      console.log(`  Fingerprint: ${fingerprint}`);
      console.log(`  Status:      ${existingMeta.status} (Not modified; pass --rotate to rotate)`);

      manifestKeys.push({
        keyId: existingMeta.keyId,
        identityType: dev.identityType,
        identityId: dev.identityId,
        siteId: dev.siteId,
        stationId: dev.stationId,
        parameter: dev.parameter,
        algorithm: 'Ed25519',
        publicKeyPem: publicKeyPem.trim(),
        publicKeyFingerprint: fingerprint,
        createdAt: existingMeta.createdAt,
        status: 'ACTIVE',
      });
      continue;
    }

    // Determine key ID and version
    let keyVersion = 1;
    let oldMetadata: StoredMetadata | null = null;

    if (keysExist && isRotate) {
      oldMetadata = JSON.parse(fs.readFileSync(metadataPath, 'utf-8')) as StoredMetadata;
      const match = oldMetadata.keyId.match(/-V(\d+)$/i);
      if (match && match[1]) {
        keyVersion = parseInt(match[1], 10) + 1;
      } else {
        keyVersion = 2;
      }

      // Preserve old key files without destroying them
      const backupPrivPath = path.join(devDir, `private-${oldMetadata.keyId}.pem`);
      const backupPubPath = path.join(devDir, `public-${oldMetadata.keyId}.pem`);
      fs.copyFileSync(privateKeyPath, backupPrivPath);
      fs.copyFileSync(publicKeyPath, backupPubPath);
      console.log(`  [PRESERVED] Archived previous key pair to private/public-${oldMetadata.keyId}.pem`);
    }

    const keyId = `${dev.baseKeyPrefix}-V${keyVersion}`;
    const keyPair = generateEd25519KeyPair();
    const nowIso = new Date().toISOString();

    // Write private key with restrictive permissions
    fs.writeFileSync(privateKeyPath, keyPair.privateKeyPem, { encoding: 'utf-8', mode: 0o600 });
    fs.writeFileSync(publicKeyPath, keyPair.publicKeyPem, { encoding: 'utf-8', mode: 0o644 });

    const history = oldMetadata?.history || [];
    if (oldMetadata) {
      history.push({
        keyId: oldMetadata.keyId,
        publicKeyFingerprint: oldMetadata.publicKeyFingerprint,
        createdAt: oldMetadata.createdAt,
        rotatedAt: nowIso,
      });
    }

    const newMetadata: StoredMetadata = {
      keyId,
      identityType: dev.identityType,
      identityId: dev.identityId,
      siteId: dev.siteId,
      stationId: dev.stationId,
      parameter: dev.parameter,
      algorithm: 'Ed25519',
      publicKeyFingerprint: keyPair.fingerprint,
      createdAt: nowIso,
      status: 'ACTIVE',
      history,
    };

    fs.writeFileSync(metadataPath, JSON.stringify(newMetadata, null, 2), 'utf-8');

    console.log(`[${isRotate ? 'ROTATED' : 'PROVISIONED'}] ${dev.identityId}`);
    console.log(`  Key ID:      ${keyId}`);
    console.log(`  Fingerprint: ${keyPair.fingerprint}`);
    console.log(`  Algorithm:   Ed25519`);
    console.log(`  Private Key: Stored in ${privateKeyPath} (0o600 permissions, never logged)`);
    if (isRotate) {
      console.log(`  NOTE: Later database registration must preserve key history for ${oldMetadata?.keyId}.`);
    }

    manifestKeys.push({
      keyId,
      identityType: dev.identityType,
      identityId: dev.identityId,
      siteId: dev.siteId,
      stationId: dev.stationId,
      parameter: dev.parameter,
      algorithm: 'Ed25519',
      publicKeyPem: keyPair.publicKeyPem.trim(),
      publicKeyFingerprint: keyPair.fingerprint,
      createdAt: nowIso,
      status: 'ACTIVE',
    });
  }

  // Generate / update public-key manifest (contains ONLY public metadata, zero private keys)
  const manifestPath = path.join(provisioningDir, 'public-key-manifest.json');
  const manifest: PublicKeyManifest = {
    schemaVersion: 1,
    generatedAt: new Date().toISOString(),
    keys: manifestKeys,
  };

  fs.writeFileSync(manifestPath, JSON.stringify(manifest, null, 2), 'utf-8');
  console.log(`\n[MANIFEST] Public key manifest written to:`);
  console.log(`  ${manifestPath}`);
  console.log(`  Total enrolled public keys: ${manifestKeys.length}`);
  console.log(`  Zero private keys included in manifest.`);

  // Provision asymmetric ECDSA P-256 JWT key pair for human authentication (ES256)
  const jwtKeyDir = path.join(baseDir, 'jwt-keys');
  const jwtPrivPath = path.join(jwtKeyDir, 'private.pem');
  const jwtPubPath = path.join(jwtKeyDir, 'public.pem');
  if (!fs.existsSync(jwtKeyDir)) {
    fs.mkdirSync(jwtKeyDir, { recursive: true, mode: 0o700 });
  }
  if (!fs.existsSync(jwtPrivPath) || !fs.existsSync(jwtPubPath)) {
    const jwtPair = generateJwtKeyPair();
    fs.writeFileSync(jwtPrivPath, jwtPair.privateKeyPem, { mode: 0o600 });
    fs.writeFileSync(jwtPubPath, jwtPair.publicKeyPem, { mode: 0o644 });
    console.log(`\n[JWT-KEYS] Provisioned asymmetric ES256 key pair in ${jwtKeyDir}`);
  }
}

// CLI entry point if run directly
if (process.argv[1] && fileURLToPath(import.meta.url) === path.resolve(process.argv[1])) {
  const args = process.argv.slice(2);
  const rotate = args.includes('--rotate');
  const targetArg = args.find((a) => a.startsWith('--target='));
  const targetIdentity = targetArg ? targetArg.split('=')[1] : undefined;
  const baseDirArg = args.find((a) => a.startsWith('--base-dir='));
  const baseDir = baseDirArg ? baseDirArg.split('=')[1] : undefined;

  const cliOpts: { rotate?: boolean; targetIdentity?: string; baseDir?: string } = {};
  if (rotate) cliOpts.rotate = true;
  if (targetIdentity) cliOpts.targetIdentity = targetIdentity;
  if (baseDir) cliOpts.baseDir = baseDir;

  provisionKeys(cliOpts);
}
