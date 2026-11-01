import fs from 'node:fs';
import path from 'node:path';
import { generateJwtKeyPair, type JwtKeyPair } from '@envirotrust/crypto';

function findJwtKeyDir(): string {
  const envVal = process.env['JWT_KEY_DIR'];
  if (envVal) {
    const directPath = path.resolve(process.cwd(), envVal);
    if (fs.existsSync(directPath)) return directPath;
    const upPath = path.resolve(process.cwd(), '../../', envVal);
    if (fs.existsSync(upPath)) return upPath;
  }
  const candidates = [
    path.resolve(process.cwd(), 'local-secrets/jwt-keys'),
    path.resolve(process.cwd(), '../../local-secrets/jwt-keys'),
    path.resolve(process.cwd(), '../local-secrets/jwt-keys'),
  ];
  for (const c of candidates) {
    if (fs.existsSync(c)) return c;
  }
  return path.resolve(process.cwd(), 'local-secrets/jwt-keys');
}

let cachedKeys: JwtKeyPair | null = null;

/**
 * Loads or initializes the asymmetric ECDSA P-256 JWT key pair for the Primary API.
 * The Primary API retains both privateKeyPem (for signing) and publicKeyPem (for verification).
 */
export function getApiJwtKeyPair(customKeyDir?: string): JwtKeyPair {
  if (cachedKeys) return cachedKeys;

  // Environment variable override
  if (process.env['JWT_PRIVATE_KEY_PEM'] && process.env['JWT_PUBLIC_KEY_PEM']) {
    cachedKeys = {
      privateKeyPem: process.env['JWT_PRIVATE_KEY_PEM'],
      publicKeyPem: process.env['JWT_PUBLIC_KEY_PEM'],
    };
    return cachedKeys;
  }

  const keyDir = customKeyDir || findJwtKeyDir();
  const privPath = path.join(keyDir, 'private.pem');
  const pubPath = path.join(keyDir, 'public.pem');

  if (fs.existsSync(privPath) && fs.existsSync(pubPath)) {
    cachedKeys = {
      privateKeyPem: fs.readFileSync(privPath, 'utf-8'),
      publicKeyPem: fs.readFileSync(pubPath, 'utf-8'),
    };
    return cachedKeys;
  }

  // Generate new key pair if not exists
  const keyPair = generateJwtKeyPair();
  if (!fs.existsSync(keyDir)) {
    fs.mkdirSync(keyDir, { recursive: true, mode: 0o700 });
  }
  fs.writeFileSync(privPath, keyPair.privateKeyPem, { mode: 0o600 });
  fs.writeFileSync(pubPath, keyPair.publicKeyPem, { mode: 0o644 });

  cachedKeys = keyPair;
  return keyPair;
}

