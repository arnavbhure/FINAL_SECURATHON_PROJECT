import fs from 'node:fs';
import path from 'node:path';

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

let cachedPublicKey: string | null = null;

/**
 * Loads the public verification key for the Witness service.
 * CRITICAL SECURITY PROPERTY:
 * The Witness service holds ONLY the public key. Private signing material is never
 * accessible to or stored by the Witness service.
 */
export function getWitnessJwtPublicKey(customKeyDir?: string): string {
  if (cachedPublicKey) return cachedPublicKey;

  if (process.env['JWT_PUBLIC_KEY_PEM']) {
    cachedPublicKey = process.env['JWT_PUBLIC_KEY_PEM'];
    return cachedPublicKey;
  }

  const keyDir = customKeyDir || findJwtKeyDir();
  const pubPath = path.join(keyDir, 'public.pem');

  if (fs.existsSync(pubPath)) {
    cachedPublicKey = fs.readFileSync(pubPath, 'utf-8');
    return cachedPublicKey;
  }

  throw new Error(`FATAL: JWT public verification key not found at: ${pubPath}. Run key provisioning first.`);
}

