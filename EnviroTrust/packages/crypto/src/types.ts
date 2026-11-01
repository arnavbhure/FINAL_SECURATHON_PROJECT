/**
 * EnviroTrust Cryptographic Types
 */

export interface Ed25519KeyPair {
  privateKeyPem: string;
  publicKeyPem: string;
  fingerprint: string;
}

export type IdentityType = 'SENSOR' | 'OPERATIONS_SOURCE';

export interface KeyMetadata {
  keyId: string;
  identityType: IdentityType;
  identityId: string;
  siteId: string;
  stationId: string;
  parameter?: 'pH' | 'COD' | 'TSS' | null;
  algorithm: 'Ed25519';
  publicKeyPem: string;
  publicKeyFingerprint: string;
  createdAt: string;
  status: 'ACTIVE' | 'REVOKED';
  rotatedAt?: string | null;
  previousKeyId?: string | null;
}

export interface PublicKeyManifestEntry {
  keyId: string;
  identityType: IdentityType;
  identityId: string;
  siteId: string;
  stationId: string;
  parameter?: 'pH' | 'COD' | 'TSS' | null;
  algorithm: 'Ed25519';
  publicKeyPem: string;
  publicKeyFingerprint: string;
  createdAt: string;
  status: 'ACTIVE';
}

export interface PublicKeyManifest {
  schemaVersion: 1;
  generatedAt: string;
  keys: PublicKeyManifestEntry[];
}

export interface VerificationResult {
  valid: boolean;
  reason?: string;
}

