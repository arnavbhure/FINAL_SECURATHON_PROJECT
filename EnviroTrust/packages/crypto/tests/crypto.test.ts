import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import {
  generateEd25519KeyPair,
  calculatePublicKeyFingerprint,
  canonicalizePayload,
  signPayload,
  verifyPayloadSignature,
  verifyPayloadSignatureWithReason,
  validateSignatureEncoding,
} from '../src/index.js';

describe('Cryptography — RFC 8785 Canonicalization (JCS)', () => {
  it('produces identical canonical strings regardless of property insertion order', () => {
    const objA = { z: 1, a: 'test', m: { b: 2, a: 1 } };
    const objB = { a: 'test', m: { a: 1, b: 2 }, z: 1 };

    const canonA = canonicalizePayload(objA);
    const canonB = canonicalizePayload(objB);

    assert.equal(canonA, canonB);
    assert.equal(canonA, '{"a":"test","m":{"a":1,"b":2},"z":1}');
  });

  it('preserves decimal strings without numeric precision corruption', () => {
    const obj = { value: '185.40', parameter: 'COD' };
    const canon = canonicalizePayload(obj);
    assert.equal(canon, '{"parameter":"COD","value":"185.40"}');
  });

  it('rejects null or undefined input', () => {
    assert.throws(() => canonicalizePayload(null), /Cannot canonicalize null or undefined payload/);
    assert.throws(() => canonicalizePayload(undefined), /Cannot canonicalize null or undefined payload/);
  });
});

describe('Cryptography — Ed25519 Key Generation and Fingerprints', () => {
  it('generates distinct Ed25519 key pairs with valid SHA-256 fingerprints', () => {
    const kp1 = generateEd25519KeyPair();
    const kp2 = generateEd25519KeyPair();

    assert.notEqual(kp1.privateKeyPem, kp2.privateKeyPem);
    assert.notEqual(kp1.publicKeyPem, kp2.publicKeyPem);
    assert.notEqual(kp1.fingerprint, kp2.fingerprint);

    // Fingerprint must be 64-character lowercase hex
    assert.match(kp1.fingerprint, /^[0-9a-f]{64}$/);
    assert.match(kp2.fingerprint, /^[0-9a-f]{64}$/);

    // Fingerprint calculation must be deterministic
    const fpAgain = calculatePublicKeyFingerprint(kp1.publicKeyPem);
    assert.equal(fpAgain, kp1.fingerprint);
  });
});

describe('Cryptography — Signature Encoding Validation', () => {
  it('accepts strictly valid 64-byte Ed25519 Base64 signatures (88 characters)', () => {
    const kp = generateEd25519KeyPair();
    const sig = signPayload({ test: 'data' }, kp.privateKeyPem);
    const check = validateSignatureEncoding(sig);
    assert.equal(check.valid, true);
    assert.equal(check.buffer?.length, 64);
  });

  it('rejects malformed Base64 characters', () => {
    const invalidChars = 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA$';
    const check = validateSignatureEncoding(invalidChars);
    assert.equal(check.valid, false);
  });

  it('rejects invalid Base64 padding or length', () => {
    const check = validateSignatureEncoding('A==');
    assert.equal(check.valid, false);
  });

  it('rejects signatures not exactly 64 raw bytes', () => {
    // 32 zero bytes Base64-encoded (44 chars)
    const thirtyTwoBytes = Buffer.alloc(32).toString('base64');
    const check = validateSignatureEncoding(thirtyTwoBytes);
    assert.equal(check.valid, false);
    assert.match(check.error || '', /Invalid signature string length|expected 64 bytes/);
  });
});

describe('Cryptography — Signing and Signature Verification', () => {
  const kpSensor = generateEd25519KeyPair();
  const kpOther = generateEd25519KeyPair();

  const originalPayload = {
    schemaVersion: 1,
    eventType: 'TELEMETRY',
    messageId: 'b2147436-3c45-48c3-ad91-03b31c64bb64',
    sensorId: 'COD-OUT-001',
    keyId: 'COD-KEY-V1',
    siteId: 'PLANT-001',
    stationId: 'ETP-OUTLET-001',
    parameter: 'COD',
    value: '185.40',
    unit: 'mg/L',
    measuredAt: '2026-10-31T12:00:00.000Z',
    sequence: 42,
    bootId: 'BOOT-2026-10-31-01',
  };

  const validSignature = signPayload(originalPayload, kpSensor.privateKeyPem);

  it('verifies a valid canonical signature under matching public key', () => {
    const isValid = verifyPayloadSignature(originalPayload, validSignature, kpSensor.publicKeyPem);
    assert.equal(isValid, true);
  });

  it('rejects verification if value is modified', () => {
    const tampered = { ...originalPayload, value: '185.41' };
    const res = verifyPayloadSignatureWithReason(tampered, validSignature, kpSensor.publicKeyPem);
    assert.equal(res.valid, false);
    assert.match(res.reason || '', /Cryptographic signature mismatch/);
  });

  it('rejects verification if sensorId is modified', () => {
    const tampered = { ...originalPayload, sensorId: 'COD-OUT-002' };
    assert.equal(verifyPayloadSignature(tampered, validSignature, kpSensor.publicKeyPem), false);
  });

  it('rejects verification if siteId is modified', () => {
    const tampered = { ...originalPayload, siteId: 'PLANT-002' };
    assert.equal(verifyPayloadSignature(tampered, validSignature, kpSensor.publicKeyPem), false);
  });

  it('rejects verification if stationId is modified', () => {
    const tampered = { ...originalPayload, stationId: 'ETP-OUTLET-002' };
    assert.equal(verifyPayloadSignature(tampered, validSignature, kpSensor.publicKeyPem), false);
  });

  it('rejects verification if parameter is modified', () => {
    const tampered = { ...originalPayload, parameter: 'TSS' };
    assert.equal(verifyPayloadSignature(tampered, validSignature, kpSensor.publicKeyPem), false);
  });

  it('rejects verification if measuredAt timestamp is modified', () => {
    const tampered = { ...originalPayload, measuredAt: '2026-10-31T12:00:01.000Z' };
    assert.equal(verifyPayloadSignature(tampered, validSignature, kpSensor.publicKeyPem), false);
  });

  it('rejects verification if sequence is modified', () => {
    const tampered = { ...originalPayload, sequence: 43 };
    assert.equal(verifyPayloadSignature(tampered, validSignature, kpSensor.publicKeyPem), false);
  });

  it('rejects verification if bootId is modified', () => {
    const tampered = { ...originalPayload, bootId: 'BOOT-2026-10-31-02' };
    assert.equal(verifyPayloadSignature(tampered, validSignature, kpSensor.publicKeyPem), false);
  });

  it('rejects verification under a different sensor public key', () => {
    const res = verifyPayloadSignatureWithReason(originalPayload, validSignature, kpOther.publicKeyPem);
    assert.equal(res.valid, false);
  });

  it('rejects signing non-object payloads', () => {
    assert.throws(() => signPayload('string', kpSensor.privateKeyPem), /Payload to sign must be a non-null object/);
    assert.throws(() => signPayload(null, kpSensor.privateKeyPem), /Payload to sign must be a non-null object/);
  });
});

