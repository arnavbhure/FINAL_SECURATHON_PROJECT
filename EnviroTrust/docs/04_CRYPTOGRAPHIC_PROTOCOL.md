# 04 — Cryptographic Protocol and Sensor Identity

## 1. Cryptographic responsibilities

| Mechanism | Algorithm/technology | Purpose |
|---|---|---|
| Sensor signatures | Ed25519 | Authenticate the registered signing-key holder and detect signed-payload modification |
| Operating-context signatures | Ed25519 with a different key | Authenticate the operations simulator's context records |
| Heartbeat signatures | Ed25519 | Authenticate liveness messages |
| Canonicalization | RFC 8785 JCS | Ensure signer and verifier sign/verify identical bytes |
| Payload/event hashes | SHA-256 | Produce deterministic fingerprints |
| Transport protection | HTTPS/TLS | Confidentiality and integrity in transit |
| User passwords | Argon2id preferred | Password hashing, not reversible encryption |

Ed25519 is a digital-signature algorithm. It does not encrypt data. TLS protects network communication. Do not describe the signed telemetry as encrypted by Ed25519.

## 2. Key roles

### Sensor keys

Each simulated sensor has a unique key pair. Private key remains in local simulator key storage. Public key is enrolled in primary and witness registries. Example IDs:

- `PH-OUT-001` / `PH-KEY-V1`
- `COD-OUT-001` / `COD-KEY-V1`
- `TSS-OUT-001` / `TSS-KEY-V1`

### Operations key

A separate `OPS-001` key pair signs operating-context records. It must not reuse any pollution sensor key.

### Witness key

The witness service has a separate Ed25519 key pair. Its private key signs checkpoints only. It never signs sensor measurements.

### User identity

Human login uses password hashing and session/token authentication. User login keys are not used to sign sensor data in the MVP.

## 3. Key provisioning

For the hackathon:

1. Run a provisioning script once per sensor and operations source.
2. Generate an Ed25519 key pair using Node.js `crypto.generateKeyPairSync('ed25519', ...)`.
3. Write private key into local simulator-only directory with restrictive permissions.
4. Compute public-key fingerprint from DER/SPKI bytes using SHA-256; display fingerprint.
5. Admin approves sensor ID, site ID, station ID, parameter and public-key fingerprint.
6. Register approved public key in primary registry.
7. Provision the same public key independently into witness registry through an explicit provisioning step/script.
8. Mark key `ACTIVE` only after both registries acknowledge it.

Do not accept a public key embedded in a telemetry request as its own trust anchor. Unknown keys are rejected.

Prototype key files are not hardware protected. Clearly document this limitation. Never commit private key files.

## 4. Telemetry payload contract

Use `contracts/telemetry.schema.json`.

Required fields:

- `schemaVersion`
- `eventType` = `TELEMETRY`
- `messageId` (UUID)
- `sensorId`
- `keyId`
- `siteId`
- `stationId`
- `parameter` in `pH`, `COD`, `TSS`
- `value` as decimal string
- `unit`
- `measuredAt` ISO-8601 UTC timestamp
- `sequence` positive integer
- `bootId` UUID/string unique per simulator boot session
- `calibrationRecordId` optional nullable reference

The signature covers the entire `payload` object, not the envelope signature field.

## 5. Canonicalization and signing

1. Validate the payload against the strict schema.
2. Reject unknown or duplicate properties as appropriate to the canonicalization implementation.
3. Canonicalize the payload using RFC 8785 JCS.
4. Encode canonical string as UTF-8.
5. Sign using Node.js `crypto.sign(null, canonicalBytes, privateKey)` for Ed25519.
6. Encode signature as standard Base64 in the envelope.

Verifier repeats the same schema validation and canonicalization, then calls `crypto.verify(null, canonicalBytes, registeredPublicKey, signatureBytes)`.

Do not use plain `JSON.stringify()` as a replacement for JCS. Do not reorder or mutate payload fields after signing. Decimal values are strings to avoid cross-language floating-point serialization ambiguity.

## 6. Signature verification order

For incoming telemetry, perform these checks:

1. Request size/content type and schema validation.
2. `keyId` exists in approved key registry.
3. Key status is active and key validity policy passes.
4. Key is bound to claimed `sensorId`, `siteId`, `stationId` and `parameter`.
5. Canonicalize payload.
6. Decode signature with strict Base64 validation and check expected Ed25519 signature length.
7. Verify signature using the stored public key.
8. Check message ID and replay/sequence constraints transactionally.
9. Check timestamp/freshness policy.
10. Check configuration/calibration metadata. Calibration status is separate from signature validity.
11. Persist accepted telemetry transactionally.

A signature-valid payload can still be out of range or suspicious. Do not reject a valid environmental exceedance as an invalid signature.

## 7. Replay and sequence policy

MVP policy:

- `messageId` must be unique.
- `(sensorId, bootId, sequence)` must be unique.
- Sequence is strictly increasing per sensor boot session.
- Duplicate or lower-than-last accepted sequence is rejected as duplicate/replay/out-of-order for the strict demo implementation.
- A forward gap is accepted but creates `SEQUENCE_GAP` alert.
- The simulator retries the same envelope with the same message ID and sequence.

This strict policy may reject legitimate out-of-order messages. A production version should support a bounded reordering window and delayed-upload semantics.

## 8. Timestamp policy

Store two separate times:

- `measuredAt`: sensor-signed device timestamp.
- `receivedAt`: server clock time assigned after receipt.

Use a configurable clock-skew/freshness policy. For the demo, defaults may be 120 seconds maximum future skew and 300 seconds maximum age; keep these in configuration, not hardcoded in many files. Demo timestamps use real UTC time even when simulator intervals are accelerated.

A sensor-signed timestamp is not a trusted independent timestamp authority. It can be wrong if the device clock is wrong or compromised. Witness receipt time adds a separate observation time but does not prove the physical time of measurement.

## 9. Heartbeat protocol

Use `contracts/heartbeat.schema.json`.

Heartbeat fields: schema version, event type, message ID, sensor ID, key ID, boot ID, heartbeat sequence and sent time. Sign the complete payload with the sensor key.

Default demo settings:

- heartbeat interval: 10 seconds
- missed intervals before offline: 3
- grace period: 5 seconds

Result status: `ONLINE`, `STALE`, `OFFLINE`. Do not label this as proof of intentional shutdown.

## 10. Operating-context protocol

Use `contracts/ops-context.schema.json`. It has a separate `OPS-001` key pair and signed payload. It contains:

- `messageId`, `sourceId`, `keyId`, `siteId`, `stationId`
- `intervalStart`, `intervalEnd`, `sequence`
- `productionRate`, `wastewaterFlow`, `treatmentDose`, `energyConsumption`
- `operatingMode`
- units/schema version

The primary backend verifies this signature before the record is eligible for ML. The same process simulator is synthetic; do not claim genuinely independent real-world measurements.

## 11. Optional nonce challenge

If P0 is complete, implement a device liveness challenge:

1. Server generates a cryptographically random 32-byte nonce.
2. Server stores challenge ID, nonce hash, device ID, creation/expiry and unused status.
3. Simulator receives challenge and returns a signed response containing challenge ID, nonce, sensor ID, key ID and response time.
4. Server verifies the response signature and matches the nonce to the unexpired, unused challenge.
5. Server atomically marks challenge used.
6. Reuse, expiry or wrong device fails.

This demonstrates fresh proof of possession of the device private key. It does **not** prove physical calibration or that the sensor measured a reference liquid.

## 12. Error codes

Use stable reason codes:

- `INVALID_SCHEMA`
- `UNKNOWN_KEY`
- `KEY_NOT_ACTIVE`
- `KEY_SENSOR_MISMATCH`
- `KEY_SITE_MISMATCH`
- `KEY_STATION_MISMATCH`
- `KEY_PARAMETER_MISMATCH`
- `INVALID_SIGNATURE`
- `INVALID_SIGNATURE_ENCODING`
- `DUPLICATE_MESSAGE`
- `REPLAYED_SEQUENCE`
- `SEQUENCE_GAP`
- `TIMESTAMP_FUTURE`
- `TIMESTAMP_STALE`
- `CALIBRATION_EXPIRED`
- `WITNESS_PENDING`

Do not reveal secret internals in public error responses. Detailed error reasons belong in sanitized security logs.

## 13. References

- RFC 8032 (EdDSA): https://www.rfc-editor.org/rfc/rfc8032
- RFC 8785 (JCS): https://www.rfc-editor.org/rfc/rfc8785
- Node.js Crypto API: https://nodejs.org/api/crypto.html
- NISTIR 8259A: https://csrc.nist.gov/pubs/ir/8259/a/final
