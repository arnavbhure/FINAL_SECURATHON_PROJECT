# 05 — Independent Witness and Audit Integrity Specification

## 1. Purpose

The witness addresses a limitation of a hash chain stored only in the primary database: a privileged attacker who can rewrite the entire database may recalculate the chain. An independent party must retain its own record/checkpoint so the primary system cannot silently rewrite history without creating a discrepancy.

## 2. Product decision

MVP uses one **Simulated Independent Witness Service**. Its display name can be configured as “Independent University/NGO Witness — Simulation”, but it must not imply a real institution participates.

The service is:

- A separate Node.js process.
- A separate service identity.
- A separate Ed25519 checkpoint signing key.
- A separate storage location/database and credentials.
- A separate sensor public-key registry provisioned independently.
- Read-only to the primary API except for ingestion through its defined endpoint.

A second witness is P1 stretch. Do not implement multiple real organizations in the 15-hour MVP.

## 3. Why sensors send directly to witness

Do not make the primary backend the only source of witness input. The sensor simulator sends the same signed envelope directly to both:

- Primary ingestion API.
- Witness ingestion API.

This allows the witness to independently observe a message even if the primary later omits it. The sensor uses the same `messageId`, payload and signature for both destinations. Retries are idempotent.

This is still a simulation: the simulator process controls both destinations, and local services may share physical infrastructure. Production independence needs separately administered infrastructure and trust provisioning.

## 4. Witness ingestion

Endpoint: `POST /witness/v1/ingestion/readings`.

Witness must:

1. Validate schema and request limits.
2. Look up its own approved public key by `keyId`.
3. Verify sensor/key/site/station/parameter binding.
4. Canonicalize payload using RFC 8785.
5. Independently verify Ed25519 signature.
6. Enforce `messageId` and sequence uniqueness/idempotency.
7. Store original payload, signature, payload hash and witness receipt time in witness storage.
8. Append witness event to its own chain.
9. Return witness event ID, receipt time and current witness-chain sequence.

The witness must not trust a `signatureValid` field sent by primary. It performs verification itself.

## 5. Witness event format

Example logical record:

```json
{
  "witnessEventId": "WEVT-uuid",
  "messageId": "same-sensor-message-id",
  "siteId": "PLANT-001",
  "stationId": "ETP-OUTLET-001",
  "sensorId": "COD-OUT-001",
  "keyId": "COD-KEY-V1",
  "sensorSequence": 1001,
  "payloadHash": "sha256-hex",
  "signatureHash": "sha256-hex",
  "witnessReceivedAt": "UTC timestamp",
  "witnessSequence": 1001,
  "previousWitnessHash": "hex-or-null",
  "witnessEventHash": "sha256-hex"
}
```

The witness stores the complete original signed envelope separately so the event can be independently re-verified later. Do not treat the example IDs/timestamps as fixed.

## 6. Witness hash chain

Use a domain separator to prevent the same hash input being confused with another purpose:

`witnessEventHash = SHA256(UTF8("ENVIROTRUST-WITNESS-V1\n") || previousHashBytes || JCS(witnessEventWithoutHash))`

For the first event, use a documented fixed genesis value (e.g. 32 zero bytes) and test it. Store hashes as lowercase 64-character hex strings.

Events are appended in a database transaction or serialized single-writer queue. Concurrent appends must not fork the chain.

## 7. Signed checkpoints

Default demo threshold: every 10 accepted witness events per station. Make the interval configurable.

Checkpoint payload fields:

- `schemaVersion`
- `checkpointId`
- `witnessId`
- `siteId`
- `stationId`
- `checkpointSequence`
- `lastWitnessSequence`
- `chainHeadHash`
- `previousCheckpointHash`
- `createdAt`

Witness canonicalizes checkpoint payload and signs it with its own Ed25519 private key. Signature is stored separately from payload. Auditor uses a pinned witness public key/fingerprint to verify.

Checkpoint must be created only after the witness has persisted the corresponding event records. Never sign a chain head that has not been stored.

## 8. Reconciliation

Primary and witness histories are compared by `messageId` and `payloadHash`, not just row count.

Report categories:

- `MATCHED`: same message ID and payload hash exist on both sides.
- `MISSING_FROM_PRIMARY`: witness received it, primary does not have it.
- `MISSING_FROM_WITNESS`: primary accepted it, witness has not received it by the defined deadline.
- `PAYLOAD_MISMATCH`: same message ID but different payload hash.
- `SIGNATURE_MISMATCH`: envelope/signature differs or fails re-verification.
- `CHECKPOINT_INVALID`: witness checkpoint signature invalid.
- `CHAIN_INVALID`: recomputed witness chain differs.
- `WITNESS_LAGGING`: not enough time has passed or witness service is unavailable; not automatically tampering.

The primary must not overwrite a mismatch with a “fixed” status. An authorized investigation may append a resolution event, preserving the original discrepancy.

## 9. What witness signing means

- Sensor signs each measurement.
- Witness independently verifies each measurement and stores its own receipt/history.
- Witness signs periodic checkpoints.
- NGO/university/regulator does not sign every reading in the MVP.

A witness checkpoint attests that the witness service retained a particular chain head at/around its recorded checkpoint time. It does not attest that the physical measurement is accurate or that an NGO inspected the factory.

## 10. Outage and retry

- Sensor sends same envelope to primary and witness.
- Each destination uses `messageId` idempotency.
- Retry same envelope, same signature, same sequence.
- If witness is unavailable, primary may accept the reading but mark witness receipt `PENDING`/`LAGGING`.
- Dashboard must not show “independently verified” until witness receipt is confirmed.
- The simulator may use bounded retries with exponential backoff. For a short prototype, retry 3 times and preserve a local failed-envelope file/outbox if feasible.

## 11. Threat limitations

The witness provides meaningful logical independence only if its storage, key and administrator access are separate. If primary and witness processes, disks, credentials and administrators are all compromised together, guarantees weaken. A local laptop demo does not provide real institutional independence.

The witness only sees what the sensor simulator sends to it. If a compromised simulator suppresses a reading before sending it to either endpoint, the witness cannot know that reading existed. Heartbeats, expected sequence windows and an independent source are useful but do not solve every omission attack.

## 12. P1 second witness

If P0 is complete, add a second simulated witness that receives checkpoint payload/signature from the first witness, verifies using a pinned public key and stores its own checkpoint copy. Label it as a simulation. Do not claim real NGO participation.
