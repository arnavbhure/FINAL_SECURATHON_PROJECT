# 10 — Testing and Security Review Plan

## 1. Test philosophy

Security features must be tested by positive and negative cases. A dashboard status alone is not evidence that a security mechanism works.

Every test should specify setup, action, expected result and evidence. Test with deterministic fixtures and fixed synthetic-data seeds.

## 2. Unit tests — cryptography

- Generate Ed25519 key pair.
- Sign a canonical telemetry payload.
- Verify correct payload succeeds.
- Change `value`; verification fails.
- Change `measuredAt`; verification fails.
- Change `sensorId`; verification fails.
- Change `sequence`; verification fails.
- Verify with another sensor public key; fails.
- Malformed Base64 signature is rejected safely.
- Unknown key is rejected before acceptance.
- Wrong parameter/site/station mapping is rejected.
- Ensure private key never appears in response/log.

## 3. Unit tests — JCS

- Same logical object with different property order canonicalizes identically.
- Changed value canonicalizes differently.
- Invalid/unsupported JSON data rejected.
- Signing and verification use the same canonicalization package/version and exact payload.
- Decimal string values remain unchanged.

## 4. Replay and freshness tests

- Re-submit identical message ID: no duplicate accepted event.
- Re-submit same sensor/boot/sequence with new message ID: reject as duplicate/replay.
- Submit lower sequence: reject under strict MVP policy.
- Skip sequence: accept next valid higher sequence and create sequence-gap alert.
- Future timestamp beyond configured tolerance: reject/quarantine.
- Stale timestamp beyond configured window: mark delayed/reject according to config; test exact policy.
- Retry same envelope after network error: idempotent response.

## 5. Witness tests

- Witness verifies valid envelope independently.
- Witness rejects tampered payload.
- Witness rejects unknown/revoked key.
- Witness stores its own copy.
- Witness builds deterministic chain.
- Checkpoint signature verifies with pinned witness public key.
- Changed checkpoint payload fails signature verification.
- Changed witness event fails chain verification.
- Deleted primary event is detected by reconciliation if witness retained it.
- Missing witness record is shown as pending/lagging/missing, not silently treated as valid.
- Primary and witness downtime produce clear states.
- Duplicate delivery to witness is idempotent.

## 6. Heartbeat tests

- Valid signed heartbeat updates last seen.
- Invalid signature does not update liveness.
- Replayed heartbeat does not count as a new heartbeat.
- Stop simulator; status moves online → stale → offline after configured intervals.
- Restart simulator; a valid heartbeat restores online state.
- UI wording does not claim intentional shutdown.

## 7. ML tests

- Model trains deterministically with fixed seed.
- Train/validation/test split does not leak adjacent samples from same simulation run.
- Model predicts on a known normal fixture.
- Normal held-out samples produce the expected false-positive baseline.
- Injected context-inconsistent COD scenario produces residual above the learned threshold.
- Missing context returns `NOT_EVALUATED`.
- Stale context returns `NOT_EVALUATED`.
- Unverified context is rejected/not evaluated.
- Flatline rule flags repeated near-identical readings after minimum window.
- Normal stable values below configured tolerance do not automatically alert.
- Model result includes model version, prediction, residual, threshold and reasons.
- ML failure does not prevent accepted telemetry persistence.
- ML result never changes original signed payload.

## 8. RBAC/security tests

- Unauthenticated user cannot access dashboard APIs.
- Factory operator cannot access another site by changing URL/site ID.
- Factory operator cannot register/revoke sensor keys.
- Auditor cannot mutate telemetry, key registry, site configuration or compliance profile.
- Demo attack endpoints are disabled when `DEMO_MODE=false`.
- Public API never returns private keys or service secrets.
- CORS allows only configured frontend origin(s).
- Rate limits and request-size limits are applied to ingestion/login.
- SQL injection payload does not alter queries.
- XSS strings render as text, not executable markup.
- Cookies/tokens follow documented secure settings.

## 9. End-to-end acceptance scenarios

### Scenario A — Normal operation

Start all simulators. Verify all three sensors send signed readings to primary and witness. Verify heartbeat status online. Check audit checkpoint and dashboard.

### Scenario B — Modified in transit

Simulator signs a COD payload. A demo interceptor changes COD before one endpoint receives it. That endpoint rejects it. The other endpoint may receive original valid envelope. Dashboard shows mismatch/one-sided delivery.

### Scenario C — Primary history tampering

Use a controlled test script to alter/delete a primary record after witness has stored it. Reconciliation detects mismatch. Do not expose raw SQL attack controls in production UI.

### Scenario D — Sensor shutdown

Stop one simulator. Heartbeat timeout creates offline alert. Primary and witness show last receipt time.

### Scenario E — Validly signed suspicious data

Trigger `CONTEXT_MISMATCH` or `FLATLINE` scenario. Sign all telemetry normally. Signature and witness statuses remain valid while ML/rules raise a separate alert.

### Scenario F — Valid environmental exceedance

Send a validly signed reading above demo profile. Signature valid, witness valid, compliance exceedance shown. Do not call it a cyberattack.

## 10. Manual review checklist

Before demo:

- Inspect all cryptographic code line by line.
- Confirm private keys are outside web bundle, database payloads, logs and Git.
- Confirm canonicalization is RFC 8785, not generic JSON.stringify.
- Confirm the witness independently verifies the envelope.
- Confirm primary and witness storage are separate.
- Confirm no secret is hardcoded in source.
- Confirm no route trusts a frontend role value.
- Confirm all statuses are separate and precise.
- Confirm ML uses only verified and time-aligned context.
- Confirm synthetic-data and model limitations are displayed.
- Confirm no real NGO/government/PCB affiliation is implied.
- Run all P0 acceptance tests.

## 11. Definition of done

A phase is done only when code, tests, error handling, documentation and review are complete. A feature that only works in the happy path is not done.
