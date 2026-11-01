# 02 — Scope, Priorities and Acceptance Criteria

## 1. Scope principle

The event build window is approximately 15 active hours. The goal is a complete, defensible vertical slice, not a production platform. Implement one site, one ETP outlet, three simulated pollution sensors, one separate operations simulator, one witness service and one ML model.

## 2. Priority definitions

- **P0 — Must work:** required for the project to demonstrate its central security story.
- **P1 — Should work if time permits:** strengthens the demo but must not block P0.
- **P2 — Explicitly deferred:** do not implement during the 15-hour MVP unless P0/P1 are already stable.

## 3. P0 — Must build

### P0.1 Identity and access

- Seed demo users for three roles.
- Enforce role authorization on API routes.
- Scope factory operator to one assigned site.
- Make auditor read-only.
- Keep machine identities separate from user accounts.

### P0.2 Signed telemetry

- Generate Ed25519 key pairs for `PH-OUT-001`, `COD-OUT-001`, `TSS-OUT-001`.
- Keep private keys in local simulator storage.
- Register public keys independently in primary and witness services through provisioning.
- Sign canonicalized payload with RFC 8785 JCS.
- Verify with Node.js `crypto.verify` and registered public key.
- Reject invalid signatures and identity mismatches.
- Reject duplicate/lower sequence values under the strict MVP sequence policy.

### P0.3 Independent witness

- Sensor simulator sends the same signed envelope to primary and witness directly.
- Witness independently verifies signature.
- Witness stores its own event copy in separate storage.
- Witness builds its own hash chain.
- Witness signs checkpoint every configurable number of events (default 10 for demo, can be raised later).
- Auditor can compare primary and witness record sets by `messageId` and `payloadHash`.

### P0.4 Heartbeats

- Signed heartbeat every 10 seconds in accelerated demo mode.
- Backend marks sensor `OFFLINE` after 3 consecutive missed expected intervals plus grace period.
- Dashboard displays last heartbeat and status.

### P0.5 ML contextual COD detection

- Synthetic normal operating-context dataset.
- RandomForestRegressor predicts outlet COD from signed operating context.
- Validation-derived residual threshold.
- API returns prediction, actual, residual, threshold, model version and explanation.
- A separate injected suspicious-COD scenario must raise an anomaly in the demo.

### P0.6 Sensor-behaviour rules

- Flatline detection over a configurable rolling window.
- Sudden-change detection using rolling median/MAD or a documented simple rule.
- These are rule-based, not presented as ML.

### P0.7 UI

- Login and role-based navigation.
- Monitoring overview.
- Security status.
- Witness/audit view.
- Anomaly view.
- Controlled demo attack panel.

## 4. P1 — Stretch only after P0 passes

- One-time nonce challenge-response for device key liveness/freshness. It does not perform physical calibration.
- Key rotation UI rather than provisioning-script-only rotation.
- Second independent witness simulation.
- Downloadable signed audit report.
- More complete drift detection.
- More than one site/station.
- Chart-level historical comparison between actual and predicted COD.

## 5. P2 — Do not build in the 15-hour MVP

- Physical sensors, ESP32, pH probes or laboratory reference solutions.
- Actual remote physical calibration.
- Actual CPCB/MPCB production integration.
- Real NGO/university/regulator onboarding or claims of partnership.
- Bitcoin/OpenTimestamps anchoring.
- Full RFC 9162 Certificate Transparency implementation or full Merkle consistency proofs.
- Blockchain.
- Deep learning, LSTM, Transformers or LLM-based fraud classification.
- Predictive legal compliance certification.
- Complex multi-tenant billing or production deployment architecture.

## 6. Acceptance criteria

### AC-01 Valid telemetry

Given a registered active sensor key, when the sensor sends a correctly signed and schema-valid reading with a new sequence, primary and witness both independently verify and record it. The dashboard shows `SIGNATURE_VALID` and `WITNESS_RECEIVED`.

### AC-02 Modified telemetry

Given a signed envelope, when one signed payload field is changed without re-signing, primary and witness reject it. It does not appear as accepted telemetry. A security event is recorded.

### AC-03 Unapproved key

Given an unknown key ID or a key not enrolled for the claimed sensor/site/station/parameter, the message is rejected even if its signature is mathematically valid under the attacker's key.

### AC-04 Replay

Given an already accepted `(sensorId, bootId, sequence)` or `messageId`, a repeated submission is rejected/idempotently marked as duplicate and not appended as a new accepted reading.

### AC-05 Sequence gap

Given accepted sequence 10 followed by sequence 12, sequence 12 may be accepted under the strict-forward MVP policy but a `SEQUENCE_GAP` alert is recorded for missing 11. Do not label the gap as proven fraud.

### AC-06 Primary database tampering

Given matching primary and witness events/checkpoint, when a primary stored record is changed or deleted, reconciliation reports `PRIMARY_WITNESS_MISMATCH` or `MISSING_FROM_PRIMARY` and the checkpoint verification fails for the affected range.

### AC-07 Witness outage

If witness is unavailable, primary ingestion remains available and records `WITNESS_PENDING`/`WITNESS_LAGGING`. The UI must not falsely show independent verification as complete. Simulator retries the same `messageId`; witness ingestion is idempotent.

### AC-08 Heartbeat loss

When the simulator stops sending heartbeats, sensor status changes to `OFFLINE` after the configured timeout. UI says `NO_RECENT_HEARTBEAT` or `COMMUNICATION_LOST`, not `FRAUD`.

### AC-09 Contextual COD anomaly

Given verified operating-context features and a validly signed COD reading deliberately outside the learned normal residual threshold, ML returns `SUSPICIOUS` with predicted COD, actual COD, residual, threshold and reason. It does not invalidate signature or change telemetry.

### AC-10 Missing ML context

If context is missing, stale or failed signature verification, ML returns `NOT_EVALUATED`; it must not use the last context indefinitely.

### AC-11 Compliance exceedance

A validly signed reading above configured demo limits is retained and shown as `EXCEEDANCE`, separately from signature and ML states.

### AC-12 Role enforcement

Factory operator cannot view another site's data or manage public keys. Auditor cannot mutate site, sensor, telemetry, key or configuration records. API responds 403 for forbidden actions.

### AC-13 Private key isolation

No private key is returned in any API response, stored in frontend bundle, logged, or committed to Git.

### AC-14 Demo safety

Attack-simulation routes are unavailable unless `DEMO_MODE=true` and user has authorized role.

## 7. Minimum release gate

Do not call the MVP complete until AC-01 through AC-13 pass. AC-14 must pass before the demo is shown to others.
