# Code Review Checklist — EnviroTrust

Use this checklist for every Antigravity-generated phase/PR. A reviewer other than the code author should inspect security-sensitive changes.

## A. Before review

- [ ] Requirement/acceptance criterion linked to the change.
- [ ] Diff is focused; no unrelated rewrites.
- [ ] No generated `node_modules`, build output, model artifacts or secret files committed.
- [ ] Tests added for success and failure paths.
- [ ] Commands and results recorded.

## B. Cryptography

- [ ] Uses Node.js maintained crypto APIs; no custom signature/hash implementation.
- [ ] Ed25519 private key is only in the relevant simulator/witness process.
- [ ] No private key is sent over an API or stored in browser storage.
- [ ] Public keys are pre-enrolled and bound to sensor/site/station/parameter.
- [ ] Signatures cover the complete canonical payload, not a subset.
- [ ] RFC 8785 JCS is used consistently; no JSON.stringify substitution.
- [ ] Signature Base64 decoding is strict and malformed signatures fail safely.
- [ ] Signature verification occurs before trusted telemetry insertion.
- [ ] Sensor, operations and witness keys are distinct.
- [ ] SHA-256 is used for digesting; code does not call hashes encryption.

## C. Replay/freshness

- [ ] Message ID is unique and idempotent.
- [ ] `(sensorId, bootId, sequence)` uniqueness is enforced in database.
- [ ] Replay checks are transactional to prevent concurrent duplicate race.
- [ ] Sequence gaps are alerts, not automatically fraud.
- [ ] Sensor timestamp and server receipt time are both retained.
- [ ] Configurable clock-skew/age validation is applied.

## D. Witness

- [ ] Sensor sends same envelope directly to primary and witness.
- [ ] Witness independently verifies sensor signature.
- [ ] Witness has separate public-key registry/storage/credentials.
- [ ] Witness retains original envelope and own event history.
- [ ] Witness chain appends are serialized/transactional.
- [ ] Checkpoint signed only after persistence.
- [ ] Checkpoint signature verifies with pinned witness public key.
- [ ] Primary/witness reconciliation compares message IDs and payload hashes.
- [ ] Missing witness is `PENDING`/`LAGGING`, not falsely verified.
- [ ] UI says simulated witness, not real NGO/university/government approval.

## E. ML

- [ ] Only signature-verified COD and operations context reach inference.
- [ ] Context source signature is separately verified.
- [ ] Context time interval matches the COD reading.
- [ ] Missing/stale/unverified context returns `NOT_EVALUATED`.
- [ ] Model training uses normal synthetic data only.
- [ ] Train/test split avoids time/run leakage.
- [ ] Residual threshold comes from validation data, not arbitrary hardcoding.
- [ ] Model version and reasons are saved.
- [ ] Model output never mutates source telemetry.
- [ ] UI labels output as anomaly/inconsistency, not proven fraud.
- [ ] Synthetic data and limitations are disclosed.

## F. API, database and access control

- [ ] Request schemas are strict and have size limits.
- [ ] Database uses parameterized queries or safe ORM.
- [ ] Critical inserts are transactional.
- [ ] Role checks happen server-side.
- [ ] Factory users are site-scoped server-side.
- [ ] Auditor routes are read-only server-side.
- [ ] CORS uses exact allow-listed origins.
- [ ] Cookie/session settings are appropriate; CSRF addressed if cookie auth used.
- [ ] Rate limits applied to login and ingestion.
- [ ] Secrets never appear in API responses/logs.
- [ ] Demo routes disabled outside DEMO_MODE.

## G. UI and product truth

- [ ] Signature, witness, availability, calibration, ML and compliance statuses remain separate.
- [ ] Every page states that data is simulated for the prototype.
- [ ] No fabricated regulatory limit, legal claim or partner endorsement.
- [ ] Charts have accessible labels/textual summaries.
- [ ] Empty/loading/error/pending states exist.
- [ ] No decorative fake metric is presented as a real result.

## H. Review decision

- [ ] Approved.
- [ ] Approved with documented non-critical follow-ups.
- [ ] Rejected — critical issue(s) must be fixed.

Reviewer notes:

- Critical findings:
- Non-critical findings:
- Tests not run:
- Residual risks:
