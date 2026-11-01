# 11 — 15-Hour Build and Team Execution Plan

## 1. Team assumption

Plan assumes four people with parallel work. If there are fewer people, reduce the scope rather than skipping verification/testing.

- Member A: full-stack/backend integration lead.
- Member B: cryptography, sensor simulator and witness.
- Member C: ML and synthetic process data.
- Member D: frontend, test scenarios and presentation.

## 2. Required first 30 minutes

All members read this pack. Agree on:

- exact service names/ports;
- shared JSON contracts;
- database field names;
- one site/station and three sensors;
- no real institution integration;
- no physical hardware;
- the minimum demo sequence.

Do not let all members independently invent API contracts.

## 3. Timeline

### Hour 0–1: Repository and contracts

- Inspect repository.
- Create monorepo/service skeleton only if needed.
- Set up environment files and Git ignore.
- Implement shared telemetry/heartbeat/ops-context schemas.
- Run health endpoints.
- Agree on API request/response examples.

**Exit gate:** all services start; contracts validate sample payloads.

### Hour 1–3: Sensor identity and signed telemetry

- Generate three key pairs and one operations key pair.
- Provision public keys into primary and witness registries.
- Implement JCS and Ed25519 signing in simulator.
- Send one signed reading to both services.
- Implement primary and witness verification.

**Exit gate:** valid signature accepted by both; changed payload rejected by both.

### Hour 3–5: Ingestion, replay and database

- Implement schema validation.
- Implement key mapping and status check.
- Implement message ID and sensor/boot/sequence uniqueness.
- Implement timestamp policy.
- Store accepted readings transactionally.
- Add security events and sequence gap alerts.

**Exit gate:** duplicate and modified messages do not create duplicate trusted telemetry.

### Hour 5–7: Witness and audit history

- Primary per-station event chain.
- Witness independently retained chain.
- Witness checkpoint signing.
- Reconciliation endpoint.
- Dashboard-facing audit status.

**Exit gate:** modifying/deleting a primary event creates an observable primary/witness mismatch.

### Hour 7–8: Heartbeats

- Signed heartbeat payload.
- Primary/witness receive and verify.
- Offline scheduler/state transition.

**Exit gate:** stopping a simulator produces an offline alert within configured timeout.

### Hour 7–10 (parallel): ML development

- Generate normal synthetic process dataset.
- Train RandomForestRegressor for COD.
- Derive threshold using held-out normal validation residuals.
- Add flatline rule.
- Implement FastAPI endpoint and response schema.

**Exit gate:** known injected context-mismatch scenario returns `SUSPICIOUS`; missing context returns `NOT_EVALUATED`.

### Hour 8–11 (parallel): UI

- Login and role navigation.
- Monitoring overview.
- Security/witness status.
- Anomaly view.
- Demo controls.

**Exit gate:** all visible statuses come from API and display simulated-data label.

### Hour 11–13: Integration

- Wire primary API to ML.
- Wire dashboard to primary APIs.
- Reconcile witness records.
- Validate role restrictions.
- Verify error and pending states.

**Exit gate:** normal operation and at least three attacks work end to end.

### Hour 13–14: Security and regression tests

Run the P0 tests in `10_TESTING_AND_SECURITY_REVIEW.md`. Fix critical failures first.

### Hour 14–15: Demo and presentation

Rehearse the exact five-minute sequence. Prepare a short architecture diagram, security boundaries, limitations and live attack demonstration.

## 4. Hard cut line if time runs out

Preserve these, in order:

1. Valid and invalid Ed25519 verification.
2. Primary persistence and replay prevention.
3. Independent witness direct ingestion and signature verification.
4. Witness checkpoint/reconciliation.
5. One working ML COD contextual anomaly.
6. Dashboard showing the above.
7. Signed heartbeat if time remains.
8. Challenge-response only after everything above is stable.

If time is tight, reduce UI polish, not security tests. If ML service integration is delayed, demonstrate the Python model locally with a documented test fixture; do not fake a live API response.

## 5. Dependency order

Do not build frontend dashboards before payload contracts and API response shapes are agreed. UI can develop against mocked responses temporarily, but must switch to actual services before final testing.

## 6. End-of-hour update template

Each member reports:

- Done:
- Not done:
- Files changed:
- Tests passed/failed:
- Blocker:
- Next 60-minute goal:

## 7. Demo sequence (approximately five minutes)

1. Normal operation: show authenticated sensor readings and witness receipt.
2. Modify signed payload: show invalid signature rejection.
3. Alter primary historical record: show independent witness mismatch.
4. Stop one simulator: show heartbeat loss.
5. Send validly signed but process-context-inconsistent COD: show ML alert while signature/witness remain valid.
6. Show auditor verification detail and explain limitations.


## Ownership clarification

Antigravity implements the React app, Express API, primary DB, simulators, cryptographic pipeline, witness service, dashboard, attack scenarios and ML integration client. The designated human teammate separately implements the Python model/FastAPI service under `services/ml/`. Do not assign Prompt 6's former ML model implementation to Antigravity; use the revised Prompt 6 in `12_ANTIGRAVITY_PROMPTS.md` for integration only. Read `OWNERSHIP_AND_AGENT_BOUNDARIES.md` and `ENVIRONMENT_SETUP.md`.
