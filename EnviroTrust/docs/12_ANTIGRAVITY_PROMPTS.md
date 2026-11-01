# 12 — Antigravity Prompt Pack

Use these prompts sequentially. Do not paste all prompts at once. The agent must obey `AGENT_RULES.md` and the specification pack.

## Prompt 0 — Repository and product architecture inspection (NO CODE CHANGES)

```text
You are the application implementation agent for EnviroTrust. This is an existing repository task, not permission to generate the whole product immediately.

FIRST: inspect the current workspace/repository root. Locate the EnviroTrust specification pack. Read these documents completely, not just their headings:
- AGENT_RULES.md
- README.md
- OWNERSHIP_AND_AGENT_BOUNDARIES.md
- ENVIRONMENT_SETUP.md
- 01_PRODUCT_REQUIREMENTS.md through 13_DECISIONS_AND_OPEN_ITEMS.md
- ML_TEAMMATE_HANDOFF.md
- CODE_REVIEW_CHECKLIST.md
- DEMO_SCRIPT.md
- GLOSSARY.md
- every JSON Schema in contracts/ (including the ML request and result contracts)
- both SQL reference schemas in database/

Also inspect all existing source files, package manifests/lockfiles, scripts, .env files (do not print secret values), database setup/migrations, tests, and current Git status. Do not overwrite working code merely to match a suggested folder structure.

OWNERSHIP BOUNDARY — NON-NEGOTIABLE:
You (Antigravity) implement:
1. React + TypeScript frontend/dashboard and role-based access UI.
2. Node.js + Express primary API and PostgreSQL primary schema/migrations.
3. Node.js sensor and operations-context simulators.
4. Ed25519 key provisioning, JCS canonicalization, signing in simulators, and signature verification in primary API.
5. Replay/freshness checks, signed heartbeats, SHA-256 audit chain.
6. Separate Node.js witness service, separate storage, independent signature verification, reconciliation and signed checkpoints.
7. Demo-only attack scenarios, frontend integration, tests, scripts, environment validation and documentation for those components.
8. ML integration only: backend HTTP client, schema validation, persistence, dashboard display, health/readiness handling and (only if needed) a clearly isolated test mock.

A DIFFERENT HUMAN TEAMMATE owns the Python ML implementation under services/ml/: synthetic dataset generator, RandomForestRegressor training, residual threshold, flatline/sudden-change rules, FastAPI inference endpoint, model artifact, ML tests and ML run instructions. DO NOT implement or rewrite the Python model/service. Do not spend this build agent's scope generating ML training code. Read 06_ML_SPECIFICATION.md and ML_TEAMMATE_HANDOFF.md to understand the exact contract and integration boundary.

PRODUCT FACTS:
- This is a software-only simulated industrial effluent monitoring prototype; no physical sensors are connected.
- Fixed demo site/station/sensor identifiers and roles are in 13_DECISIONS_AND_OPEN_ITEMS.md.
- React never holds sensor or witness private keys.
- Sensors sign their own telemetry; primary and witness independently verify.
- Sensor simulator sends the same signed envelope directly to primary and witness.
- Witness retains its own event history and signs periodic checkpoints; it is labelled “Simulated Independent Witness”.
- TLS is transport encryption; Ed25519 is signatures; SHA-256 is hashing. Do not call signatures encryption.
- ML analyzes only backend-verified COD and signed operations context. ML does not prove fraud and must not block ingestion.
- Do not claim real NGO, university, CPCB or MPCB participation, physical calibration, regulatory approval, or real-world ML accuracy.

TECH STACK BASELINE:
- Frontend: React + TypeScript + Vite + Tailwind (respect existing repo if already configured).
- Primary backend: Node.js + Express.
- Primary/witness persistence: PostgreSQL, using separate databases/credentials for witness storage.
- Sensor/operations simulators: Node.js processes.
- Cryptography: Node.js built-in crypto Ed25519 and SHA-256; RFC 8785-compatible JCS library.
- Independent witness: separate Node.js service and separate storage.
- ML: Python + FastAPI + scikit-learn, implemented by the human ML teammate, not you.
- Ports and environment variables are described in ENVIRONMENT_SETUP.md.
Do not add Redis, Kafka, blockchain, Docker orchestration, LLM services or unrelated dependencies without an explicit reason and approval.

RETURN AN INSPECTION REPORT ONLY. Do not edit files, install dependencies, run migrations, create keys, seed data or start implementing.

Your report must contain:
1. Repository baseline: current folders, languages, framework versions, package managers, scripts, tests and Git status. Do not reveal secret values.
2. Specification files read: list them and identify any unreadable/missing file.
3. Ownership matrix: explicitly separate your application/crypto/witness/UI work from the human teammate's Python ML work.
4. Architecture map: map each required service to an existing or proposed folder and process/port.
5. Reuse assessment: what existing code can be preserved and what is genuinely missing.
6. Contract review: verify consistency of telemetry, heartbeat, operations-context and ML request/response schemas. Report exact discrepancies; do not invent fields.
7. Database review: compare current schema with primary-schema.sql and witness-schema.sql; identify constraints/indexes/migrations needed.
8. Environment setup report: list each variable needed by each process, whether it is already configured, and which values the human team must supply. Never print existing secret values. Do not invent production credentials.
9. Dependency proposal: exact packages to add, why each is needed, and whether an equivalent already exists.
10. Security risks and mitigation: private-key handling, key enrollment, replay protection, independent witness storage, RBAC/site scoping, CORS/CSRF, demo route isolation, secret handling and service-to-service authentication.
11. Phased implementation plan for the 15-hour MVP, with clear ownership and test gates.
12. First implementation phase you recommend and its acceptance tests.
13. All blockers/open decisions that require human approval.

If documents conflict, quote the filenames and exact conflicting requirements and stop that part. Do not silently resolve security design conflicts. Do not claim anything has been implemented. End by waiting for explicit approval to begin Prompt 1.
```

## Prompt 1 — Contracts and skeleton

```text
Implement only the approved project skeleton and shared contracts. Use the exact schemas in contracts/. Add service health endpoints and basic environment validation. Do not implement signing, ingestion, ML or dashboard features yet. Preserve existing working code. Add tests that validate sample telemetry, heartbeat and operations-context payloads. Run the relevant checks and report changed files and results.
```

## Prompt 2 — Key provisioning and sensor signing

```text
Implement sensor key provisioning and the sensor simulator only. Use Node.js built-in Ed25519 crypto APIs and a maintained RFC 8785 JCS canonicalizer. Generate separate keys for PH-OUT-001, COD-OUT-001, TSS-OUT-001 and OPS-001. Private keys must remain in local simulator-only storage outside the frontend and Git. Public keys are exported for explicit provisioning to primary and witness registries. Implement signed telemetry and heartbeat payload generation exactly as documented. Add tests proving changed fields invalidate signatures. Do not implement backend ingestion yet.
```

## Prompt 3 — Primary API verification and ingestion

```text
Implement the primary Express ingestion pipeline. Follow 04_CRYPTOGRAPHIC_PROTOCOL.md and contracts exactly. Validate schema, find pre-enrolled public key, enforce key-to-sensor/site/station/parameter mapping, JCS-canonicalize and verify Ed25519 signature, then apply messageId and sensor/boot/sequence replay constraints transactionally. Store accepted telemetry immutably and record rejected attempts as security events. Do not trust a public key supplied in the request. Do not let ML or compliance checks reject a valid signed environmental exceedance. Add positive and negative tests. Do not implement the UI in this phase.
```

## Prompt 4 — Independent witness service

```text
Implement the independent witness as a separate process and separate storage. The sensor simulator sends the same signed telemetry envelope directly to the witness endpoint. The witness has its own provisioned public-key registry and MUST independently verify the original sensor signature; it must not trust a verification result from primary. Store its own event copy, create a separate per-station hash chain and sign periodic checkpoints using a separate witness Ed25519 private key. Implement idempotent retry handling and primary-versus-witness reconciliation. Never expose witness private key. Add tests for valid data, tampering, duplicates, checkpoint signature failure, missing primary record and witness lag.
```

## Prompt 5 — Heartbeats and optional challenge

```text
Implement signed heartbeats using the exact heartbeat schema. Track last valid heartbeat and transition ONLINE -> STALE -> OFFLINE based on configurable interval, missed count and grace period. A missing heartbeat must be described as communication loss, not proven deliberate shutdown. If and only if P0 tests pass, implement the optional one-time nonce liveness challenge described in 04_CRYPTOGRAPHIC_PROTOCOL.md. Do not call it physical calibration.
```

## Prompt 6 — ML integration only (DO NOT IMPLEMENT THE MODEL)

```text
Implement only the Express-side integration with the separately owned Python ML service. The human ML teammate owns services/ml/ and will implement the FastAPI model.

Read OWNERSHIP_AND_AGENT_BOUNDARIES.md, ML_TEAMMATE_HANDOFF.md, 06_ML_SPECIFICATION.md and contracts/ml-result.schema.json.

Implement:
1. A typed ML HTTP client using ML_BASE_URL, ML_TIMEOUT_MS, ML_ENABLED and Authorization: Bearer ML_SERVICE_TOKEN when configured.
2. Request construction using only backend-verified COD telemetry and backend-verified, time-aligned OPS-001 context. The browser must never set contextVerified.
3. Request and response validation against the documented ML contract.
4. Persistence of immutable analysis results in the primary database, separate from original signed telemetry.
5. Correct statuses for disabled, pending, timeout, service unavailable, NOT_EVALUATED, CONSISTENT and SUSPICIOUS.
6. Health/readiness handling for GET /ml/v1/health.
7. Integration tests using a clearly named test-only mock server if the human teammate's ML service is not yet available.
8. Dashboard/API data contract for displaying expected COD, actual COD, residual, threshold, model version and reasons.

DO NOT create or modify Python model/training code under services/ml/. DO NOT train a RandomForestRegressor. DO NOT invent response fields or status enums. If the ML teammate's service is not ready, keep ML_ENABLED=false by default and ensure telemetry ingestion, witness processing and audit logging continue normally. A mock response must be visibly identified as TEST MOCK and must never be stored or displayed as a genuine ML result in the final demo.

Add tests for valid response, invalid response shape, timeout, unavailable service, missing/stale context and ensuring ML errors do not reject valid telemetry. Report changed files and test results.
```

## Prompt 7 — Dashboard

```text
Implement the React dashboard according to 08_UI_UX_AND_ACCESS_CONTROL.md. Use real API data for final integration. Implement role-based navigation and views for monitoring, sensors/keys, security events, audit/witness, anomaly investigation and demo attack controls. Enforce that the auditor is read-only and factory operator is site-scoped in both UI and API. Clearly separate signature, witness, availability, calibration, ML and compliance statuses. Show SIMULATED DATA — HACKATHON PROTOTYPE visibly. Do not expose any private key or secret.
```

## Prompt 8 — Attack simulator and demo fixtures

```text
Implement controlled demo scenarios only when DEMO_MODE=true: tamper with signed envelope before one destination receives it; replay a prior envelope; modify/delete a primary test audit record; stop a simulator; generate validly signed flatline readings; generate a validly signed context-mismatch COD reading. Scenarios must operate only on synthetic demo site data. Add explicit tests and verify each detection result. Do not build a general-purpose production attack endpoint.
```

## Prompt 9 — Final security review

```text
Do not add features. Review the whole repository against every requirement and acceptance test in the specification pack. Inspect cryptographic code, private key boundaries, JCS use, replay checks, database transaction behavior, witness independence, RBAC, site scoping, demo route exposure, CORS, input validation, logging and ML data provenance. Run all tests, lint, type checking and build. Report every failed or untested item honestly. Do not say production-ready or fully secure. Propose fixes for critical failures and wait for approval before large refactors.
```

## Prompt discipline

- Run one prompt at a time.
- Inspect the diff after every phase.
- Reject unrelated dependency upgrades or architecture rewrites.
- Do not let the agent mark acceptance criteria complete without test evidence.
- If output conflicts with a contract, stop and correct it before continuing.


## Prompt 10 — Build documentation and handoff

```text
Update README and developer documentation to match the actual implemented code. Document local setup, environment variables, database migrations, how to provision sensor keys, how to start each service, how to seed demo users, how to run tests and how to trigger each demo scenario. Do not document features that are not implemented. Clearly list prototype limitations. Verify commands from a clean local setup if possible and report anything not tested.
```
