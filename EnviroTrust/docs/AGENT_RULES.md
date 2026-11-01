# Agent Rules — Mandatory Instructions for Antigravity

This file governs how the coding agent must work on EnviroTrust.

## 1. Before editing anything

1. Inspect the repository structure, existing package manifests, scripts, environment files, database setup and current code.
2. Read the complete specification pack.
3. Identify what already exists. Do not overwrite working code simply to match a generated preferred structure.
4. Produce a short implementation plan listing files to create/change, dependencies to add, tests to run and risks.
5. If a requirement is contradictory or missing, report it and stop that part. Do not invent a security protocol.

## 2. Source-of-truth hierarchy

1. `13_DECISIONS_AND_OPEN_ITEMS.md`
2. `contracts/*.schema.json` for wire payload shapes
3. `04_CRYPTOGRAPHIC_PROTOCOL.md`, `05_INDEPENDENT_WITNESS.md`, `06_ML_SPECIFICATION.md`
4. Other product and UI specifications
5. Existing repository conventions, provided they do not violate this pack

If two sources conflict, do not silently choose. Report the exact conflict and ask for a decision.

## 3. Work in small, reviewable phases

- Implement only the phase requested by the user.
- Do not scaffold every feature in one giant generation step.
- After each phase, run formatter, linter, type checker (if configured), unit tests and relevant integration tests.
- Report the exact commands run and their results.
- Show a concise summary of changed files and any known limitations.
- Do not proceed to the next phase until the current phase passes its acceptance criteria or the user explicitly accepts a documented failure.

## 4. Security-sensitive code rules

- Do not implement custom cryptographic primitives.
- Use Node.js `crypto` Ed25519 APIs and SHA-256; use a maintained RFC 8785 JCS implementation.
- Never substitute `JSON.stringify()` for RFC 8785 canonicalization in signature/hash code.
- Sign the exact payload defined in `contracts/telemetry.schema.json`; do not sign only the measurement value.
- Never put sensor private keys, witness private keys, database passwords, JWT secrets or service tokens in frontend code, source control or logs.
- Do not return private keys in API responses.
- React must not sign telemetry and must not hold device private keys.
- The sensor simulator signs. The primary API verifies. The witness independently verifies and stores its own copy.
- Do not accept a public key supplied in the same telemetry request as the trust anchor. Keys must already be enrolled and approved.
- Use parameterized SQL queries or a safe ORM. Do not concatenate user input into SQL.
- Enforce RBAC and site scoping on the server, not only by hiding UI controls.
- Never mutate accepted signed telemetry after ingestion. Store analysis and status in separate records.
- Invalid signatures, replay attempts and authorization failures must not enter the trusted telemetry chain as accepted readings. They should create separate security events with bounded, sanitized metadata.
- Do not log bearer tokens, passwords, private keys, raw secret values or full challenge secrets.
- Use HTTPS in deployment. Local HTTP is allowed only for local development.

## 5. ML ownership and integration rules

- The designated human teammate owns and implements the Python model and FastAPI service under `services/ml/`, as defined in `OWNERSHIP_AND_AGENT_BOUNDARIES.md` and `ML_TEAMMATE_HANDOFF.md`.
- Antigravity must not implement, replace, rewrite or silently generate the Python ML model/service. It owns only the primary API ML client, shared contracts, response validation, persistence, test-only mock (if required), dashboard and integration tests.
- The ML service receives only COD readings and operating context that have passed primary backend signature, identity, freshness and source validation.
- COD prediction uses only the documented features and synthetic process model in `06_ML_SPECIFICATION.md`.
- Do not claim the model is trained on real industrial measurements.
- Do not label model anomalies as proven fraud.
- Missing or stale operational context must produce `NOT_EVALUATED`, not a fabricated prediction.
- ML output must never modify the signed reading or compliance profile.
- Record the model version and feature set with every result.
- Do not use an LLM to make the numeric anomaly decision.
- ML unavailability must not block valid telemetry ingestion, signature verification, heartbeat handling or witness/audit processing.

## 6. Witness rules

- The witness is a separate service and stores its own event copy and checkpoints.
- Sensors send the same signed envelope directly to primary and witness endpoints.
- The witness must independently verify the sensor signature; it must not trust the primary service's `signatureValid: true` field.
- The witness private key is separate from all sensor and primary backend keys.
- The witness signs periodic checkpoints, not each reading.
- UI labels must say “Simulated Independent Witness” unless a real institution has formally connected and approved the integration.
- Do not invent NGO, university, CPCB or MPCB participation.

## 7. UI rules

- Build a functional, accessible interface, not a decorative mockup.
- The regulator view is read-only.
- Factory operators are scoped to their own site.
- Platform administrators manage provisioning and configuration.
- Clearly distinguish: signature status, audit status, sensor availability, measurement quality, ML anomaly and environmental compliance.
- Do not collapse these into one generic green/red “secure” score.
- Use real API data in the final UI; mock data is permitted only in an explicitly labelled demo mode.

## 8. Dependency discipline

- Prefer the existing stack and existing installed libraries.
- Add only dependencies needed by the current phase.
- Explain why each new dependency is needed.
- Do not add blockchain, Redis, Kafka, Docker orchestration, a vector database, an LLM API or a second UI framework unless the user explicitly approves it.
- Do not silently upgrade unrelated dependencies.

## 9. Completion report format

After every phase, report:

1. What was implemented.
2. Files changed.
3. Commands/tests run and pass/fail counts.
4. Security checks performed.
5. Known gaps and assumptions.
6. Exact next phase proposed.

Never say “fully secure,” “tamper-proof,” “production-ready,” or “100% correct.” Use precise claims such as “the test detected a modified signed payload” or “the primary history did not match the independently stored witness checkpoint.”
