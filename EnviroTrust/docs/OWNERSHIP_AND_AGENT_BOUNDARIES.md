# Ownership and Agent Boundaries — EnviroTrust

**Version:** 1.1  
**Purpose:** Prevent Antigravity and the ML teammate from implementing the same subsystem or creating incompatible contracts.

## 1. Ownership decision

### Antigravity owns and implements

Antigravity is the primary application engineer. It must implement:

1. React + TypeScript frontend/dashboard and role-based UI.
2. Node.js + Express primary API.
3. PostgreSQL primary database schema/migrations and seed scripts.
4. Node.js sensor simulator for PH-OUT-001, COD-OUT-001 and TSS-OUT-001.
5. Node.js operations-context simulator for OPS-001.
6. Ed25519 key provisioning, telemetry signing in the simulators, and signature verification in the primary API.
7. RFC 8785 JSON canonicalization for signed payloads.
8. SHA-256 audit event chain.
9. Separate Node.js witness service, its separate storage, independent verification and signed checkpoints.
10. Signed heartbeats, freshness/replay checks and sensor availability state.
11. Attack/demo scenarios and test fixtures.
12. ML integration client in the primary API, response validation, persistence of analysis results, dashboard integration and a clearly isolated test mock if needed.
13. Documentation, environment validation, scripts, tests and security review for the parts above.

### A designated human teammate owns and implements

The ML teammate exclusively owns the Python implementation under `services/ml/`:

1. Synthetic normal industrial dataset generator and documented simulation assumptions.
2. RandomForestRegressor training and persisted pipeline.
3. Validation-derived residual threshold and model evaluation.
4. Flatline/sudden-change statistical rules as specified in `06_ML_SPECIFICATION.md`.
5. FastAPI service and `/ml/v1/analyze/cod` endpoint.
6. ML-specific tests, model metadata and ML README/run instructions.

Antigravity must **not** implement, replace, rewrite, or silently generate the Python model/service. Antigravity may create a temporary, contract-compatible mock client/server only for frontend/backend integration tests. Any mock must be clearly named `mock`/`test`, must not be mistaken for the real ML service, and must be removable without changing the API contract.

## 2. Integration boundary between Antigravity and ML teammate

The ML teammate owns the implementation; Antigravity owns the caller and application integration.

The primary API sends only:

- a telemetry reading that has passed signature, key mapping, replay and freshness checks;
- operations context that has independently passed its signature and source validation;
- same-site/station/time-window identifiers;
- recent verified COD values needed by documented rules.

The primary API must never send unverified context or let a browser set `contextVerified=true`. That flag is derived internally after backend verification and is not trusted from client input.

The ML service returns the exact result contract defined by `contracts/ml-result.schema.json` and `06_ML_SPECIFICATION.md`. Antigravity must validate the response before storing it. If ML is unavailable, ingestion, signature verification, witness delivery and audit logging continue; analysis is marked `PENDING` or `NOT_EVALUATED`.

Do not invent an alternate ML endpoint, feature names, status values or response fields. If the ML teammate needs a contract change, both owners must review and update the JSON Schema, ML specification, backend client and tests together.

## 3. Ownership matrix

| Component | Antigravity | ML teammate |
|---|---:|---:|
| React dashboard | Owns | No |
| Express API | Owns | No |
| PostgreSQL app schema | Owns | No |
| Sensor simulator and sensor keys | Owns | No |
| Operations-context simulator and key | Owns | No |
| Ed25519 verification | Owns | No |
| Audit hash chain | Owns | No |
| Witness service and checkpoints | Owns | No |
| Heartbeat/replay handling | Owns | No |
| Python synthetic data/model | No | Owns |
| FastAPI inference implementation | No | Owns |
| ML integration client and UI | Owns | Supplies endpoint contract |
| Cross-service integration tests | Owns | Supports ML-specific tests |

## 4. Required handoff from ML teammate

Before integration is considered complete, the ML teammate must provide:

1. `services/ml/main.py` and all source files required to run the service.
2. A reproducible training script.
3. A deterministic synthetic data generator with fixed seed and documented assumptions.
4. The saved model pipeline and metadata, or a startup process that creates them reproducibly.
5. The FastAPI `/ml/v1/analyze/cod` endpoint.
6. `GET /ml/v1/health` reporting readiness and model version.
7. Request and response examples matching the shared contracts.
8. Tests for normal, context-mismatch, missing context, stale context and flatline scenarios.
9. A `requirements.txt` and exact local run command.
10. A statement that reported metrics are from synthetic test data only.

## 5. Integration rule

The contract files are jointly owned and are the single source of truth. Neither owner may independently change the request/response shape. The integration test must prove:

- verified normal input returns a valid ML result;
- injected context mismatch returns `SUSPICIOUS` with predicted value, residual, threshold and reasons;
- missing/stale/unverified context returns `NOT_EVALUATED`;
- ML timeout does not reject valid telemetry or block audit/witness processing;
- a model result never modifies original signed telemetry.
