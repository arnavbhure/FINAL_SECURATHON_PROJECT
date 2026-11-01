# ML Teammate Handoff — EnviroTrust

You own the Python ML implementation. Antigravity owns the React application, Express API, simulators, cryptography, witness, integration client and dashboard.

## Read first

1. `06_ML_SPECIFICATION.md` — complete model and API requirements.
2. `contracts/ml-result.schema.json` — exact response contract.
3. `OWNERSHIP_AND_AGENT_BOUNDARIES.md` — ownership split.
4. `ENVIRONMENT_SETUP.md` — ML service variables and local run configuration.

## Your deliverables

- `services/ml/` Python source code.
- Deterministic synthetic normal-process data generator and documented assumptions.
- RandomForestRegressor COD model and saved preprocessing pipeline.
- Validation-derived residual threshold.
- Separate injected scenario tests.
- Flatline/sudden-change rules as specified.
- FastAPI `POST /ml/v1/analyze/cod`.
- FastAPI `GET /ml/v1/health`.
- Exact response matching `contracts/ml-result.schema.json`.
- `requirements.txt`, `.env.example`, tests and run instructions.

## Input trust

The primary API calls your endpoint only after it has verified the COD reading and the separate OPS-001 signed context. Do not accept direct public browser calls. The primary API supplies trusted identifiers and validated feature values. Missing, stale or mismatched context must return `NOT_EVALUATED`.

## Do not

- Implement Ed25519 verification or audit chains in Python.
- Modify or overwrite original telemetry.
- Return a `fraudProbability` or claim that an anomaly proves fraud.
- Train on injected attacks as normal data.
- Claim model performance on real industrial plants.
- Change endpoint paths, request fields, status enums or response fields without coordinating with Antigravity and updating the shared contracts.

## Integration acceptance

Demonstrate:

1. Normal synthetic context + normal COD => usually `CONSISTENT`.
2. Verified context + deliberately injected COD mismatch => `SUSPICIOUS` with prediction, residual, threshold and reasons.
3. Missing/stale/unverified context => `NOT_EVALUATED`.
4. ML service unavailable => primary ingestion and witness auditing still work.
5. Validly signed flatline stream => sensor-behaviour rule flags it while signature remains valid.
