# Environment Setup — EnviroTrust

This document explains which variables the team must configure. It is not a place to put real secrets in Git.

## 1. Local services and default ports

| Service | Default address | Owner |
|---|---|---|
| React/Vite | `http://localhost:5173` | Antigravity |
| Primary Express API | `http://localhost:4000` | Antigravity |
| Independent witness | `http://localhost:4001` | Antigravity |
| Python ML service | `http://127.0.0.1:8000` | ML teammate |
| PostgreSQL primary DB | Local PostgreSQL, port 5432 | Antigravity/setup |
| PostgreSQL witness DB | Separate database/role on local PostgreSQL, port 5432 | Antigravity/setup |

The sensor and operations simulators are local processes and do not need public listening ports unless the implementation has a documented control API. They send signed envelopes directly to primary and witness ingestion endpoints.

## 2. Environment files

Use separate environment files per service where practical:

- Repository root or `apps/api/.env`: primary API configuration.
- `apps/web/.env`: copy `apps_web_env.example`; Vite variables only; every browser-exposed variable must start with `VITE_` and must never contain secrets.
- `apps/witness/.env`: copy `apps_witness_env.example`; witness configuration.
- `apps/api/.env`: copy `apps_api_env.example` for the primary API.
- `apps/sensor-simulator/.env`: copy `apps_simulator_env.example`; simulator endpoints and local key directories.
- `services/ml/.env`: copy `services_ml_env.example`; ML teammate's FastAPI settings.

If Antigravity chooses a single root `.env` for local orchestration, it must document which process reads each variable. Do not make Vite consume server-only secrets.

## 3. Primary API variables

| Variable | Required | Meaning / local value |
|---|---|---|
| `NODE_ENV` | Yes | `development` locally |
| `DEMO_MODE` | Yes | `true` locally; enables synthetic attack controls only |
| `API_PORT` | Yes | `4000` |
| `API_BASE_URL` | Yes | `http://localhost:4000` |
| `WEB_ORIGIN` | Yes | `http://localhost:5173`; exact CORS origin |
| `DATABASE_URL` | Yes | Primary PostgreSQL DSN, e.g. `postgresql://envirotrust_app:LOCAL_PASSWORD@localhost:5432/envirotrust_primary` |
| `JWT_SECRET` | Yes | Unique random secret, never the placeholder |
| `JWT_ACCESS_TTL_MINUTES` | Yes | `60` for local demo |
| `COOKIE_SECURE` | Yes | `false` on localhost HTTP; `true` behind HTTPS in deployment |
| `COOKIE_SAME_SITE` | Yes | `lax` for local same-site deployment; reassess if frontend/API are cross-site |
| `MAX_FUTURE_SKEW_SECONDS` | Yes | `120` demo policy, configurable |
| `MAX_TELEMETRY_AGE_SECONDS` | Yes | `300` live-ingestion demo policy, configurable |

## 4. Browser variables (`apps/web/.env`)

| Variable | Required | Meaning |
|---|---|---|
| `VITE_API_BASE_URL` | Yes | `http://localhost:4000/api/v1` |
| `VITE_DEMO_MODE` | Yes | `true` for demo-only UI controls |

Never place `JWT_SECRET`, database URLs, witness tokens, ML tokens or any private key in a `VITE_` variable. Vite embeds `VITE_` values into the browser bundle.

## 5. Witness variables

| Variable | Required | Meaning / local value |
|---|---|---|
| `WITNESS_PORT` | Yes | `4001` |
| `WITNESS_BASE_URL` | Yes | `http://localhost:4001` |
| `WITNESS_DATABASE_URL` | Yes | Separate DB/user, e.g. `postgresql://envirotrust_witness:LOCAL_WITNESS_PASSWORD@localhost:5432/envirotrust_witness` |
| `WITNESS_ID` | Yes | `WITNESS-001` |
| `WITNESS_DISPLAY_NAME` | Yes | `Simulated Independent Witness` |
| `WITNESS_CHECKPOINT_EVERY` | Yes | `10` accepted events for accelerated demo |
| `WITNESS_KEY_DIR` | Yes | `./local-secrets/witness-keys` |
| `WITNESS_SERVICE_TOKEN` | If internal management routes use it | Unique random internal token; never expose to web client |

The witness database must be distinct from the primary database and use separate credentials. It may run on the same local PostgreSQL server for the hackathon, but the application DB role must not have permission to rewrite witness records.

## 6. Simulator variables

| Variable | Required | Meaning / local value |
|---|---|---|
| `SENSOR_KEY_DIR` | Yes | `./local-secrets/sensor-keys` |
| `OPS_KEY_DIR` | Yes | `./local-secrets/ops-keys` |
| `SIMULATOR_TELEMETRY_INTERVAL_MS` | Yes | `7000` accelerated demo interval |
| `SIMULATOR_HEARTBEAT_INTERVAL_MS` | Yes | `10000` |
| `SIMULATOR_RETRY_COUNT` | Yes | `3` |
| `SIMULATOR_RETRY_BASE_MS` | Yes | `500` |
| `PRIMARY_INGESTION_URL` | Yes for simulator | `http://localhost:4000/api/v1/ingestion/readings` |
| `PRIMARY_HEARTBEAT_URL` | Yes for simulator | `http://localhost:4000/api/v1/ingestion/heartbeats` |
| `WITNESS_INGESTION_URL` | Yes for simulator | `http://localhost:4001/witness/v1/ingestion/readings` |
| `WITNESS_HEARTBEAT_URL` | Yes for simulator | `http://localhost:4001/witness/v1/ingestion/heartbeats` |

Retries must reuse the exact original message ID, payload, signature, boot ID and sequence. Do not generate a fresh reading on retry.

## 7. ML integration variables

| Variable | Required | Meaning / local value |
|---|---|---|
| `ML_ENABLED` | Initially `false`; set `true` after ML teammate's service works | Controls whether primary calls ML |
| `ML_BASE_URL` | Yes when enabled | `http://127.0.0.1:8000` |
| `ML_TIMEOUT_MS` | Yes | `2500` initial timeout; tune after integration |
| `ML_SERVICE_TOKEN` | Recommended for service-to-service auth | Same random internal token in primary and ML service; never expose to browser |

Antigravity builds the ML HTTP client, request validation, response validation, persistence and UI. The designated ML teammate implements `services/ml/` and its Python model. Until that service is delivered, `ML_ENABLED=false`; use only a clearly labelled test mock for frontend work. Never present mock output as real ML analysis.

## 8. ML teammate variables (`services/ml/.env`)

| Variable | Required | Meaning / local value |
|---|---|---|
| `ML_HOST` | Yes | `127.0.0.1` for local development |
| `ML_PORT` | Yes | `8000` |
| `MODEL_PATH` | Yes | `./models/cod_model.joblib` or the path the teammate documents |
| `ML_RANDOM_SEED` | Yes | `42` for reproducibility |
| `ML_SERVICE_TOKEN` | Recommended | Same internal token configured for primary API |
| `ML_LOG_LEVEL` | No | `INFO` |

The ML teammate may add implementation-specific variables but must document them and must not change the shared HTTP contract unilaterally.

## 9. Demo seed account variables

If the seed script is configurable through environment variables, use:

- `SEED_ADMIN_EMAIL`
- `SEED_ADMIN_PASSWORD`
- `SEED_OPERATOR_EMAIL`
- `SEED_OPERATOR_PASSWORD`
- `SEED_OPERATOR_SITE_ID=PLANT-001`
- `SEED_AUDITOR_EMAIL`
- `SEED_AUDITOR_PASSWORD`

Use local-only demo passwords. Store password hashes (Argon2id or maintained bcrypt) in the database, never plaintext. The seed script must be idempotent and must not print passwords to logs. If the project seeds fixed documented demo credentials instead, keep them development-only and require changing them before deployment.

## 10. Generate secrets safely

Generate random local secrets with Node.js instead of inventing a memorable string:

```bash
node -e "console.log(require('crypto').randomBytes(48).toString('base64url'))"
```

Run it separately for `JWT_SECRET`, `WITNESS_SERVICE_TOKEN` and `ML_SERVICE_TOKEN`. Do not reuse a value across purposes. For the ML token, copy the same generated value into the primary API and ML service environment files.

For PowerShell, the same command works when Node.js is installed:

```powershell
node -e "console.log(require('crypto').randomBytes(48).toString('base64url'))"
```

## 11. Local setup checklist

1. Install a supported Node.js LTS version and Python version compatible with the ML teammate's `requirements.txt`.
2. Install/start PostgreSQL.
3. Create two databases: `envirotrust_primary` and `envirotrust_witness`, with separate users/passwords and least-privilege permissions.
4. Copy the example environment files to the service-specific `.env` files.
5. Generate unique JWT, witness and ML service secrets.
6. Keep `ML_ENABLED=false` until the ML teammate has provided a running FastAPI service and passing contract tests.
7. Run database migrations and seed demo users/site/sensor configuration.
8. Run the witness, primary API, sensor/operations simulators and web app as separate processes.
9. Verify `/health` endpoints and the first signed reading before enabling attack scenarios.
10. Enable ML integration only after `/ml/v1/health` reports ready and the request/response contract passes.

Never commit `.env`, `local-secrets/`, private keys, generated credentials or actual database exports.
