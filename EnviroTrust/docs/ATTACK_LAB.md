# Attack Simulation Lab

> **DEMO ENVIRONMENT ONLY.** The lab executes predefined attacks against the *local* demo services
> (Primary API, Simulated Independent Witness, ML FastAPI service, Alert Management). It is never mounted in
> production and refuses to run unless every safety gate passes. All sensors, keys and operating context are
> software simulations; no physical hardware is involved.

The lab lets a judge **select an attack → run it → observe the real server responses → see the threat
rejected or detected → open the alert → verify the persisted evidence**. Every result shown is read back from
real HTTP responses, database rows and verifier output. Nothing is pre-scripted: if a service does not respond
the way the scenario expects, the run is reported as `INCONCLUSIVE`, `ACCEPTED` or `SERVICE_UNAVAILABLE`.

---

## 1. Architecture

```
                 ┌──────────── React /attack-lab (read status, pick a fixed scenario ID, poll the run) ───────────┐
                 │                                                                                               │
                 ▼                                                                                               │
  Primary API  /api/v1/demo/attack-lab/*   (mounted only when DEMO_MODE=true, ATTACK_LAB_ENABLED=true, NODE_ENV≠production)
                 │
                 ▼
  Attack Simulation Engine  (apps/api/src/attack-lab — also used by the demo:* CLI and the automated tests)
     │  signs with the simulated device code (SensorDevice / OpsContextSimulator / @envirotrust/crypto)
     │  keys are loaded server-side from local-secrets/ and never leave the process
     ├──► POST Primary ingestion endpoints  (/api/v1/ingestion/*, /api/v1/tamper/events)
     ├──► POST Witness ingestion endpoints  (/witness/v1/ingestion/*, /witness/v1/tamper/events)
     ├──► reads evidence: primary DB (read queries), witness DB (read-only queries), witness /events API
     ├──► spawns the real operator tools: scripts/export-checkpoints.ts, scripts/verify-checkpoint.ts
     └──► writes ONLY its own evidence table: attack_lab_runs  (never telemetry, never audit records)
```

Design rules the engine follows:

* **No second implementation of verification.** Signatures are only ever verified by the Primary API and the
  Witness through their normal ingestion paths; the offline check uses the existing verifier script.
* **No bypass of the pipeline.** Attack envelopes travel over HTTP to the same endpoints the sensor simulators use.
* **Fixed scenarios only.** A run request contains a scenario ID from the catalog and an optional boolean
  `confirm`. Any other field is rejected (`400 INVALID_RUN_REQUEST`). Targets, payloads and keys come from server
  configuration; there is no general-purpose attack endpoint.
* **Private keys stay server-side.** The ephemeral attacker key in scenario B lives only in memory. No run record,
  API response or log line contains key material, tokens or passwords.
* **Demo identities are dedicated.** Compromised-key and availability scenarios use identities that exist only for
  the lab (`npm run demo:provision`); the real `COD-OUT-001`/`PH-OUT-001` keys are only used for attacks that the
  services must reject (A, C, E) or for replaying envelopes they already hold (D).

## 2. Safety gates

The engine evaluates these before every run (`GET /api/v1/demo/attack-lab/status` and `npm run demo:doctor` show them):

| Gate | Requirement |
|---|---|
| Demo mode | `DEMO_MODE=true` |
| Lab flag | `ATTACK_LAB_ENABLED=true` (default **false**) |
| Environment | `NODE_ENV` is not `production` (routes are not even mounted in production) |
| Primary DB identity | `current_database()` equals `ATTACK_LAB_EXPECTED_PRIMARY_DB` (default `envirotrust_primary`) and site `PLANT-001` is flagged `is_demo` |
| Witness DB identity | `current_database()` equals `ATTACK_LAB_EXPECTED_WITNESS_DB` (default `envirotrust_witness`) and the witness key registry exists |
| Separate databases | Primary and witness database names differ |
| Local targets | Primary/Witness URLs are loopback; RFC 1918 LAN hosts only with `ATTACK_LAB_ALLOW_PRIVATE_NETWORK_TARGETS=true`; public hosts always refused |
| Authorized operators | `ATTACK_LAB_AUTHORIZED_ADMINS` (default: the seeded demo admin) is non-empty |

If any gate fails the server answers `503 ATTACK_LAB_MISCONFIGURED` and records nothing. Disruptive scenarios
(H and I) also require `confirm: true` (`400 CONFIRMATION_REQUIRED` otherwise). Only one scenario runs at a time
(a partial unique index on `attack_lab_runs`; `409 RUN_IN_PROGRESS`).

### Access control

| Role | Status, catalog, run history and evidence | Execute scenarios |
|---|---|---|
| `PLATFORM_ADMIN` on `ATTACK_LAB_AUTHORIZED_ADMINS` | all sites | yes |
| other `PLATFORM_ADMIN` | all sites | no (`403 NOT_AUTHORIZED`) |
| `FACTORY_OPERATOR` | runs of assigned sites only | no (`403`) |
| `REGULATOR_AUDITOR` | runs of assigned sites only (read-only security evidence) | no (`403`) |

## 3. Scenarios

| | Scenario (ID) | What the engine does | Confirmed outcome |
|---|---|---|---|
| A | Telemetry Payload Tampering (`telemetry-tampering`) | Signs a genuine COD-OUT-001 reading with the registered key, changes the value after signing, sends the same modified envelope to both services | **PREVENTED / INVALID_SIGNATURE** — both reject, no trusted record, security event + security alert, no PHYSICAL_TAMPER alert |
| B | Unknown Signing Key (`unknown-signing-key`) | Ephemeral in-memory Ed25519 key signs a schema-valid envelope claiming COD-OUT-001 | **PREVENTED / UNKNOWN_KEY** — key never persisted |
| C | Invalid Tamper Signal (`invalid-tamper-signal`) | Creates a COD-OUT-001 tamper event, flips signature bytes, submits to the existing tamper endpoints | **PREVENTED / INVALID_TAMPER_SIGNATURE_REJECTED** — SECURITY_EVENT recorded, no verified PHYSICAL_TAMPER alert |
| D | Replay Attack (`replay-attack`) | Case 1: re-delivers a captured accepted COD-OUT-001 envelope byte-for-byte. Case 2: new message ID, same boot, already consumed sequence, correctly signed | Case 1 idempotent (`200 isDuplicate`, still one record, one audit event). Case 2 **PREVENTED / REPLAYED_SEQUENCE** at both services |
| E | Sensor Identity / Key Mismatch (`identity-key-mismatch`) | Claims `sensorId=COD-OUT-001`, signs with (and names) the registered PH-OUT-001 key | **PREVENTED / IDENTITY_BINDING_FAILURE** (`KEY_SENSOR_MISMATCH` at both) |
| F | Authorised Insider / Compromised Signing Key (`compromised-signing-key`) | **SIMULATED COMPROMISED KEY** `LAB-COD-902` legitimately signs a manipulated COD value (`ATTACK_LAB_COMPROMISED_COD_VALUE`, default 18.40 mg/L); matching verified OPS-001 context is reused (or newly signed with the OPS-001 key); the genuine assessment pipeline sends it to FastAPI | Crypto **accepts** (expected). Verdict = what the model actually returned: `SUSPICIOUS` (flagged), `ACCEPTED` (not detected), or `PENDING` with `ML_NOT_ENABLED` / `ML_UNAVAILABLE`. A `SUSPICIOUS` flag counts only if the same model did not also flag at least half of the genuine readings it evaluated for the site in the last 30 min; otherwise the run is `INCONCLUSIVE / ML_FLAG_NOT_SPECIFIC` |
| G | Historical Witness Record Tampering (`checkpoint-history-tampering`) | Genuine `LAB-COD-901` readings until a signed checkpoint covers them; real export; modify one covered event in a separate temp copy; run the real offline verifier on both copies with the independently pinned witness fingerprint | **DETECTED / CHECKPOINT_VERIFICATION_FAILED** — original PASS, copy FAIL with the exact reason (e.g. `EVENT_HASH_MISMATCH`), witness DB record unchanged |
| H | Sensor Heartbeat Interruption (`heartbeat-interruption`) | `LAB-COD-901` streams signed heartbeats, stops, waits, restores | **DETECTED / COMMUNICATION_LOSS_INCIDENT** — STALE (WARNING) → OFFLINE (HIGH) → RECOVERED event, OFFLINE incident resolved, exactly one alert of each kind |
| I | Witness Service Outage (`witness-outage`) | Baseline dual delivery; the demo sensor's path to the witness is isolated (closed loopback port = simulated network partition — the shared witness process is **not** stopped); new signed reading; outbox check; restore; retry original envelope | **DETECTED / WITNESS_DELIVERY_FAILURE_RECOVERED** — Primary accepted during outage, witness failed, outbox kept the envelope, retry accepted with the same signature, sensor stayed ONLINE |

### Outcome states

`PREVENTED` (rejected by the mechanism under test, nothing stored), `DETECTED` (the expected detection or
incident was confirmed in persisted evidence), `SUSPICIOUS` (the ML model flagged the reading), `ACCEPTED`
(the attack got through or was not detected), `PENDING` (ML result not available), `INCONCLUSIVE` (a response
came back but the expected mechanism/evidence was not confirmed), `SERVICE_UNAVAILABLE` (a target could not be
reached). An unsuccessful attack request is **not** automatically `DETECTED`: e.g. a rejection with
`INVALID_SCHEMA` in scenario A is `INCONCLUSIVE`.

### Classification is separate from incidents

| Event | Classification | Alert |
|---|---|---|
| Modified payload | Prevented `INVALID_SIGNATURE` | `SECURITY_EVENT` (HIGH) |
| Unknown key | Prevented `UNKNOWN_KEY` | `SECURITY_EVENT` (WARNING), scoped to the *claimed* sensor and marked unauthenticated |
| Sequence rollback | Prevented `REPLAYED_SEQUENCE` | `SECURITY_EVENT` (HIGH) |
| Key/sensor mismatch | Prevented identity-binding failure | `SECURITY_EVENT` (HIGH) |
| Compromised key + ML anomaly | Detected/flagged `SUSPICIOUS` — not proof of fraud | ML assessment (Anomalies page) |
| Modified historical export | Detected `CHECKPOINT_VERIFICATION_FAILED` | verifier report (offline) |
| Signed physical tamper signal | CRITICAL `PHYSICAL_TAMPER` alert (existing tamper pipeline) | `PHYSICAL_TAMPER` |
| Invalid tamper event | Rejected security event | `SECURITY_EVENT` — never `PHYSICAL_TAMPER` |
| Heartbeat loss | Operational communication incident — does not prove intentional tampering | `SENSOR_STALE` / `SENSOR_OFFLINE` / `SENSOR_RECOVERED` |
| Witness outage | Delivery failure and retry incident | run evidence + outbox |

`SECURITY_EVENT` alerts are durable and deduplicated: one open alert per site, sensor and rejection reason; later
rejections increment `occurrenceCount` and link the newest security-event IDs. Rejected messages are recorded only in
`security_events` / `witness_security_events`, never in trusted telemetry.

## 4. Run evidence

Each run is a row in `attack_lab_runs` (Primary DB, migration `008_attack_lab.sql`): run ID, scenario ID,
start/end, actor (user ID or `CLI (<os user>)`), site, step timeline, actual Primary outcome, actual Witness
outcome, ML result (with the anomaly-result ID), alert IDs, primary/witness security-event IDs and verification
evidence (counts, hashes, verifier report). No private keys, tokens or credentials are stored. The summary line
("Attack prevented", "Threat detected", "Operational alert generated", "Evidence verified", …) is derived from
the actual outcome.

## 5. Interfaces

### HTTP (demo-only, under the Primary API)

| Method & path | Roles | Purpose |
|---|---|---|
| `GET /api/v1/demo/attack-lab/status` | all | safety checks, Primary/Witness/ML health, ML readiness, demo identities, active run, `canExecute` |
| `GET /api/v1/demo/attack-lab/scenarios` | all | the fixed catalog |
| `POST /api/v1/demo/attack-lab/scenarios/:scenarioId/runs` | allowlisted `PLATFORM_ADMIN` | body `{ "confirm": true }` only; returns `202 { runId }` |
| `GET /api/v1/demo/attack-lab/runs` | all (site-scoped) | run history |
| `GET /api/v1/demo/attack-lab/runs/:runId` | all (site-scoped) | one run with steps and evidence |

### CLI (same engine and catalog as the UI)

| Command | Purpose |
|---|---|
| `npm run demo:doctor` | checks gates, services, migrations, keys, demo identities, routes; non-zero exit on blocking failures |
| `npm run demo:provision` | creates/registers the dedicated demo identities `LAB-COD-901` and `LAB-COD-902` in both registries |
| `npm run demo:attacks` | runs A–I; `-- --scenario <id>` runs one; `-- --json` for machine output; non-zero exit if any expected outcome was not achieved. Invoking it is the confirmation for H and I |
| `npm run demo:verify` | re-verifies the evidence of the latest run of each scenario (or `-- --run <id>`) against the live DBs and re-runs the witness chain check |
| `npm run demo:restore -- --confirm` | takes demo identities out of service, resolves incidents raised by recorded runs (records kept), clears the lab's own outbox and temp exports. Never deletes telemetry, audit, witness, security-event or run evidence |

### Configuration (`apps/api/.env`, no secrets)

| Variable | Default | Meaning |
|---|---|---|
| `ATTACK_LAB_ENABLED` | `false` | master switch |
| `ATTACK_LAB_AUTHORIZED_ADMINS` | `admin@envirotrust.local` | comma-separated admin e-mails allowed to execute |
| `ATTACK_LAB_EXPECTED_PRIMARY_DB` / `ATTACK_LAB_EXPECTED_WITNESS_DB` | `envirotrust_primary` / `envirotrust_witness` | database identity checks |
| `ATTACK_LAB_ALLOW_PRIVATE_NETWORK_TARGETS` | `false` | allow RFC 1918 Primary/Witness targets |
| `ATTACK_LAB_PRIMARY_URL` | `API_BASE_URL` | ingestion target for attacks |
| `ATTACK_LAB_TRUSTED_WITNESS_FINGERPRINT` | from `local-secrets/witness-keys/public.pem` | independently supplied trust anchor for scenario G |
| `ATTACK_LAB_COMPROMISED_COD_VALUE` | `18.40` | manipulated value for scenario F |
| `ATTACK_LAB_ML_WAIT_SECONDS` | `75` | how long F waits for the genuine assessment |
| `ATTACK_LAB_WORK_DIR` | OS temp dir | where G writes the export copies |

## 6. Gaps found and fixed while building the lab

1. **Witness accepted sequence rollbacks.** Witness telemetry ingestion only checked message-ID idempotency, so a
   correctly signed new message reusing a consumed `(sensor, boot, sequence)` was stored. The witness now rejects
   it with `409 REPLAYED_SEQUENCE` (doc 05 §4 step 6), checked under the station chain lock, and records a
   witness security event. Delayed, never-witnessed sequences (outbox catch-up) are still accepted.
2. **Identity-binding failures left no evidence.** `KEY_SENSOR/SITE/STATION/PARAMETER/SOURCE_MISMATCH` rejections
   now record security events at Primary and Witness (rejection behaviour unchanged).
3. **Rejected attacks raised no alerts.** Rejections now open/refresh one deduplicated `SECURITY_EVENT` alert.
4. **Raw ML output was discarded.** The ML client kept only derived values; `anomaly_results` now also stores the
   model's `anomaly_score`, `anomaly_threshold`, `is_anomaly` and `detection_sources` exactly as returned.
5. **Browser-side "scenarios" on the Alerts page** printed canned success messages (e.g. claiming a verified tamper
   alert for a stub-signed event). They were replaced by a link to the lab, which runs server-side.
6. **Idle demo sensors** would raise permanent OFFLINE alerts; the availability evaluator now skips sensors whose
   registry status is not `ACTIVE`. The lab activates its demo sensor only for the duration of H and I.
7. **Recovery events could be lost after a reboot.** The availability evaluator keyed `SENSOR_RECOVERED` alerts on
   the heartbeat sequence, which restarts with every boot session, so a later recovery could collapse into an old
   alert and no new recovery event was stored (found by running scenario H twice). The key is now tied to the
   incident(s) the recovery resolves.

## 7. Limitations (what the lab does not show)

* Everything is simulated software on one or two laptops; this is not real-hardware physical tamper detection and
  no regulator is notified automatically.
* Scenario F shows whether the *current* model flags a legitimately signed false value. In the live run on
  2026-11-01 the teammate's service (`iforest-demo-v1.0`) returned `SUSPICIOUS` for the manipulated 18.40 mg/L
  reading via its `physical_rules` source (COD outside its learned range of roughly 3,489–8,062 mg/L) with an
  Isolation Forest score of 0.0395 below its 0.0694 threshold — and it flagged every genuine simulated reading
  (≈170–230 mg/L) the same way, because the simulator's COD scale lies outside the model's training range. The lab
  therefore reports that run as `ML_FLAG_NOT_SPECIFIC`, not as a detection. A compromised key cannot be
  detected cryptographically, and an anomaly flag is not proof of fraud. The FastAPI service is stateful, so its
  result can depend on prior traffic. The anomaly score is not a COD prediction.
* The ML client still derives a `predictedCod` from the anomaly score for the existing Anomalies chart (pre-existing
  behaviour, not shown by the lab).
* Scenario I isolates the demo sensor's network path to the witness rather than stopping the shared witness process.
* Only events covered by a signed checkpoint are checkpoint-anchored; scenario G reports how many newer events are not.
* The Primary replay policy tracks the latest boot session per sensor; a key holder can always start a new boot
  session. Replay protection stops reuse of consumed sequences, not a compromised key.
* The lab's own evidence rows and demo-identity readings live in the demo databases; `demo:restore` resolves lab
  incidents but deliberately deletes nothing.
