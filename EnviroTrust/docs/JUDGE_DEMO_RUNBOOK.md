# Judge Demo Runbook — Attack Simulation Lab (Windows PowerShell)

> **DEMO ENVIRONMENT.** All sensors, keys, operating context and the Independent Witness are software
> simulations running on the team's laptops. Nothing here is connected to real hardware, a real regulator or a
> real NGO/university. See `docs/ATTACK_LAB.md` for what each scenario proves and what it does not.

## Machines and terminals

| Machine | Role |
|---|---|
| **Laptop A — Demo laptop** | PostgreSQL, Primary API, Witness, simulators, React dashboard, Attack Lab CLI, browser for judges |
| **Laptop B — ML laptop** (optional) | The ML teammate's FastAPI Isolation Forest service (`services/ml`). If Laptop B is not available, run the FastAPI service on Laptop A or skip the ML part of scenario F (it then reports `ML_NOT_ENABLED` / `ML_UNAVAILABLE`, never a fabricated result) |

| Terminal | Machine | Runs |
|---|---|---|
| T1 | A | PostgreSQL check, migrations, keys, users, demo identities, CLI (`demo:*`) |
| T2 | A | Primary API (`:4000`) |
| T3 | A | Independent Witness (`:4001`) |
| T4 | B (or A) | FastAPI ML service (`:8000`) — owned by the ML teammate |
| T5 | A | Continuous sensor + operations simulators (`stream:all`) |
| T6 | A | React dashboard (`:5173`) |

Placeholders used below — replace them, never commit real values: `<REPO>` (repository folder on Laptop A),
`<ML_LAPTOP_IP>` (Laptop B's LAN address), `<ML_SHARED_TOKEN>` (token agreed with the ML teammate),
`<DEMO_ADMIN_PASSWORD>` (the password you seed for the demo accounts).

---

## Part 1 — One-time setup (Laptop A, T1)

### 1. Start PostgreSQL

```powershell
Get-Service postgresql*
# If it is not "Running" (the service name depends on the installed version):
Start-Service postgresql-x64-16
```

The two databases and roles (`envirotrust_primary` / `envirotrust_app`, `envirotrust_witness` /
`envirotrust_witness`) are created once as described in `docs/ENVIRONMENT_SETUP.md`. They must be separate
databases with separate credentials — the Attack Lab refuses to run otherwise.

### 2. Install, migrate, provision keys, seed users

```powershell
cd <REPO>
npm install
npm run build
npm run db:migrate
npm run witness:migrate
npm run keys:provision
npm run keys:register
npm run witness:keys:provision
npm run witness:keys:register
$env:DEMO_USER_PASSWORD = "<DEMO_ADMIN_PASSWORD>"
npm run users:seed
```

All private keys are written to the git-ignored `local-secrets/` folder. Never copy them into the repository.

### 3. Create the dedicated Attack Lab demo identities

```powershell
$env:DEMO_MODE = "true"
$env:ATTACK_LAB_ENABLED = "true"
npm run demo:provision
```

This creates `LAB-COD-901` (lab sensor for scenarios G, H, I) and `LAB-COD-902` (**SIMULATED COMPROMISED KEY**
for scenario F), stores their private keys in `local-secrets/attack-lab/identities/`, and registers the public
keys independently in the Primary and Witness registries. The demo sensors stay `INACTIVE` (no alerts) except
while H or I runs.

---

## Part 2 — Start the demo (every time)

### T4 — ML service (Laptop B, run by the ML teammate)

```powershell
cd <REPO>\services\ml
uvicorn app.main:app --host 0.0.0.0 --port 8000
```

Check from **Laptop A, T1**:

```powershell
Test-NetConnection <ML_LAPTOP_IP> -Port 8000
Invoke-RestMethod http://<ML_LAPTOP_IP>:8000/health
```

(Firewall/LAN troubleshooting: `docs/ML_LAN_SETUP.md`.) If the ML service runs on Laptop A, use `127.0.0.1`
instead of `<ML_LAPTOP_IP>`.

### T2 — Primary API (Laptop A)

```powershell
cd <REPO>
$env:DEMO_MODE = "true"
$env:ATTACK_LAB_ENABLED = "true"
$env:ATTACK_LAB_AUTHORIZED_ADMINS = "admin@envirotrust.local"
$env:ML_ENABLED = "true"
$env:ML_BASE_URL = "http://<ML_LAPTOP_IP>:8000"
$env:ML_SERVICE_TOKEN = "<ML_SHARED_TOKEN>"
npm run api:dev
```

Expected log: `Primary API running on port 4000` and, in the configuration summary, `ML_ENABLED: true`.
With `ML_ENABLED=true` every live COD reading is sent to the ML service; agree this with the ML teammate first.
Leave `ML_ENABLED` unset to keep the ML service out of the demo (scenario F then reports `ML_NOT_ENABLED`).

### T3 — Independent Witness (Laptop A)

```powershell
cd <REPO>
npm run witness:dev
```

### T5 — Continuous sensor and operations simulators (Laptop A)

```powershell
cd <REPO>
npm run stream:all
```

Every 5 s each simulated sensor signs a reading and a heartbeat and sends the same envelope to the Primary API
and the Witness; OPS-001 signs operating context every 15 s.

### T6 — React dashboard (Laptop A)

```powershell
cd <REPO>
$env:VITE_DEMO_MODE = "true"
npm run web:dev
```

Open `http://localhost:5173` in the browser on Laptop A.

### T1 — Pre-flight check (Laptop A)

```powershell
cd <REPO>
$env:DEMO_MODE = "true"
$env:ATTACK_LAB_ENABLED = "true"
npm run demo:doctor
```

Every line must show ✓ except optional ML lines (shown with `!`). Fix anything marked ✗ before judges arrive.

### Log in as the demo administrator

In the browser: sign in as `admin@envirotrust.local` with `<DEMO_ADMIN_PASSWORD>`, then open **Attack Simulation
Lab** in the sidebar. The header must show **DEMO ENVIRONMENT**, Primary API UP, Witness UP, ML service status,
**Safety gates ALL PASS** and **Demo identities 2/2**.

---

## Part 3 — Focused judge sequence (3–5 minutes, browser on Laptop A)

| Time | Action (Attack Simulation Lab page) | What to point at |
|---|---|---|
| 0:00 | Show the header. | DEMO ENVIRONMENT label, live service status, safety gates — the lab refuses to run if any gate fails. |
| 0:20 | Select **A — Telemetry Payload Tampering** → **Run Simulation** → **Confirm run**. | Timeline: value changed after signing → Primary `401 INVALID_SIGNATURE`, Witness `401 INVALID_SIGNATURE`, 0 trusted records, security event IDs, security alert. Outcome **PREVENTED**. |
| 1:00 | Click **Alert Center**. | The `SECURITY_EVENT` alert "SIGNED MESSAGE REJECTED — SIGNATURE VERIFICATION FAILED" (not a physical-tamper alert). Return with the browser Back button. |
| 1:20 | Run **D — Replay Attack**. | Case 1: byte-identical re-delivery → `200 isDuplicate` at both, still one record and one audit event (legitimate retry). Case 2: rolled-back sequence → `409 REPLAYED_SEQUENCE` at both. |
| 2:00 | Run **F — Authorised Insider / Compromised Signing Key** (needs ML; ~20–40 s). | Signatures **verify** at both services — cryptography cannot detect a stolen key. Then the actual model result: anomaly score, decision threshold, classification, model version, and how many genuine readings the same model flagged. Say clearly: detection is not guaranteed, a flag is not proof of fraud, and a flag the model also gives genuine readings is reported as `INCONCLUSIVE / ML_FLAG_NOT_SPECIFIC`. |
| 3:00 | Run **G — Historical Witness Record Tampering**. | Untouched export **PASS**; modified copy **FAIL** with the exact reason (e.g. `EVENT_HASH_MISMATCH` at witness sequence N); witness database record unchanged. Click **Audit & Witness** to show the live checkpoint. |
| 4:00 | (Optional, 75 s) Run **H — Sensor Heartbeat Interruption** while explaining the others; or show a previous H/I run from **Run history**. | STALE → OFFLINE (HIGH) → RECOVERED, no duplicate alerts; communication loss is not proof of tampering. |

Scenarios B, C, E and I can be run in the same way if judges ask; each takes 3–15 s.

### Same scenarios from the command line (T1, Laptop A)

```powershell
cd <REPO>
$env:DEMO_MODE = "true"
$env:ATTACK_LAB_ENABLED = "true"
npm run demo:attacks -- --scenario telemetry-tampering
npm run demo:attacks
```

The second command runs all nine scenarios (about 3 minutes) and exits with a non-zero code if any expected
outcome was not actually achieved — for example scenario F when ML is not enabled.

---

## Part 4 — Verify evidence after the demo (T1, Laptop A)

### Re-verify recorded runs and the witness chain

```powershell
npm run demo:verify
```

### Verify witness history offline (what an auditor does)

```powershell
npm run witness:checkpoint:export -- --output=witness-checkpoint-export.json
npm run witness:checkpoint:verify -- --file=witness-checkpoint-export.json
```

The verifier checks every checkpoint signature against the pinned witness key (from
`local-secrets/witness-keys/`, or pass `--pinned-fingerprint=<64-hex fingerprint obtained independently>`) and
recomputes every covered event hash. It prints `Overall Status: PASS` or the exact discrepancies. Only events
covered by a checkpoint are checkpoint-anchored. Delete the export file afterwards; it is not committed.

---

## Part 5 — Restore the demo environment (T1, Laptop A)

```powershell
npm run demo:restore -- --confirm
```

This takes the demo identities out of service, resolves incidents raised by recorded lab runs (the alerts stay in
the history with a resolution note), and clears the lab's own outbox and temporary export copies. It refuses to run
without `--confirm`, while a scenario is running, or when a safety gate fails, and it never deletes telemetry,
audit records, witness records, security events or run evidence.

To stop the demo, press `Ctrl+C` in T2, T3, T5 and T6 (and T4 on Laptop B).

## Troubleshooting

| Symptom | Fix |
|---|---|
| Lab page says the lab is disabled | T2 was started without `DEMO_MODE=true` and `ATTACK_LAB_ENABLED=true`; restart it with the variables above. |
| "Safety gates n FAILED" | Run `npm run demo:doctor`; usually a wrong database name or a non-local target. |
| Run button disabled: "Demo identities not provisioned" | `npm run demo:provision` (T1). |
| F shows `ML_NOT_ENABLED` | Restart T2 with `ML_ENABLED=true` and the ML variables. |
| F shows `ML_UNAVAILABLE` / `PENDING` | Laptop B unreachable or model not ready — see `docs/ML_LAN_SETUP.md`. |
| `409 RUN_IN_PROGRESS` | Another scenario is still running (UI or CLI); wait for it to finish. |
