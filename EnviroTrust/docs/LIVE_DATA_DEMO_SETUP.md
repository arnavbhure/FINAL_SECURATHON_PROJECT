# EnviroTrust — Live Server Data, ML Assessment & Stream Integration Runbook

> **SYSTEM PROVENANCE & DEMONSTRATION NOTICE**
> All sensor hardware readings, operational context parameters, and physical enclosure signals within this hackathon demonstration originate from **signed software simulators** (`apps/sensor-simulator` and `apps/ops-simulator`). No physical hardware enclosures, switches, or physical sensors are connected. All UI graphs, tables, and witness receipts reflect **genuine live backend events** ingested into PostgreSQL and evaluated by the ML and Witness services.

---

## 1. System Architecture & Topology

EnviroTrust operates as an integrated zero-trust industrial telemetry, cryptographic audit, and ML chemical assessment platform:

```
[ Sensor Simulator ] ---> (Ed25519 Signed Telemetry & Heartbeats) ---\
                                                                     +--> [ Express API :4000 ] <---> [ PostgreSQL ]
[ Ops Simulator ]    ---> (Signed Chemical & Flow Context) ----------/           |        ^
                                                                                 |        | (Residuals / Assessments)
                                                                                 v        v
[ React Dashboard :5173 ] <--(Vite Proxy /api)------------------------------> [ FastAPI ML :8000 (LAN 10.16.6.81) ]
         |
         \--(Vite Proxy /api/v1/witness)--> [ Express API :4000 ] ---------> [ Witness Service :4001 ] <---> [ Witness DB ]
```

### Architectural Principles:
1. **Zero Browser-Direct Backend Calls**: The React browser client communicates **exclusively** with the Express Primary API (via `/api` reverse proxy). The browser never calls the internal FastAPI service (`:8000`) or Witness service (`:4001`) directly.
2. **Dual-Delivery Path**: High-integrity sensor telemetry is delivered concurrently to both the Primary API and the Independent Witness service.
3. **Session Continuity Across Reloads**: User JWT credentials are encrypted in cookies (`envirotrust_jwt`) and stored in secure client storage. Authenticated Express routes automatically verify the JWT from both Bearer headers and cookies. Browser reloads preserve the active session without flashing login.
4. **Live Continuous ML COD Graph**: COD actual telemetry readings appear instantly upon ingestion. As the remote ML model evaluates the dual streams, predictions and dynamic residual thresholds populate in real time with zero hardcoded mock values.

---

## 2. Complete Demonstration Startup Sequence (PowerShell)

Open separate Windows PowerShell terminals for each service and execute the commands in the order shown below.

### Terminal 1: PostgreSQL Databases & Migrations
Ensure PostgreSQL 16+ is running locally on port `5432`:
```powershell
# Verify PostgreSQL service is active
Get-Service postgresql*

# Run database migrations for Primary API and Witness Service
npm run migrate
```

### Terminal 2: Express Primary API (Port 4000)
```powershell
cd "c:\ALL FILES HERE\ALL REPOS\Repo\EnviroTrust"
npm run dev:api
```
*Expected log output:*
```
[Primary API] Server listening on port 4000 (environment: development)
[Primary API] Connected to PostgreSQL at localhost:5432/envirotrust_primary
[Primary API] Mounted routes: /api/v1/auth, /api/v1/monitoring, /api/v1/ml, /api/v1/witness, /api/v1/alerts
```

### Terminal 3: Independent Witness Service (Port 4001)
```powershell
cd "c:\ALL FILES HERE\ALL REPOS\Repo\EnviroTrust"
npm run dev:witness
```
*Expected log output:*
```
[Witness Service] Server listening on port 4001
[Witness Service] Connected to PostgreSQL at localhost:5432/envirotrust_witness
[Witness Service] Cryptographic signing key loaded (ES256)
```

### Terminal 4: Teammate's LAN FastAPI ML Service (Port 8000)
*Run on teammate's laptop (`10.16.6.81:8000`) or local emulator:*
```powershell
cd "c:\ALL FILES HERE\ALL REPOS\Repo\EnviroTrust\services\ml"
uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload
```
*Verification:*
```powershell
# Test ML endpoint from Primary API host
curl http://10.16.6.81:8000/health
```

### Terminal 5: Continuous Simulators Stream (`stream:all`)
Starts concurrent periodic emission for both effluent sensors (COD, pH, TSS) and operational context:
```powershell
cd "c:\ALL FILES HERE\ALL REPOS\Repo\EnviroTrust"
npm run stream:all
```
*Configuration variables (optional overrides):*
```powershell
$env:SENSOR_TELEMETRY_INTERVAL_MS = "5000"  # 5-second sensor emission cadence
$env:OPS_CONTEXT_INTERVAL_MS     = "15000" # 15-second operational context cadence
npm run stream:all
```
*Clean shutdown: Press `Ctrl+C` in Terminal 5. Both stream runners gracefully terminate.*

### Terminal 6: React Web Dashboard (Port 5173)
```powershell
cd "c:\ALL FILES HERE\ALL REPOS\Repo\EnviroTrust"
npm run dev:web
```
*Navigate to:* `http://localhost:5173`

---

## 3. Demo Roles & Authentication Credentials

| Role | Email Address | Password | Permissions |
| :--- | :--- | :--- | :--- |
| **Platform Admin** | `admin@envirotrust.local` | `DemoPassword123!` | Global administrative access, user management, tamper simulation lab |
| **Factory Operator** | `operator@envirotrust.local` | `DemoPassword123!` | Plant-level operational telemetry, COD monitoring, stream health |
| **Regulator Auditor**| `auditor@envirotrust.local` | `DemoPassword123!` | Read-only regulatory audit, witness hash chain recomputation, proof inspection |

*Quick-login pills on the redesigned Better Stack login screen allow 1-click credential population.*

---

## 4. End-to-End Verification Checkpoints

1. **Session Persistence**:
   - Log in as `operator@envirotrust.local`.
   - Refresh the page (`F5` or `Ctrl+R`).
   - The user remains logged in without flickering or returning to the login screen.
2. **Live COD Monitoring Graph (`/anomalies`)**:
   - As `stream:all` runs, observe the COD graph updating automatically every 3.5 seconds.
   - Newly ingested COD readings appear immediately with a `PENDING ASSESSMENT` indicator.
   - Once the ML model computes the residual, the point transitions to `CONSISTENT` (green) or `SUSPICIOUS` (red) with dynamic model baseline and threshold lines.
3. **Sensor Fleet Availability (`/sensors`)**:
   - Active sensor heartbeat timestamps refresh dynamically.
   - Status transitions (`ONLINE` $\to$ `STALE` $\to$ `OFFLINE`) reflect actual elapsed time without hardcoded confirmations.
4. **Independent Witness Verification (`/audit`)**:
   - Checkpoint sequences increment every 10 events.
   - Click "Verify Witness Hash Chain" to trigger cryptographic recomputation of SHA-256 chain continuity.
   - Verify that all requests route through `/api/v1/witness/*` on port 4000.

