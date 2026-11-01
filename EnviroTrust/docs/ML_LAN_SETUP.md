# EnviroTrust — ML Integration over Local LAN Setup Guide

This guide details the exact operational setup for connecting the Node.js Primary API (running on the backend laptop) to our teammate's Python FastAPI service (running on a separate Windows laptop) over a shared local Wi-Fi or Ethernet LAN.

---

## 1. Architecture Overview & Network Roles

```
+------------------------------------+          +------------------------------------+
|       LAPTOP 1: ML TEAMMATE        |          |      LAPTOP 2: PRIMARY BACKEND     |
|   (Windows / Python 3.11+ / LAN)   |          |    (Windows / Node.js 24 LTS / LAN)|
|                                    |          |                                    |
|  FastAPI Model Inference Service   |          |  EnviroTrust Express Primary API   |
|  - Host binding: 0.0.0.0           |  HTTP    |  - Host binding: 127.0.0.1 / 0.0.0.0|
|  - Port: 8000                      |<---------|  - Port: 4000                      |
|  - Auth: ML_SERVICE_TOKEN          |  (LAN)   |  - Client: ML HTTP Worker Service  |
|                                    |          |                                    |
|  Firewall: Port 8000 Inbound Allow |          |  PostgreSQL Database: Port 5432    |
+------------------------------------+          +------------------------------------+
```

> [!IMPORTANT]
> **Network Trust Boundary**:
> For local demonstration and hackathon evaluation, plaintext HTTP is permitted exclusively over a private, trusted Wi-Fi/Ethernet LAN. For any public or untrusted network deployment, TLS (HTTPS) or a private encrypted WireGuard/Tailscale VPN tunnel is strictly mandatory.
> 
> **Service Isolation**:
> The FastAPI service is internal-only. It must **never** be exposed directly to browsers or public networks. Only the Node.js Primary API backend communicates directly with the ML service.

---

## 2. Configuration Files & Environment Variables

### A. Location of Node.js API Environment File
The Primary API consumes its environment from the local file:
`c:\ALL FILES HERE\ALL REPOS\Repo\EnviroTrust\apps\api\.env`
*(Alternatively, values in repo root `.env` are also loaded during root script execution).*

### B. Node.js API Settings (`apps/api/.env`)
Edit `apps/api/.env` on **LAPTOP 2** (do not commit this file):

```env
# Enable ML Assessment Worker
ML_ENABLED=true

# Remote FastAPI Base URL on teammate's laptop (Port 8000)
# Replace <ML_TEAMMATE_LAN_IP> with the IPv4 address obtained in Step 3
ML_BASE_URL=http://<ML_TEAMMATE_LAN_IP>:8000

# Bounded Timeout (in milliseconds)
ML_TIMEOUT_MS=5000

# Shared Service Secret (must match LAPTOP 1 exactly)
ML_SERVICE_TOKEN=<SHARED_RANDOM_SECRET_AT_LEAST_16_CHARS>
```

> [!WARNING]
> - Never hardcode an IP address into tracked codebase files.
> - Never prefix these variables with `VITE_`.
> - Never expose `ML_SERVICE_TOKEN` to the browser frontend.

### C. Teammate FastAPI Settings (`services/ml/.env`)
Configured on **LAPTOP 1** by the ML teammate:

```env
ML_HOST=0.0.0.0
ML_PORT=8000
ML_SERVICE_TOKEN=<SHARED_RANDOM_SECRET_AT_LEAST_16_CHARS>
MODEL_PATH=./models/cod_model.joblib
```

---

## 3. Step-by-Step Setup & Verification Instructions

### Step 1: Obtain Teammate's LAN IPv4 Address
**Run on LAPTOP 1 (ML Teammate) in PowerShell:**
```powershell
# Display active IPv4 network configuration
ipconfig
```
*Look for the active Wi-Fi or Ethernet adapter's `IPv4 Address` (e.g., `10.23.25.3` or `192.168.1.150`). Note this address down.*

---

### Step 2: Configure Windows Firewall for Port 8000
By default, Windows Firewall blocks incoming connections from other devices on the LAN.

**Run on LAPTOP 1 (ML Teammate) in an Administrative PowerShell terminal:**
```powershell
# Open inbound TCP port 8000 for FastAPI on private/domain networks
New-NetFirewallRule -DisplayName "EnviroTrust FastAPI ML Inbound" `
                    -Direction Inbound `
                    -LocalPort 8000 `
                    -Protocol TCP `
                    -Action Allow `
                    -Profile Private,Domain
```

---

### Step 3: Start the FastAPI Service
**Run on LAPTOP 1 (ML Teammate) in Terminal 1:**
```powershell
cd services\ml

# Activate virtual environment if configured
# .\venv\Scripts\Activate.ps1

# Start Uvicorn bound to 0.0.0.0 so remote LAN devices can connect
uvicorn main:app --host 0.0.0.0 --port 8000 --reload
```

---

### Step 4: Verify Network Connectivity from Primary API Laptop
**Run on LAPTOP 2 (Primary Backend) in PowerShell:**
```powershell
# Test TCP connectivity to teammate's port 8000 (replace with teammate's actual IP)
Test-NetConnection -ComputerName <ML_TEAMMATE_LAN_IP> -Port 8000
```
**Expected Output:**
`TcpTestSucceeded : True`

*If `TcpTestSucceeded : False`, check:*
1. Both laptops are on the exact same Wi-Fi network (no AP isolation enabled).
2. The teammate's firewall rule in Step 2 was created.
3. Teammate's network connection is set to "Private network", not "Public network".

---

### Step 5: Test the FastAPI Health Endpoint
**Run on LAPTOP 2 (Primary Backend) in PowerShell:**
```powershell
# Probe the remote ML health endpoint
Invoke-RestMethod -Uri "http://<ML_TEAMMATE_LAN_IP>:8000/ml/v1/health" `
                  -Method GET `
                  -Headers @{ "Authorization" = "Bearer <SHARED_RANDOM_SECRET>" }
```
**Expected Output:**
```json
{
  "status": "ok",
  "ready": true,
  "modelVersion": "rf-cod-v1.0"
}
```

---

### Step 6: Start Primary API & Background Worker
**Run on LAPTOP 2 (Primary Backend) in Terminal 1:**
```powershell
# Ensure local database migrations are applied
npm run db:migrate

# Start the Node.js Primary API server
npm run dev --workspace=@envirotrust/api
```
**Console Log Confirmation:**
```
[envirotrust-api] Primary API running on port 4000
[envirotrust-api] ML_ENABLED is true. Starting background assessment worker...
```

---

### Step 7: Run End-to-End Live Assessment Demonstration

**1. Send Signed Operations Context:**
**Run on LAPTOP 2 (Primary Backend) in Terminal 2:**
```powershell
# Dispatch signed operational context from OPS-001
npm run ops:send-once
```

**2. Send Signed COD Sensor Telemetry:**
**Run on LAPTOP 2 in Terminal 2:**
```powershell
# Dispatch signed COD reading from COD-OUT-001
npm run sensor:send-once
```

**3. Verify Assessment via Node.js Primary API:**
**Run on LAPTOP 2 in Terminal 2:**
```powershell
# Query the latest ML assessments for PLANT-001 (requires login token)
$LOGIN = Invoke-RestMethod -Uri "http://localhost:4000/api/v1/auth/login" `
                           -Method POST `
                           -ContentType "application/json" `
                           -Body '{"email":"admin@envirotrust.local","password":"DemoPassword123!"}'

$TOKEN = $LOGIN.accessToken

# Fetch latest assessment
Invoke-RestMethod -Uri "http://localhost:4000/api/v1/ml/assessments/latest?siteId=PLANT-001" `
                  -Method GET `
                  -Headers @{ "Authorization" = "Bearer $TOKEN" }
```

---

## 4. Troubleshooting Guide

| Symptom | Probable Cause | Corrective Action |
| :--- | :--- | :--- |
| `Test-NetConnection` returns `False` | Windows Firewall or AP Isolation | Run `New-NetFirewallRule` on Laptop 1. Verify Wi-Fi network profile is "Private". |
| `ML_HTTP_ERROR` status 401 | Shared secret mismatch | Ensure `ML_SERVICE_TOKEN` in `apps/api/.env` strictly matches `ML_SERVICE_TOKEN` on Laptop 1. |
| `status: "NOT_EVALUATED"` (INSUFFICIENT_CONTEXT) | No overlapping ops context | Send `npm run ops:send-once` within 10 minutes of sending sensor reading. Future context is rejected. |
| `ML_TIMEOUT` | Python model taking $> 5000$ms | Increase `ML_TIMEOUT_MS=10000` in `apps/api/.env` if model inference is cold-starting. |
| Cryptographic signature error (401) | Reading tampered in transit | Sensor readings are cryptographically signed before transmission. Do not modify payload bytes. |

