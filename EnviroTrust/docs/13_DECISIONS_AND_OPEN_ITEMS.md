# 13 — Architecture Decisions and Open Items

This file is the binding decision register. Antigravity must not change a decision without explicit user approval.

## 1. Confirmed decisions

| ID | Decision | Rationale |
|---|---|---|
| D-001 | Project name is EnviroTrust | Stable project identity |
| D-002 | Domain is Water & Waste Management | Hackathon domain selection |
| D-003 | Initial use case is industrial effluent monitoring | Narrow, demonstrable problem |
| D-004 | No physical hardware in MVP | 15-hour software-only build |
| D-005 | Monitor pH, COD and TSS in simulation | Small, recognizable parameter set |
| D-006 | COD is the only ML regression target | Time and data constraint |
| D-007 | Sensor simulator signs telemetry using Ed25519 | Clear device identity/signature model |
| D-008 | React never holds or uses sensor private keys | Correct trust boundary |
| D-009 | Primary and witness independently verify original envelope | Prevent reliance on one backend assertion |
| D-010 | Sensor sends same envelope directly to both services | Witness can retain independent receipt |
| D-011 | Witness stores its own event history and signs checkpoints | Detect changes/omissions relative to retained history |
| D-012 | One simulated independent witness is P0 | Real institution onboarding is outside scope |
| D-013 | NGO/university second witness is optional P1 | Avoid overbuilding |
| D-014 | Witness signs checkpoints, not every reading | Efficient attestation model |
| D-015 | SHA-256 hash chain is P0; full Merkle tree is deferred | Lower implementation risk |
| D-016 | HTTPS/TLS provides transport encryption | Ed25519 is signatures, not encryption |
| D-017 | Signed heartbeats are P0 | Demonstrates availability monitoring |
| D-018 | RandomForestRegressor predicts COD from synthetic signed context | Feasible explainable ML feature |
| D-019 | Flatline/sudden-change use rules | Do not overcomplicate ML |
| D-020 | ML results are not proof of fraud | Avoid unsupported claims |
| D-021 | Challenge-response is optional P1 and proves key liveness only | It cannot prove physical calibration |
| D-022 | OpenTimestamps/Bitcoin anchoring is deferred | Not needed for 15-hour MVP |
| D-023 | No blockchain | Hash chain + witness is sufficient for prototype |
| D-024 | Simulated compliance profiles are clearly labelled | Avoid misrepresenting regulatory limits |
| D-025 | No actual CPCB/MPCB/NGO/university integration is claimed | No authorization/partnership established |

## 2. Fixed demo identifiers

- Site: `PLANT-001`
- Station: `ETP-OUTLET-001`
- Sensors: `PH-OUT-001`, `COD-OUT-001`, `TSS-OUT-001`
- Operations source: `OPS-001`
- Witness: `WITNESS-001` (display label must include “Simulated Independent Witness”)

These are demo identifiers only.

## 3. Default demo settings

Keep in configuration, not scattered magic numbers:

- Telemetry interval: 5–10 seconds (accelerated demo).
- Heartbeat interval: 10 seconds.
- Offline after: 3 missed intervals + 5-second grace period.
- Witness checkpoint interval: 10 accepted events per station.
- Maximum future timestamp skew: 120 seconds (configurable).
- Maximum age for normal live telemetry: 300 seconds (configurable).
- ML context match tolerance: configurable interval; start with 60 seconds for simulation.
- Flatline window: 8 readings minimum, tolerance per parameter.

These are prototype defaults, not regulatory requirements.

## 4. Open items that may be decided by team

- Exact UI component library, provided it does not introduce unnecessary complexity.
- Exact chart library, provided it supports accessible time-series charts.
- Whether primary DB uses Prisma, Drizzle or node-postgres; preserve SQL constraints.
- Whether witness storage uses a separate PostgreSQL database or a separate local SQLite/file store. It must be separately permissioned and not queried from primary tables.
- Exact service ports, based on existing environment.
- Exact synthetic process generator coefficients, documented as simulation assumptions and validated on held-out synthetic data.

## 5. Decisions requiring explicit approval before changing

- Changing signature algorithm or signed payload fields.
- Letting frontend sign telemetry.
- Sharing private keys between services/devices.
- Removing independent witness direct ingestion.
- Removing witness independent storage/checkpoints.
- Combining signature validity, ML anomaly and environmental compliance into one status.
- Claiming real physical sensor calibration or real regulatory/NGO endorsement.
- Adding blockchain or external timestamping.
