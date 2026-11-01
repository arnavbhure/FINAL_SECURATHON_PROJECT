# EnviroTrust — Antigravity Project Specification Pack

**Document version:** 1.1  
**Product type:** Software-only hackathon prototype  
**Target build window:** Approximately 15 team-hours of active hackathon development  
**Status:** Implementation baseline; not a production regulatory system

## What this project is

EnviroTrust is a cryptographic trust and anomaly-detection layer for simulated industrial effluent monitoring. It does **not** replace CPCB/MPCB OCEMS, a laboratory, a calibrated physical sensor, an environmental regulator, or an official compliance determination.

The prototype demonstrates four distinct controls:

1. **Sensor authenticity and message integrity:** simulated sensor identities sign telemetry using Ed25519; the ingestion service verifies signatures against previously approved public keys.
2. **Tamper-evident history:** the primary service records accepted telemetry in an append-only hash chain; an independent witness service receives the same signed sensor envelope directly, verifies it independently, stores its own copy, builds its own chain, and signs periodic checkpoints.
3. **Availability monitoring:** sensors send signed heartbeats; missed heartbeats create an availability alert. A missed heartbeat is not proof of deliberate shutdown.
4. **Behavioural/process analysis:** a Python ML service estimates expected outlet COD from separate, signed simulated operating-context data and compares the estimate with the signed COD reading. Statistical rules detect flatline and sudden-change patterns.

## Required reading order

Antigravity and every developer must read these files before implementing features:

1. `AGENT_RULES.md`
2. `OWNERSHIP_AND_AGENT_BOUNDARIES.md`
3. `ENVIRONMENT_SETUP.md`
4. `01_PRODUCT_REQUIREMENTS.md`
5. `02_SCOPE_AND_ACCEPTANCE.md`
6. `03_ARCHITECTURE_AND_FLOWS.md`
7. `04_CRYPTOGRAPHIC_PROTOCOL.md`
8. `05_INDEPENDENT_WITNESS.md`
9. `06_ML_SPECIFICATION.md` (ML teammate implements; Antigravity integrates only)
10. `ML_TEAMMATE_HANDOFF.md`
11. `07_DATABASE_AND_API_CONTRACTS.md`
12. `08_UI_UX_AND_ACCESS_CONTROL.md`
13. `09_THREAT_MODEL_AND_LIMITATIONS.md`
14. `10_TESTING_AND_SECURITY_REVIEW.md`
15. `11_15_HOUR_EXECUTION_PLAN.md`
16. `12_ANTIGRAVITY_PROMPTS.md`
17. `13_DECISIONS_AND_OPEN_ITEMS.md`
18. `CODE_REVIEW_CHECKLIST.md`, `DEMO_SCRIPT.md` and `GLOSSARY.md`

Machine-readable contracts are in `contracts/`. SQL reference schemas are in `database/`. `ENVIRONMENT_SETUP.md` explains every environment variable and process. The service-specific `*_env.example` files are templates; they contain placeholders only.

## Ownership split

Antigravity implements the web app, primary API, PostgreSQL integration, sensor/operations simulators, cryptography, witness service, dashboard, attack demonstrations and the ML integration client. A designated human teammate implements the Python ML model and FastAPI service under `services/ml/`. Antigravity must not implement or rewrite that Python ML service. See `OWNERSHIP_AND_AGENT_BOUNDARIES.md` and `ML_TEAMMATE_HANDOFF.md`.

## Source-of-truth and conflict rules

- The documents in this pack are the product's source of truth.
- `13_DECISIONS_AND_OPEN_ITEMS.md` records decisions that must not be silently changed.
- `contracts/*.schema.json` defines wire-format fields. If prose and a schema conflict, stop and report the conflict; do not invent a third format.
- `database/*.sql` is a reference schema. If the implementation uses a migration framework, migrations must preserve the same entities, constraints and immutability assumptions.
- Do not add features just because they are easy to generate.
- Do not claim real institutional participation, regulatory approval, real pollution measurements, real sensor calibration, or real-world model accuracy.

## Non-negotiable product truths

- React does not sign sensor measurements.
- A sensor simulator signs its own readings with its private key.
- The primary backend and independent witness each verify that signature using an approved public key.
- The witness signs checkpoints, not every sensor reading.
- The witness is a **simulated independent organization/service** for the hackathon. No NGO, university, CPCB or MPCB is actually connected unless the team obtains and documents a real agreement.
- Ed25519 is a signature scheme, not encryption.
- HTTPS/TLS protects data in transit. Ed25519 provides authenticity/integrity. SHA-256 provides hashes. These are different functions.
- A valid signature does not prove a measurement is physically accurate.
- ML generates investigation signals; it does not prove fraud or legal non-compliance.
- Environmental limit exceedance, security failure, data-quality failure and ML anomaly are separate statuses.

## Suggested monorepo layout

```text
envirotrust/
├── apps/
│   ├── web/                 # React dashboard
│   ├── api/                 # Express primary backend
│   ├── sensor-simulator/    # Simulated sensor identities and signed telemetry
│   ├── ops-simulator/       # Separate signed plant operational context
│   └── witness/             # Independent witness service and storage
├── services/
│   └── ml/                  # Python ML teammate-owned FastAPI + scikit-learn service
├── contracts/               # JSON Schema files from this pack
├── database/                # SQL reference schemas/migrations
├── .env.example
└── README.md
```

This is a recommended logical layout, not a demand to create a complicated monorepo framework. If the existing repository has a simpler structure, preserve it and map the same responsibilities cleanly.

## Definition of a successful MVP

A user can log in as a platform administrator, factory operator or regulator/auditor. A simulated sensor creates a reading, signs it, and sends the same envelope to both the primary API and witness. Both independently verify it. The primary API applies replay/freshness checks and stores it. Both services preserve their own audit history. The witness issues a signed checkpoint. The dashboard can compare primary and witness records. A controlled tampering scenario fails signature or audit verification. A validly signed but suspicious COD reading is flagged by the ML service using independently signed operational context. A stopped simulator causes a missing-heartbeat alert.

A complete build is not “all screens render.” It is the acceptance tests in `10_TESTING_AND_SECURITY_REVIEW.md` passing.

## External technical references

Use these references for implementation details; do not treat them as proof that EnviroTrust is regulator-approved:

- RFC 8785 — JSON Canonicalization Scheme: https://www.rfc-editor.org/rfc/rfc8785
- RFC 8032 — Edwards-Curve Digital Signature Algorithm (EdDSA): https://www.rfc-editor.org/rfc/rfc8032
- Node.js Crypto API: https://nodejs.org/api/crypto.html
- NISTIR 8259A — IoT Device Cybersecurity Capability Core Baseline: https://csrc.nist.gov/pubs/ir/8259/a/final
- Scikit-learn RandomForestRegressor: https://scikit-learn.org/stable/modules/generated/sklearn.ensemble.RandomForestRegressor.html
- MPCB OCEMS connectivity procedure (verify latest official version before making any current compliance claim): https://www.mpcb.gov.in/

## Important note on AI coding agents

No prompt or document can guarantee that an AI coding agent produces 100% correct code. This pack reduces ambiguity. The team must still inspect every diff, run tests, review security-sensitive code and reject unverified claims. Follow `AGENT_RULES.md` and implement phase-by-phase.
