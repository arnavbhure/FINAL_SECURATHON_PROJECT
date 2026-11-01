# EnviroTrust documentation index

Read `AGENT_RULES.md` first, then follow the numbered documents.

## Core specifications
- [README.md](README.md)
- [AGENT_RULES.md](AGENT_RULES.md)
- [01_PRODUCT_REQUIREMENTS.md](01_PRODUCT_REQUIREMENTS.md)
- [02_SCOPE_AND_ACCEPTANCE.md](02_SCOPE_AND_ACCEPTANCE.md)
- [03_ARCHITECTURE_AND_FLOWS.md](03_ARCHITECTURE_AND_FLOWS.md)
- [04_CRYPTOGRAPHIC_PROTOCOL.md](04_CRYPTOGRAPHIC_PROTOCOL.md)
- [05_INDEPENDENT_WITNESS.md](05_INDEPENDENT_WITNESS.md)
- [06_ML_SPECIFICATION.md](06_ML_SPECIFICATION.md)
- [07_DATABASE_AND_API_CONTRACTS.md](07_DATABASE_AND_API_CONTRACTS.md)
- [08_UI_UX_AND_ACCESS_CONTROL.md](08_UI_UX_AND_ACCESS_CONTROL.md)
- [09_THREAT_MODEL_AND_LIMITATIONS.md](09_THREAT_MODEL_AND_LIMITATIONS.md)
- [10_TESTING_AND_SECURITY_REVIEW.md](10_TESTING_AND_SECURITY_REVIEW.md)
- [11_15_HOUR_EXECUTION_PLAN.md](11_15_HOUR_EXECUTION_PLAN.md)
- [12_ANTIGRAVITY_PROMPTS.md](12_ANTIGRAVITY_PROMPTS.md)
- [13_DECISIONS_AND_OPEN_ITEMS.md](13_DECISIONS_AND_OPEN_ITEMS.md)
- [GLOSSARY.md](GLOSSARY.md)

## Machine-readable / implementation references
- [CODE_REVIEW_CHECKLIST.md](CODE_REVIEW_CHECKLIST.md)
- [DEMO_SCRIPT.md](DEMO_SCRIPT.md)
- `contracts/telemetry.schema.json`
- `contracts/signed-telemetry-envelope.schema.json`
- `contracts/signed-heartbeat-envelope.schema.json`
- `contracts/signed-ops-context-envelope.schema.json`
- `contracts/heartbeat.schema.json`
- `contracts/ops-context.schema.json`
- `contracts/ml-result.schema.json`
- `database/primary-schema.sql`
- `database/witness-schema.sql`
- `.env.example`
- `.gitignore.example`


## Ownership and environment additions (v1.1)

- `OWNERSHIP_AND_AGENT_BOUNDARIES.md` — Antigravity vs human ML teammate responsibilities.
- `ML_TEAMMATE_HANDOFF.md` — concise implementation brief for the ML teammate.
- `ENVIRONMENT_SETUP.md` — ports, environment variables, secrets and local setup.
- `apps_api_env.example`, `apps_web_env.example`, `apps_witness_env.example`, `apps_simulator_env.example`, `services_ml_env.example` — service-specific environment examples.

- `contracts/ml-request.schema.json` — exact primary-to-ML request body schema.

## Attack Simulation Lab (Prompt 9)

- `ATTACK_LAB.md` — architecture, safety gates, scenarios A–I, classification, evidence, CLI, limitations.
- `JUDGE_DEMO_RUNBOOK.md` — Windows PowerShell start-up, 3–5 minute judge sequence, verification and restore.
