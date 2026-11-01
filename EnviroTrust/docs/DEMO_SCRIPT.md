# EnviroTrust — Five-Minute Judge Demo Script

## Setup before judges arrive

- Show the permanent banner: `SIMULATED DATA — HACKATHON PROTOTYPE`.
- Start primary API, witness service, ML service, sensor simulator and operations simulator.
- Confirm the three sensors and operations source are provisioned.
- Confirm witness public-key fingerprint is pinned in the auditor UI.
- Ensure normal signed readings and heartbeats are flowing.
- Do not use actual factory, government, NGO or university names as participants.

## 0:00–0:45 — Explain the problem

“An environmental monitoring dashboard shows values, but a value alone does not explain who signed it, whether it was changed, whether history can be rewritten, whether a device went silent or whether the reading makes sense given industrial operations. EnviroTrust adds independent verification and anomaly analysis to simulated effluent monitoring.”

## 0:45–1:30 — Normal signed telemetry

1. Open Monitoring Overview.
2. Show pH/COD/TSS values.
3. Open a COD reading.
4. Show sensor ID, key fingerprint, signature status, sequence, server receipt time and witness receipt.
5. Explain: sensor simulator signs; primary and witness independently verify.

## 1:30–2:15 — Tampered reading

1. Trigger the controlled modify-in-transit scenario.
2. Show primary/witness rejection with `INVALID_SIGNATURE`.
3. Explain that the private key was not available to the interceptor and the signed payload changed.

## 2:15–3:00 — Independent witness

1. Open Audit & Witness.
2. Show witness event sequence and signed checkpoint.
3. Run reconciliation.
4. In test/demo fixture, alter or delete one primary record.
5. Show mismatch against the independent witness record/checkpoint.

## 3:00–3:40 — Sensor availability

1. Stop one sensor simulator.
2. Show last valid heartbeat.
3. Wait for configured offline threshold.
4. Show `OFFLINE — NO RECENT AUTHENTICATED HEARTBEAT`.
5. Explain that silence indicates loss of communication; it does not establish intent.

## 3:40–4:40 — ML contextual anomaly

1. Show normal COD/context relationship.
2. Trigger validly signed context-mismatch scenario.
3. Show that signature and witness status remain valid.
4. Show actual COD, predicted COD, residual, learned threshold and model reasons.
5. Explain that it is a synthetic process inconsistency requiring investigation, not proof of fraud.

## 4:40–5:00 — Close

“EnviroTrust separates four questions: who signed the data, whether the record history was changed, whether the sensor is communicating and whether the measurement behaviour is consistent with the process. It is a software prototype and a proposed trust layer, not a replacement for calibrated instruments or official OCEMS.”

## Questions to prepare for

- Does a signature prove the sensor's physical reading is correct? No.
- Why does the witness sign checkpoints instead of each reading? It independently retains events and periodically attests to a chain head; signing every reading at every institution is unnecessary for the MVP.
- Why not blockchain? The prototype's requirement is independent retention and verifiability; blockchain is not required to demonstrate it.
- Is the NGO real? No. It is represented by a simulated independent witness service.
- Is the ML trained on real factory data? No. It is trained and evaluated on synthetic demonstration data.
- Is this integrated with CPCB/MPCB? No. It is a proposed complementary prototype.
