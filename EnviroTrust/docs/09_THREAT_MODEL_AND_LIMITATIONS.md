# 09 — Threat Model, Abuse Cases and Limitations

## 1. Assets to protect

- Sensor private keys.
- Witness checkpoint private key.
- User credentials and sessions.
- Approved public-key registry.
- Original signed telemetry envelopes.
- Primary audit history.
- Witness's independent event history and checkpoints.
- Operating-context signed records.
- Compliance profile/configuration history.
- Anomaly results and investigation records.

## 2. Trust boundaries

1. Sensor simulator to primary API.
2. Sensor simulator to witness API.
3. Operations simulator to primary API.
4. Human browser to primary API.
5. Primary API to ML service.
6. Primary service to witness reconciliation API.
7. Primary database vs separate witness storage.

## 3. Threats and controls

| Threat | Control | Residual limitation |
|---|---|---|
| Modify payload in transit | Ed25519 signature + HTTPS | Compromised signing key can create valid modified payloads |
| Submit unapproved device | Pre-enrolled public key and key-to-device binding | Bad provisioning can bind wrong key |
| Replay old reading | Message ID + boot ID + sequence uniqueness | Out-of-order legitimate delivery is simplified in MVP |
| Steal sensor private key | Local restricted files; revoke/rotate key | Software files are not hardware-backed |
| Rewrite primary database | Witness independent copy and signed checkpoints | Coordinated compromise of both stores defeats separation |
| Primary suppresses record | Sensor sends directly to witness; compare histories | Compromised simulator can suppress before both sends |
| Witness suppresses record | Compare primary and witness records; witness health | Witness can be unavailable or compromised |
| Sensor stops sending | Signed heartbeat monitoring | Cannot infer cause or intent from silence |
| Sensor reports constant false value | Flatline rule and process-context model | Real processes can be stable; false positives possible |
| Plausible false value signed by compromised sensor | Context cross-check and independent testing | Model cannot prove physical truth |
| Operating context manipulated | Separate signed OPS source | All simulated context is still generated software data |
| Admin changes limits | Versioned profiles and append-only config events | Platform admin compromise remains a risk |
| Flood ingestion API | Rate limits, body-size limits, schema validation | DDoS resilience is not fully implemented |
| XSS steals user session | Output encoding, CSP, safe UI patterns, HttpOnly cookies | Browser/host compromise remains possible |
| Unauthorized cross-site access | Server-side RBAC/site scoping | Requires tests on every route |
| ML false positives | Validation-derived thresholds and human review | Synthetic model does not generalize to real plants |

## 4. Key compromise process

1. Admin marks key revoked.
2. New readings under key are rejected.
3. Key history remains available.
4. New key pair is generated and independently provisioned.
5. New public key is approved in primary and witness registries.
6. Old accepted records retain their historical signature-verification outcome; they are not silently rewritten.

## 5. Sensor clock and time trust

Sensor timestamp is signed but not independently trusted. Store server receive time and witness receive time. Do not claim that a signed sensor timestamp proves the physical time of measurement. Optional external timestamp anchoring is deferred.

## 6. Calibration truth

A signed calibration record proves the record was signed by the relevant key, not that a reference solution was correct or that the sensor is currently physically calibrated. Actual calibration requires a controlled reference standard and trustworthy procedure. Physical calibration is out of scope.

## 7. ML truth

The ML model is trained on synthetic data produced by the project's simulator. Its metrics describe synthetic test performance only. It must not claim production accuracy, regulatory-grade fraud detection or legal proof.

## 8. Witness truth

The witness is a simulated independent service. It is separate in process, key and storage for the demo, but may share the same physical laptop/network/admin. Do not claim real organizational independence. A real NGO/university/regulator witness requires an agreement, onboarding, key governance, operational availability and independent administration.

## 9. Regulatory truth

The product is a prototype trust layer. Applicable monitoring parameters/requirements vary by industry, consent/authorization and regulatory direction. Do not claim every Indian factory must stream the exact pH/COD/TSS set used in this demo. Do not present simulated limits as CPCB/MPCB legal limits. Verify current official documents before using a current regulatory claim in a presentation.

## 10. Honest product wording

Acceptable:

- “Detects modification of signed telemetry in the tested workflow.”
- “Compares primary records against independently retained witness records and signed checkpoints.”
- “Flags unusual relationships in synthetic operating-context data.”
- “Detects missing authenticated heartbeats.”

Not acceptable:

- “Prevents all pollution fraud.”
- “Makes sensor readings impossible to fake.”
- “Government/NGO certified” without actual authorization.
- “Proves the factory cheated.”
- “Legally admissible/officially compliant” without legal and regulatory validation.
