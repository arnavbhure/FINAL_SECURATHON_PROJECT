import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { canRunScenario, mlResultLines, outcomeTone, runDurationSeconds } from '../src/pages/attackLabView.js';
import type { AttackLabStatus, AttackScenario } from '../src/types/index.js';

const scenario = (overrides: Partial<AttackScenario> = {}): AttackScenario => ({
  id: 'telemetry-tampering',
  letter: 'A',
  name: 'Telemetry Payload Tampering',
  description: '',
  threatCategory: '',
  mechanismTested: '',
  expectedResponse: '',
  severity: 'HIGH',
  requiresConfirmation: false,
  requiresDemoIdentities: false,
  estimatedDurationSeconds: 3,
  evidenceLinks: [],
  ...overrides,
});

const status = (overrides: Partial<AttackLabStatus> = {}): AttackLabStatus => ({
  environmentLabel: 'DEMO ENVIRONMENT',
  siteCode: 'PLANT-001',
  stationCode: 'ETP-OUTLET-001',
  canExecute: true,
  safety: { ok: true, checks: [] },
  services: {
    primary: { reachable: true, httpStatus: 200, detail: 'UP' },
    witness: { reachable: true, httpStatus: 200, detail: 'UP', witnessId: 'WITNESS-001', displayName: 'Simulated Independent Witness' },
    ml: { reachable: false, httpStatus: null, detail: 'down', enabledOnPrimary: false, ready: null, modelVersion: null, modelMode: null },
  },
  demoIdentities: { 'LAB-COD-901': { ready: true, keyId: 'K1' }, 'LAB-COD-902': { ready: false, keyId: null } },
  activeRun: null,
  ...overrides,
});

describe('Attack Lab view logic', () => {
  it('maps outcomes to distinct tones; acceptance is never shown as safe', () => {
    assert.equal(outcomeTone('PREVENTED'), 'success');
    assert.equal(outcomeTone('DETECTED'), 'info');
    assert.equal(outcomeTone('SUSPICIOUS'), 'warning');
    assert.equal(outcomeTone('ACCEPTED'), 'danger');
    assert.equal(outcomeTone('INCONCLUSIVE'), 'neutral');
    assert.equal(outcomeTone('SERVICE_UNAVAILABLE'), 'neutral');
  });

  it('shows only values the model returned and never a COD prediction', () => {
    const lines = mlResultLines({ status: 'SUSPICIOUS', detail: '', anomalyScore: 0.21, anomalyThreshold: 0.07, modelVersion: 'm1' });
    assert.deepEqual(
      lines.map((l) => l.label),
      ['Classification', 'Anomaly score', 'Decision threshold', 'Model version']
    );
    assert.equal(lines.some((l) => /predict/i.test(l.label)), false);
    assert.deepEqual(mlResultLines({ status: 'ML_UNAVAILABLE', detail: 'down' }).map((l) => l.value), ['ML UNAVAILABLE']);
  });

  it('gates the Run button on server-side permission, safety, services and demo identities', () => {
    assert.equal(canRunScenario(status(), scenario()).allowed, true);
    assert.equal(canRunScenario(status({ canExecute: false }), scenario()).allowed, false);
    assert.equal(canRunScenario(status({ safety: { ok: false, checks: [] } }), scenario()).allowed, false);
    assert.equal(canRunScenario(status({ activeRun: { id: 'r', scenarioId: 'x', startedAt: '' } }), scenario()).allowed, false);
    assert.equal(canRunScenario(status(), scenario({ requiresDemoIdentities: true })).allowed, false);
    assert.equal(canRunScenario(null, scenario()).allowed, false);
  });

  it('computes run duration from persisted timestamps', () => {
    assert.equal(runDurationSeconds({ startedAt: '2026-01-01T00:00:00.000Z', finishedAt: '2026-01-01T00:01:15.000Z' }), 75);
  });
});
