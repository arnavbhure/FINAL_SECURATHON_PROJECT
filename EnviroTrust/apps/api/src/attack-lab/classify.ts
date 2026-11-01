import type { HttpExchange, MlEvidence, RunOutcome } from './types.js';

export interface RejectionAssessment {
  outcome: RunOutcome;
  expectationMet: boolean;
  reason: string;
}

/**
 * Classifies an attack that both services are expected to reject with a specific reason code.
 * A rejection only counts as PREVENTED when it came from the mechanism under test and no trusted
 * record exists; any other rejection is INCONCLUSIVE, any acceptance is ACCEPTED.
 */
export function classifyRejection(input: {
  expectedCode: string;
  primary: HttpExchange;
  witness: HttpExchange;
  primaryTrustedRecords: number;
  witnessTrustedRecordFound: boolean;
}): RejectionAssessment {
  const { expectedCode, primary, witness } = input;

  if (primary.status === null || witness.status === null) {
    const down = [primary, witness].filter((e) => e.status === null).map((e) => e.target);
    return {
      outcome: 'SERVICE_UNAVAILABLE',
      expectationMet: false,
      reason: `${down.join(' and ')} could not be reached; no verdict on the attack`,
    };
  }

  if (primary.ok || witness.ok || input.primaryTrustedRecords > 0 || input.witnessTrustedRecordFound) {
    const accepted = [
      primary.ok || input.primaryTrustedRecords > 0 ? 'PRIMARY' : null,
      witness.ok || input.witnessTrustedRecordFound ? 'WITNESS' : null,
    ].filter(Boolean);
    return {
      outcome: 'ACCEPTED',
      expectationMet: false,
      reason: `Attack message was accepted by ${accepted.join(' and ')}`,
    };
  }

  if (primary.code === expectedCode && witness.code === expectedCode) {
    return {
      outcome: 'PREVENTED',
      expectationMet: true,
      reason: `Both services rejected with ${expectedCode} and stored no trusted record`,
    };
  }

  return {
    outcome: 'INCONCLUSIVE',
    expectationMet: false,
    reason: `Rejected, but not by the mechanism under test (expected ${expectedCode}; primary=${primary.code ?? primary.status}, witness=${witness.code ?? witness.status})`,
  };
}

/**
 * Outcome for the compromised-key scenario: cryptography is expected to accept the reading;
 * the verdict depends only on what the genuine anomaly model actually returned.
 */
export function classifyCompromisedKey(input: {
  primaryAccepted: boolean;
  witnessAccepted: boolean;
  ml: MlEvidence;
  /** The same model's verdicts on genuine readings from the same site and time window. */
  control?: { evaluated: number; flagged: number };
}): RejectionAssessment & { classification: string } {
  if (!input.primaryAccepted || !input.witnessAccepted) {
    return {
      outcome: 'INCONCLUSIVE',
      expectationMet: false,
      classification: 'COMPROMISED_KEY_NOT_EXERCISED',
      reason: 'The legitimately signed reading was not accepted by both services, so the ML layer was not exercised',
    };
  }
  switch (input.ml.status) {
    case 'SUSPICIOUS':
      // A flag only counts as detection if the model does not flag genuine readings the same way.
      if (input.control && input.control.evaluated >= 5 && input.control.flagged / input.control.evaluated >= 0.5) {
        return {
          outcome: 'INCONCLUSIVE',
          expectationMet: true,
          classification: 'ML_FLAG_NOT_SPECIFIC',
          reason: `The model flagged the manipulated reading SUSPICIOUS, but it also flagged ${input.control.flagged} of ${input.control.evaluated} genuine readings in the same window, so the flag does not single out the manipulation`,
        };
      }
      return {
        outcome: 'SUSPICIOUS',
        expectationMet: true,
        classification: 'COMPROMISED_KEY_FLAGGED_BY_ML',
        reason: 'Signatures verified (as expected for a stolen key); the Isolation Forest flagged the reading SUSPICIOUS',
      };
    case 'CONSISTENT':
      return {
        outcome: 'ACCEPTED',
        expectationMet: true,
        classification: 'COMPROMISED_KEY_NOT_DETECTED',
        reason: 'Signatures verified and the Isolation Forest classified the manipulated value as CONSISTENT — not detected',
      };
    case 'NOT_EVALUATED':
      return {
        outcome: 'INCONCLUSIVE',
        expectationMet: false,
        classification: 'ML_NOT_EVALUATED',
        reason: input.ml.detail,
      };
    default:
      return {
        outcome: 'PENDING',
        expectationMet: false,
        classification: input.ml.status,
        reason: input.ml.detail,
      };
  }
}

export function summaryFor(outcome: RunOutcome, kind: 'attack' | 'operational' | 'evidence'): string {
  switch (outcome) {
    case 'PREVENTED':
      return 'Attack prevented';
    case 'DETECTED':
      return kind === 'operational'
        ? 'Operational alert generated'
        : kind === 'evidence'
          ? 'Threat detected — evidence verified'
          : 'Threat detected';
    case 'SUSPICIOUS':
      return 'Threat detected — flagged SUSPICIOUS (not proof of fraud)';
    case 'ACCEPTED':
      return 'Attack accepted — not detected';
    case 'PENDING':
      return 'Result pending';
    case 'SERVICE_UNAVAILABLE':
      return 'Service unavailable — no verdict';
    default:
      return 'Inconclusive — expected response not confirmed';
  }
}
