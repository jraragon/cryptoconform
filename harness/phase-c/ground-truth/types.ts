// Bloque C1 -- ground-truth row types and the M3 normative rules.
//
// The frozen H9.2a schema (schema.ts) fixes the DOMAIN of each premise and
// the provenance union. This module fixes the wire shape of a table row and
// states, once, the rules that produce the values the contract does not
// determine. The taxonomy is not widened: every row resolves to exactly one
// of the two frozen provenance kinds.

import type { SdkErrorClass } from '../../../src/contract/errors.js';
import type { ClauseId } from '../../../src/contract/clause-ids.js';
import type { SerializationObservationBasis, ValidationDecisionGT } from './schema.js';

export type GroundTruthRuleId =
  | 'GT-VAL-ACCEPT-ANCHOR'
  | 'GT-ERR-ACCEPT'
  | 'GT-ERR-VERIFY'
  | 'GT-ERR-DECLARATIVE'
  | 'GT-SER-BOTH'
  | 'GT-SER-DECLARATIVE'
  | 'GT-INTEROP-ROUNDTRIP';

export interface GroundTruthRow {
  readonly expectedValidation?: {
    readonly decision: ValidationDecisionGT;
    readonly clauseIds: readonly ClauseId[];
  };
  readonly errorExpectation?:
    | { readonly kind: 'error-expected'; readonly errorClass: SdkErrorClass; readonly clauseIds: readonly ClauseId[] }
    | { readonly kind: 'no-error-expected'; readonly ruleId: GroundTruthRuleId };
  readonly checksRequired?: {
    readonly basis: SerializationObservationBasis;
    readonly ruleId: GroundTruthRuleId;
  };
  readonly expectedOutcome?:
    | { readonly kind: 'reject'; readonly clauseIds: readonly ClauseId[] }
    | { readonly kind: 'normal'; readonly ruleId: GroundTruthRuleId };
}

/**
 * The M3 normative rules, stated once.
 *
 * Each is a decision the frozen design did not make, recorded as one. A row
 * citing a ruleId resolves to provenance 'm3-normative-decision' with this
 * rationale; a row citing clauseIds resolves to 'contract-derived'. Nothing
 * resolves to both, and nothing resolves to neither.
 */
export const GROUND_TRUTH_RULES: Readonly<Record<GroundTruthRuleId, { readonly rationale: string; readonly decidedIn: string }>> =
  Object.freeze({
    'GT-VAL-ACCEPT-ANCHOR': {
      rationale:
        'For a mutated input the contract ACCEPTS, no individual clause fires, so no clause can be cited as having ' +
        'produced the value. The anchor is instead the clause that DEFINES the acceptance boundary for the operation ' +
        '-- gcm.validation states that "inputs/parameter combinations outside the portable domain are accepted/rejected ' +
        'according to the contract", and its siblings say the same for their operations. For the two serialization ' +
        'operations, which have no single validation clause, the anchor is the clause set the importer evaluates. This ' +
        'is contract-derived: the cited clauses are exactly what was evaluated, and acceptance is their verdict.',
      decidedIn: 'Bloque C1',
    },
    'GT-ERR-ACCEPT': {
      rationale:
        'The contract accepts the mutated input, so no rejection is expected and no error class can be. Stated rather ' +
        'than inferred from an absent field, per the frozen ErrorExpectation union. NoReject does not imply ' +
        'R_err = fail: an expected rejection that fails to materialise is R_val\'s divergence, and R_err records ' +
        'insufficient-evidence.',
      decidedIn: 'Bloque C1',
    },
    'GT-ERR-VERIFY': {
      rationale:
        'PSS verification returns a boolean; verified(false) for a genuinely invalid signature is the contractually ' +
        'CORRECT outcome, not an error. Comparable_err condition 4 guards exactly this trap, so these classes expect ' +
        'no error class at all.',
      decidedIn: 'Bloque C1',
    },
    'GT-ERR-DECLARATIVE': {
      rationale:
        'A capability-declaration fixture {capabilityId, kind, support} and an error-mapping fixture ' +
        '{triggeringCondition, declaredErrorClass} carry no operational input, so no contractual rejection can occur ' +
        'during their evaluation. Their own object of observation is R_cap and R_err\'s mapping respectively, not a ' +
        'rejection produced by processing them.',
      decidedIn: 'Bloque C1',
    },
    'GT-SER-BOTH': {
      rationale:
        'The frozen design leaves the basis to the plan ("when both are required BY THE PLAN"). The plan requires ' +
        'BOTH by default, because omitting a check can only make R_ser more likely to report conformant, and that is ' +
        'the direction that fabricates a pass. Requiring both is therefore the conservative choice: where the material ' +
        'needed for preservation is unavailable, Comparable_ser fails and the observation is insufficient-evidence, ' +
        'never a divergence invented from a missing check.',
      decidedIn: 'Bloque C1',
    },
    'GT-SER-DECLARATIVE': {
      rationale:
        'A capability or error-mapping fixture serializes no material, so material-preservation has nothing to ' +
        'preserve and would render every such observation non-comparable. Representation-conformance alone is the ' +
        'only basis with an object. This is the sole exception to GT-SER-BOTH and is structural, not discretionary.',
      decidedIn: 'Bloque C1',
    },
    'GT-INTEROP-ROUNDTRIP': {
      rationale:
        'Where the contract accepts the mutated flow, the operation\'s own round-trip obligation applies unchanged ' +
        '(Dec_q(Enc_p(m)) = m; Verify_q(m, Sign_p(m)) = true; Import_q(Export_p(K)) === K), so the expected outcome is ' +
        'the normal one. The frozen design admits this reasoning for 11 producer-side pairs; applying it to all 24 ' +
        'accepted eligible pairs -- including consumer-side and adapter-interface cases -- is BROADER than what the ' +
        'design states, and is therefore recorded as an M3 decision rather than as contract-derived. Acceptance is ' +
        'structural and does not by itself imply a normal outcome, which is why the five cryptographic classes are ' +
        'excluded from this rule and carry gcm.authentication instead.',
      decidedIn: 'Bloque C1',
    },
  });
