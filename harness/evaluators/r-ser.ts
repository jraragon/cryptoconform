// M2.4.4 -- R_ser evaluator. Pure function: EvaluationInput -> ObservationState.
// Source: Paper_4_Experimental_Harness v0.21, §5.14.
// No mutationId branching anywhere in this file.

import type { ObservationState } from '../evidence/execution-status.js';

export interface SerializationChecksRequired {
  readonly representationConformance: boolean;
  readonly materialPreservation: boolean;
}

export interface SerializationEvaluationInput {
  readonly applicable: boolean;
  readonly comparable: boolean; // Comparable_ser preconditions, resolved upstream+here
  readonly checksRequired: SerializationChecksRequired;
  readonly repOK?: boolean; // RepOK(a, C_o) -- purely structural/canonical
  readonly materialOK?: boolean; // Material(a) === Material_expected -- semantic
}

// R_ser = conformant <=> RepOK AND MaterialOK (for whichever checks the plan
// requires); R_ser = divergent <=> NOT RepOK OR NOT MaterialOK. Two internal
// detection paths, one relation -- never split into R_rep/R_material.
export function evaluateSer(input: SerializationEvaluationInput): ObservationState {
  if (!input.applicable) return 'n/a';
  if (!input.comparable) return 'insufficient-evidence'; // NEVER 'divergent'

  const repNeeded = input.checksRequired.representationConformance;
  const materialNeeded = input.checksRequired.materialPreservation;

  // A directly observed failure of either REQUIRED check is already
  // sufficient to establish divergence. Missing evidence for the other
  // check must not erase that observed failure.
  if ((repNeeded && input.repOK === false) ||
      (materialNeeded && input.materialOK === false)) {
    return 'divergent';
  }

  // Only after ruling out an observed failure does unavailable evidence make
  // the relation insufficient. This preserves the frozen distinction:
  // false = observed non-conformance; undefined = check unavailable.
  if ((repNeeded && input.repOK === undefined) ||
      (materialNeeded && input.materialOK === undefined)) {
    return 'insufficient-evidence';
  }

  return 'conformant';
}
