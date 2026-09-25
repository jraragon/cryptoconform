// M2.4.4 -- R_val evaluator. Pure function: EvaluationInput -> ObservationState.
// Source: Paper_4_Experimental_Harness v0.21, §5.15.
// No mutationId branching anywhere in this file.

import type { ObservationState } from '../evidence/execution-status.js';
import type { ExecutionStatus } from '../evidence/execution-status.js';

export type ValidationDecision =
  | { readonly kind: 'accept' }
  | { readonly kind: 'accept-normalized'; readonly normalizedForm?: string }
  | { readonly kind: 'reject' }
  | { readonly kind: 'verified'; readonly value: boolean };

export interface ValidationEvaluationInput {
  readonly applicable: boolean;
  readonly executionStatus: ExecutionStatus; // a contractual reject is NOT an execution failure
  readonly expected: ValidationDecision;
  readonly observed?: ValidationDecision;
}

// Decision equality is semantic and typed, never a bare kind===kind:
// accept-normalized with a specified form must match that form, not merely
// "also happened to normalize something."
function decisionsEqual(expected: ValidationDecision, observed: ValidationDecision): boolean {
  if (expected.kind !== observed.kind) return false;
  if (expected.kind === 'accept-normalized' && observed.kind === 'accept-normalized') {
    if (expected.normalizedForm !== undefined) return expected.normalizedForm === observed.normalizedForm;
    return true;
  }
  if (expected.kind === 'verified' && observed.kind === 'verified') {
    return expected.value === observed.value;
  }
  return true; // accept/accept, reject/reject
}

// Reject does not mean fail; accept does not mean pass. verified(false) can
// be fully conformant. executionStatus='completed' must coexist with a
// reject outcome -- only harness-error/environment-error/timeout are
// infrastructure failures, never validation decisions.
export function evaluateVal(input: ValidationEvaluationInput): ObservationState {
  if (!input.applicable) return 'n/a';

  const comparable = input.executionStatus === 'completed' && input.observed !== undefined;
  if (!comparable) return 'insufficient-evidence'; // NEVER 'divergent'

  return decisionsEqual(input.expected, input.observed!) ? 'conformant' : 'divergent';
}
