// M2.4.4 -- R_err evaluator. Pure function: EvaluationInput -> ObservationState.
// Source: Paper_4_Experimental_Harness v0.21, §5.16.
// No mutationId branching anywhere in this file.

import type { ObservationState } from '../evidence/execution-status.js';
import type { ExecutionStatus } from '../evidence/execution-status.js';

export interface ErrorEvaluationInput {
  readonly applicable: boolean;
  readonly executionStatus: ExecutionStatus;
  // Whether the SDK actually produced a classifiable rejection at all. If a
  // rejection was expected but the input was instead wrongly accepted, this
  // is false -- that is R_val's own divergence, never R_err's.
  readonly rejectionOccurred: boolean;
  readonly expectedErrorClass?: string;
  readonly observedErrorClass?: string; // from the SDK layer ONLY, never nativeObservation
}

// A rejection that never happened produces no error-class divergence -- it
// produces insufficient-evidence for R_err, while R_val independently and
// correctly records the actual divergence elsewhere.
export function evaluateErr(input: ErrorEvaluationInput): ObservationState {
  if (!input.applicable) return 'n/a';

  const comparable =
    input.executionStatus === 'completed' &&
    input.rejectionOccurred &&
    input.expectedErrorClass !== undefined &&
    input.observedErrorClass !== undefined;

  if (!comparable) return 'insufficient-evidence'; // NEVER 'divergent'

  // Exact class equality only -- no substring matching, no native exception
  // substitution. The caller is responsible for never populating
  // observedErrorClass from a native exception type/message.
  return input.expectedErrorClass === input.observedErrorClass ? 'conformant' : 'divergent';
}
