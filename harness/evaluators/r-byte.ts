// M2.4.4 -- R_byte evaluator. Pure function: EvaluationInput -> ObservationState.
// Source: Paper_4_Experimental_Harness v0.21, §5.12.
// No mutationId branching anywhere in this file.

import type { ObservationState } from '../evidence/execution-status.js';
import type { ExecutionStatus } from '../evidence/execution-status.js';

export interface ComparableByteOutput {
  readonly kind: 'raw-output' | 'contract-artifact' | 'canonical-serialization';
  readonly bytes: string; // hex-encoded, opaque
}

export interface ByteEqualityEvaluationInput {
  readonly applicable: boolean;
  readonly inputsEquivalent: boolean; // resolved upstream, not decided here
  readonly left: { readonly executionStatus: ExecutionStatus; readonly comparableOutput?: ComparableByteOutput };
  readonly right: { readonly executionStatus: ExecutionStatus; readonly comparableOutput?: ComparableByteOutput };
}

// Bytes(y_p) = Bytes(y_q) <=> |y_p|=|y_q| AND forall j, y_p[j]=y_q[j].
// No parse-and-reserialize, no leading-zero stripping, no DER canonicalization,
// no field reordering, no semantic-equivalence conversion -- literal string
// equality on the already-supplied byte representation only.
function bytesEqual(a: string, b: string): boolean {
  return a === b;
}

// Comparable_byte(e_p, e_q): all six frozen preconditions collapse here to
// what this evaluator can actually see -- applicability, both executions
// completed, and both having a comparable object at all. InputsEquivalent
// and "same baseline/stimulus" are resolved upstream (planner's job), but
// this evaluator still enforces its OWN normative preconditions rather than
// blindly trusting the caller.
export function evaluateByte(input: ByteEqualityEvaluationInput): ObservationState {
  if (!input.applicable) return 'n/a';

  const comparable =
    input.inputsEquivalent &&
    input.left.executionStatus === 'completed' &&
    input.right.executionStatus === 'completed' &&
    input.left.comparableOutput !== undefined &&
    input.right.comparableOutput !== undefined;

  if (!comparable) return 'insufficient-evidence'; // NEVER 'divergent'

  const equal = bytesEqual(input.left.comparableOutput!.bytes, input.right.comparableOutput!.bytes);
  return equal ? 'conformant' : 'divergent';
}
