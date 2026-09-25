// M2.4.4 -- R_interop evaluator. Pure function: EvaluationInput -> ObservationState.
// Source: Paper_4_Experimental_Harness v0.21, §5.13.
// No mutationId branching anywhere in this file.

import type { ObservationState } from '../evidence/execution-status.js';
import type { ExecutionStatus } from '../evidence/execution-status.js';

export type InteropExpectedOutcome =
  | { readonly kind: 'recover-bytes'; readonly expected: string }
  | { readonly kind: 'verify'; readonly expected: boolean }
  | { readonly kind: 'import-material'; readonly expected: string }
  | { readonly kind: 'authenticated-decrypt'; readonly expected: string }
  | { readonly kind: 'reject'; readonly expectedErrorClass?: string };

export interface InteropOutcomeProjection {
  readonly kind: 'recovered-plaintext' | 'verification-result' | 'imported-key-material' | 'authenticated-plaintext' | 'rejection';
  readonly value: unknown;
  readonly errorClass?: string;
}

export interface InteropEvaluationInput {
  readonly applicable: boolean;
  // ProducerValid(p): the PRODUCER's own process validity, never whether the
  // transferred artifact is pristine -- a tamper stimulus can have a fully
  // valid producer and still transfer a deliberately mutated artifact.
  readonly producerValid: boolean;
  readonly producerExecutionStatus: ExecutionStatus;
  readonly consumerExecutionStatus: ExecutionStatus;
  readonly sameBaselineOrStimulus: boolean;
  readonly expectedOutcome: InteropExpectedOutcome;
  readonly observedOutcome?: InteropOutcomeProjection;
}

function outcomesMatch(expected: InteropExpectedOutcome, observed: InteropOutcomeProjection): boolean {
  switch (expected.kind) {
    case 'recover-bytes':
      return observed.kind === 'recovered-plaintext' && observed.value === expected.expected;
    case 'verify':
      return observed.kind === 'verification-result' && observed.value === expected.expected;
    case 'import-material':
      return observed.kind === 'imported-key-material' && observed.value === expected.expected;
    case 'authenticated-decrypt':
      return observed.kind === 'authenticated-plaintext' && observed.value === expected.expected;
    case 'reject':
      return observed.kind === 'rejection' && (expected.expectedErrorClass === undefined || observed.errorClass === expected.expectedErrorClass);
  }
}

// ProducerFailure does NOT imply fail; ConsumerReject does NOT imply fail
// automatically -- the evaluator always compares against expectedOutcome,
// never against a fixed accept/reject default.
export function evaluateInterop(input: InteropEvaluationInput): ObservationState {
  if (!input.applicable) return 'n/a';

  const comparable =
    input.producerValid &&
    input.producerExecutionStatus === 'completed' &&
    input.consumerExecutionStatus === 'completed' &&
    input.sameBaselineOrStimulus &&
    input.observedOutcome !== undefined;

  if (!comparable) return 'insufficient-evidence'; // NEVER 'divergent'

  return outcomesMatch(input.expectedOutcome, input.observedOutcome!) ? 'conformant' : 'divergent';
}
