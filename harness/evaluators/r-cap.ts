// M2.4.4 -- R_cap evaluator. Pure function: EvaluationInput -> ObservationState.
// Source: Paper_4_Experimental_Harness v0.21, §5.17.
// No mutationId branching anywhere in this file. Does NOT read manifests
// itself -- `declared` arrives already resolved by the planner (M2.4.5);
// CapabilityClaim -> DeclarationSource -> Manifest/Profile resolution is not
// this evaluator's job.

import type { ObservationState } from '../evidence/execution-status.js';
import type { ExecutionStatus } from '../evidence/execution-status.js';
import type { ObservedCapabilityState } from '../schema/capability.js';

export class CapabilityIndependenceViolation extends Error {}

export interface CapabilityEvaluationInput {
  readonly applicable: boolean;
  readonly declared: ObservedCapabilityState; // already-resolved declaration value
  readonly observed?: ObservedCapabilityState;
  readonly probeStatus: ExecutionStatus;
  // Evidence_declaration(kappa,p) ∩ Evidence_scored(kappa,p) = ∅, checked on
  // concrete execution identity -- same operation type is fine; the SAME
  // ExecutionID serving both roles is not.
  readonly declarationExecutionId: string;
  readonly scoredExecutionId: string;
}

function statesEqual(a: ObservedCapabilityState, b: ObservedCapabilityState): boolean {
  if (a.kind !== b.kind) return false;
  return a.state === b.state;
}

export function evaluateCap(input: CapabilityEvaluationInput): ObservationState {
  // Independence check happens FIRST, before any observation is produced --
  // a tautological R_cap must never even reach a comparison.
  if (input.declarationExecutionId === input.scoredExecutionId) {
    throw new CapabilityIndependenceViolation(
      `declarationExecutionId and scoredExecutionId are identical (${input.declarationExecutionId}) -- ` +
      'this would make R_cap tautological by construction.',
    );
  }

  if (!input.applicable) return 'n/a';

  // ProbeFailure does NOT imply CapabilityUnsupported: harness/environment
  // errors or timeouts resolve to insufficient-evidence, never to
  // observed='unsupported' and never to R_cap='fail'.
  const comparable = input.probeStatus === 'completed' && input.observed !== undefined;
  if (!comparable) return 'insufficient-evidence';

  return statesEqual(input.declared, input.observed!) ? 'conformant' : 'divergent';
}
