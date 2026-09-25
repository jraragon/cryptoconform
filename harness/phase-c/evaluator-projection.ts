// Bloque C3 -- the projection layer.
//
//     PlanEntry -> Execution -> Evidence -> Projection_R -> Evaluator_R -> RelationObservation
//
// The last stretch of the pipeline, and the one that turns experimental
// evidence into an evaluator's exact input. Its responsibility is bounded by
// one rule, and everything below follows from it:
//
//     the projector INTERPRETS EXPERIMENTAL EVIDENCE;
//     it does not DECIDE NORMATIVE TRUTH.
//
// So it may read an ExecutionStatus, an executionId, observed bytes, an
// import result, a declaration or the presence of material -- all facts about
// what happened. It may NOT consult the contract to decide what SHOULD have
// happened: that was settled in C1, is pre-registered, and arrives here as a
// parameter. A projector that re-derived an expectation during execution
// would let the run decide what it was supposed to find.
//
// Structurally enforced: this module imports nothing from src/contract, and
// the gate greps for it.

import type { ExecutionEvidence } from '../evidence/execution-evidence.js';
import type { ExecutionStatus } from '../evidence/execution-status.js';
import type { ByteEqualityEvaluationInput, ComparableByteOutput } from '../evaluators/r-byte.js';
import type { InteropEvaluationInput, InteropExpectedOutcome, InteropOutcomeProjection } from '../evaluators/r-interop.js';
import type { SerializationChecksRequired, SerializationEvaluationInput } from '../evaluators/r-ser.js';
import type { ValidationDecision, ValidationEvaluationInput } from '../evaluators/r-val.js';
import type { ErrorEvaluationInput } from '../evaluators/r-err.js';
import type { CapabilityEvaluationInput } from '../evaluators/r-cap.js';
import type { ObservedCapabilityState } from '../schema/capability.js';
import type { SerializationObservationBasis } from './ground-truth/schema.js';
import type { TransferRecord } from '../orchestration/interop-transfer.js';

export class ProjectionError extends Error {}

function requireOutputBytes(e: ExecutionEvidence, what: string): string | undefined {
  const bytes = e.output?.bytes;
  if (bytes === undefined) return undefined;
  if (typeof bytes !== 'string') throw new ProjectionError(`${what}: output bytes must be an opaque string.`);
  return bytes;
}

// ---------------------------------------------------------------------
// R_byte -- cross-backend, never baseline-vs-mutated
//
// M3-H8's correction preserved in the projector's own SHAPE rather than in a
// comment: this function takes TWO executions of DIFFERENT backends, and
// there is no parameter through which a baseline could enter. Phase A's
// single-backend baseline comparison is a different scope kind and has no
// route into this projection.
// ---------------------------------------------------------------------

export function projectByte(params: {
  readonly left: ExecutionEvidence;
  readonly right: ExecutionEvidence;
  readonly outputKind: ComparableByteOutput['kind'];
}): ByteEqualityEvaluationInput {
  if (params.left.subject.backend.family === params.right.subject.backend.family) {
    throw new ProjectionError(
      'R_byte in Phase C is a CROSS-BACKEND comparison. Two executions of the same backend cannot form one, ' +
      'and a baseline-vs-mutated pair is Phase A\'s own single-backend scope (M3-H8).',
    );
  }
  const project = (e: ExecutionEvidence) => {
    const bytes = requireOutputBytes(e, 'R_byte');
    return {
      executionStatus: e.executionStatus,
      ...(bytes === undefined ? {} : { comparableOutput: { kind: params.outputKind, bytes } }),
    };
  };
  return {
    applicable: true,
    // Both sides received the SAME mutated stimulus, which is what makes the
    // frozen inputsEquivalent precondition true here -- and what made it
    // false under the pre-H8 reading, where the mutation was one side of the
    // comparison rather than the common stimulus.
    inputsEquivalent: true,
    left: project(params.left),
    right: project(params.right),
  };
}

// ---------------------------------------------------------------------
// R_interop -- consumes the real A -> B transfer
//
// Takes a TransferRecord, not two executions. Two independent executions
// cannot be assembled into an interoperability observation after the fact,
// and accepting them here would reintroduce exactly the inference the
// transfer capability was built to replace.
// ---------------------------------------------------------------------

export function projectInterop(params: {
  readonly transfer: TransferRecord;
  readonly expectedOutcome: InteropExpectedOutcome; // from C1, never derived here
  readonly observedOutcome?: InteropOutcomeProjection;
}): InteropEvaluationInput {
  const { transfer } = params;
  if (transfer.producerExecution.executionId === transfer.consumerExecution.executionId) {
    throw new ProjectionError('The producer and consumer of a transfer must be distinct executions.');
  }
  return {
    applicable: true,
    // ProducerValid is the producer's own PROCESS validity, never whether the
    // transferred artifact is pristine: a tamper stimulus has a perfectly
    // valid producer and still transfers a deliberately mutated artifact.
    producerValid: transfer.producerExecution.executionStatus === 'completed',
    producerExecutionStatus: transfer.producerExecution.executionStatus,
    consumerExecutionStatus: transfer.consumerExecution.executionStatus,
    // True by construction here, and only here: the consumer consumed the
    // producer's own artifact, verified by transferHash inside runTransfer.
    sameBaselineOrStimulus: transfer.consumedHash === transfer.artifact.transferHash,
    expectedOutcome: params.expectedOutcome,
    ...(params.observedOutcome === undefined ? {} : { observedOutcome: params.observedOutcome }),
  };
}

// ---------------------------------------------------------------------
// R_ser -- checksRequired governs WHICH checks, never their RESULT
//
// The three booleans are where a convenient value would be easiest to
// invent, so each has an identified source and none has a default:
//
//   checksRequired  from C1's pre-registered basis. Translated, not decided.
//   repOK/materialOK  supplied by the caller from an OBSERVED structural
//                   comparison. Passing `undefined` means the check could
//                   not be performed, and the evaluator turns that into
//                   insufficient-evidence -- never into a divergence and
//                   never into a pass.
//   comparable      Comparable_ser's own preconditions. A required check
//                   whose result is unavailable makes the observation
//                   NON-COMPARABLE by construction, so an absent value can
//                   never be silently read as a satisfied check.
// ---------------------------------------------------------------------

export function toChecksRequired(basis: SerializationObservationBasis): SerializationChecksRequired {
  switch (basis) {
    case 'representation-conformance': return { representationConformance: true, materialPreservation: false };
    case 'material-preservation': return { representationConformance: false, materialPreservation: true };
    case 'both': return { representationConformance: true, materialPreservation: true };
  }
}

export function projectSer(params: {
  readonly basis: SerializationObservationBasis; // from C1
  readonly execution: ExecutionEvidence;
  readonly repOK?: boolean;
  readonly materialOK?: boolean;
}): SerializationEvaluationInput {
  const checksRequired = toChecksRequired(params.basis);
  return {
    applicable: true,
    // Comparability establishes that the execution itself is usable evidence.
    // Availability of individual serialization checks is handled by evaluateSer:
    // an observed false on either REQUIRED check establishes divergence, while
    // genuinely missing required evidence remains insufficient-evidence.
    comparable: params.execution.executionStatus === 'completed',
    checksRequired,
    ...(params.repOK === undefined ? {} : { repOK: params.repOK }),
    ...(params.materialOK === undefined ? {} : { materialOK: params.materialOK }),
  };
}

// ---------------------------------------------------------------------
// R_val and R_err -- the expectation comes from C1, the projector supplies
// only what actually happened.
// ---------------------------------------------------------------------

export function projectVal(params: {
  readonly expected: ValidationDecision; // from C1
  readonly execution: ExecutionEvidence;
  readonly observed?: ValidationDecision;
}): ValidationEvaluationInput {
  return {
    applicable: true,
    // A contractual rejection is NOT an execution failure: the run completed
    // and produced a decision. Conflating them would turn every expected
    // reject into a harness error.
    executionStatus: params.execution.executionStatus,
    expected: params.expected,
    ...(params.observed === undefined ? {} : { observed: params.observed }),
  };
}

export function projectErr(params: {
  readonly execution: ExecutionEvidence;
  readonly rejectionOccurred: boolean;
  readonly expectedErrorClass?: string; // from C1; absent means no error expected
  readonly observedErrorClass?: string;
}): ErrorEvaluationInput {
  return {
    applicable: true,
    executionStatus: params.execution.executionStatus,
    // A rejection that never happened produces no error-class divergence: it
    // produces insufficient-evidence for R_err, while R_val independently
    // records the actual divergence.
    rejectionOccurred: params.rejectionOccurred,
    ...(params.expectedErrorClass === undefined ? {} : { expectedErrorClass: params.expectedErrorClass }),
    ...(params.observedErrorClass === undefined ? {} : { observedErrorClass: params.observedErrorClass }),
  };
}

// ---------------------------------------------------------------------
// R_cap -- evidence independence, enforced on the path, not just in the API
//
// id(E_declaration) != id(E_scored) is refused HERE as well as in the
// evaluator. The orchestrator already provides runDeclarationProbe precisely
// so a declaration is never served from the baseline cache; this makes the
// same requirement unsatisfiable by accident rather than merely discouraged.
// ---------------------------------------------------------------------

export function projectCap(params: {
  readonly declared: ObservedCapabilityState;
  readonly declarationExecution: ExecutionEvidence;
  readonly scoredExecution: ExecutionEvidence;
  readonly observed?: ObservedCapabilityState;
}): CapabilityEvaluationInput {
  if (params.declarationExecution.executionId === params.scoredExecution.executionId) {
    throw new ProjectionError(
      'R_cap requires Evidence_declaration and Evidence_scored to be DISJOINT. One execution serving both roles ' +
      'would let a declaration confirm itself.',
    );
  }
  return {
    applicable: true,
    declared: params.declared,
    probeStatus: params.scoredExecution.executionStatus,
    declarationExecutionId: params.declarationExecution.executionId,
    scoredExecutionId: params.scoredExecution.executionId,
    ...(params.observed === undefined ? {} : { observed: params.observed }),
  };
}

/** An inapplicable relation never reaches a projector: it is n/a upstream. */
export function assertApplicable(relation: string, applicable: boolean): void {
  if (!applicable) {
    throw new ProjectionError(
      `${relation} is not applicable here; n/a is decided by the frozen applicability rule, not by projection.`,
    );
  }
}

export type { ExecutionStatus };
