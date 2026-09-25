// M2.4.3 -- evidence core. Represent/validate only, no evaluator logic.
// Source: Paper_4_Experimental_Harness v0.21, §5.6.

import type { ObservationContext } from './execution-context.js';
import type { ObservationScope } from './observation-scope.js';
import type { NonExecution } from './execution-status.js';
import type { RelationId } from '../schema/registry-types.js';

export type RelationObservationStatus = 'pass' | 'fail' | 'n/a' | NonExecution | 'insufficient-evidence';

export interface RelationObservation {
  readonly observationId: string;
  readonly context: ObservationContext;
  readonly relation: RelationId;
  readonly scope: ObservationScope;
  readonly status: RelationObservationStatus;
  readonly participants: readonly string[]; // ExecutionEvidence.executionId refs
  /**
   * M3.8.2 (I5') -- for R_cap only: the identity of the DECLARED side, which
   * is not an M4 execution and therefore not a participant.
   *
   * M2.3.3b-II grounds the manifest cells in M1 evidence ("v0.13 SS15,
   * HKDF x WebCrypto closed"), so the declaration has an identity but no
   * ExecutionEvidence in this bundle. Recording it here keeps the two sides
   * traceable without pretending the declaration was executed now.
   */
  readonly declarationBasisRef?: string;
  readonly evaluatorId: string;
  readonly basis: string;
}

let observationCounter = 0;
function nextObservationId(): string {
  observationCounter += 1;
  return `obs-${observationCounter}`;
}

export class IllegalObservationStateError extends Error {}

// Enforces n/a <=> Applicability(R_i,o)=0 (§5.2, §9): callers cannot
// silently construct a status='n/a' observation for an applicable relation,
// nor a pass/fail observation for an inapplicable one.
/**
 * M3.3 -- the plan -> evidence bridge for NonExecution.
 *
 * Designed since M3-H9.3a-3.1, which reused the frozen NonExecution.reason
 * vocabulary verbatim "so a planned non-execution maps onto its evidence
 * counterpart without translation" -- and then never built the producer. A
 * grep of the whole tree found no code in Phase C constructing one: the
 * orchestrator skipped non-executable entries silently, so the fact lived
 * only in coverage.planned and never appeared as an observation.
 *
 * The vocabulary is REUSED, not re-decided: the reason comes from the plan's
 * own PlannedExecutability, so the evidence materialises the pre-registered
 * decision instead of inventing one at run time.
 *
 * This produces a RelationObservation whose status is NOT terminal, so it
 * cannot cross into a RelationSpectrum cell -- toRelationValue returns
 * undefined for 'not-executed' and always has.
 */
export function makeNonExecutionObservation(params: {
  readonly relation: RelationObservation['relation'];
  readonly scope: RelationObservation['scope'];
  readonly context: RelationObservation['context'];
  readonly reason: NonExecution['reason'];
  readonly evaluatorId: string;
}): RelationObservation {
  return makeRelationObservation({
    applicable: true,
    relation: params.relation,
    scope: params.scope,
    context: params.context,
    status: { state: 'not-executed', reason: params.reason },
    participants: [],
    evaluatorId: params.evaluatorId,
    basis: `planned non-execution: ${params.reason}`,
  });
}

export function makeRelationObservation(params: {
  readonly applicable: boolean;
  readonly context: ObservationContext;
  readonly relation: RelationId;
  readonly scope: ObservationScope;
  readonly status: Exclude<RelationObservationStatus, 'n/a'>;
  readonly participants: readonly string[];
  /** R_cap only: the identity of the declared side, which is not executed. */
  readonly declarationBasisRef?: string;
  readonly evaluatorId: string;
  readonly basis: string;
}): RelationObservation {
  if (!params.applicable) {
    // The only legal status for an inapplicable relation is 'n/a' -- the
    // caller passed something else, which is illegal by the frozen rule.
    throw new IllegalObservationStateError(
      `Relation ${params.relation} is not applicable to this operation; the only legal status is 'n/a', not ${JSON.stringify(params.status)}.`,
    );
  }
  if (params.applicable && (params.status as unknown) === 'n/a') {
    throw new IllegalObservationStateError(
      `Relation ${params.relation} IS applicable; 'n/a' may not be used for an applicable relation.`,
    );
  }
  return {
    observationId: nextObservationId(),
    context: params.context,
    relation: params.relation,
    scope: params.scope,
    status: params.status,
    participants: params.participants,
    ...(params.declarationBasisRef === undefined ? {} : { declarationBasisRef: params.declarationBasisRef }),
    evaluatorId: params.evaluatorId,
    basis: params.basis,
  };
}

export function makeNotApplicableObservation(params: {
  readonly context: ObservationContext;
  readonly relation: RelationId;
  readonly scope: ObservationScope;
  readonly evaluatorId: string;
  readonly basis: string;
}): RelationObservation {
  return {
    observationId: nextObservationId(),
    context: params.context,
    relation: params.relation,
    scope: params.scope,
    status: 'n/a',
    participants: [],
    evaluatorId: params.evaluatorId,
    basis: params.basis,
  };
}
