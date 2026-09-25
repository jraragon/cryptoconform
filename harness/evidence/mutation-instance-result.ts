// M2.4.3 -- evidence core.
// Source: Paper_4_Experimental_Harness v0.21, §5.4 (planned observations,
// completeness gate), §5.5 (MutationInstanceResult).
// This computes STRUCTURAL completeness only -- the scientific fail-dominant
// aggregation across instances into r(c) is M2.4.7's own deliverable.

import type { RelationId } from '../schema/registry-types.js';
import type { ObservationScope } from './observation-scope.js';
import { scopeEquals } from './observation-scope.js';
import type { RelationObservation } from './relation-observation.js';
import type { InteropEligibility } from '../phase-c/interop-eligibility/types.js';

// M3-H9.3a-3.1 -- a planned non-execution now carries its REASON.
//
// The plan could previously say THAT an observation was not executable but
// never WHY. That was adequate while the only cause was M3-H6's own
// (a backend lacking a declared capability), but the R_interop eligibility
// audit found 27 of 81 applicable pairs that cannot materialise for a
// different reason entirely -- 17 whose mutated producer input the contract
// rejects, so no artifact is ever produced, and 10 whose fixture carries no
// operational input at all.
//
// Both are known BEFORE execution, from the contract. Leaving the reason to
// NonExecution -- which lives in the evidence layer -- would let the run
// discover something the protocol already knows, breaking
//     Planned  _|_  Observed
//
// The vocabulary is NOT new: it reuses the frozen NonExecution.reason
// verbatim, so a planned non-execution maps onto its evidence counterpart
// without translation:
//     structurally-not-executable(reason)  ->  NonExecution{reason}
// The evidence materialises the plan's decision; it does not invent one.
export type NonExecutionReason =
  | 'backend-capability-absent'
  | 'stimulus-not-expressible'
  | 'direction-not-materializable';

export type PlannedExecutability =
  | { readonly kind: 'required' }
  | { readonly kind: 'structurally-not-executable'; readonly reason: NonExecutionReason };

export function isRequired(e: PlannedExecutability): boolean {
  return e.kind === 'required';
}

export interface PlannedObservation {
  readonly relation: RelationId;
  readonly scope: ObservationScope;
  readonly executability: PlannedExecutability;
}

export interface ObservationCoverage {
  readonly planned: readonly PlannedObservation[];
  readonly reached: readonly string[]; // RelationObservation.observationId refs that reached a terminal state
  readonly outstanding: readonly PlannedObservation[]; // required, not yet terminal/valid
}

// M3-H9.3a-3.2.5c, connection 1 of 4 -- InteropEligibility reaches the
// dataset.
//
// The plan is never serialized: EvidenceBundle carries executions,
// observations, instance results and mutation results, and nothing of the
// plan except coverage.planned copied into each MutationInstanceResult. So
// although the plan HAS a (c,s) slot and the dataset HAS a (c,s) record,
// no channel joined them. This field is that channel.
//
// It sits on MutationInstanceResult itself rather than inside coverage,
// because coverage answers (c,s,R,scope) while eligibility answers (c,s).
// Putting it in coverage would re-contaminate the observation layer
// immediately after M3-H9.3a-3.2.3 demonstrated the two are independent
// dimensions.
//
// OPTIONAL, and necessarily so:
//     Applicability(o, R_interop) = 0  =>  interopEligibility absent
// HKDF's own 9 pairs carry no eligibility at all, and forcing a value
// there would answer a question the protocol never asks. Optionality also
// keeps every pre-existing M2 object valid unchanged.
//
// PLAIN JSON ONLY. exportBundle is JSON.stringify o sortKeysDeep, so a
// Uint8Array or bigint anywhere in this payload would not survive the
// round trip -- and would fail silently rather than loudly, which is
// precisely the M3-H2 failure mode. The registry is guarded against that
// shape-wise before it ever gets here.
//
// The runner COPIES this verbatim from the plan and never recomputes it:
// evidence materialises the pre-registered decision, it does not derive
// one. `value` and `source` are exactly what resolveInteropEligibility
// returned, and together with the instance's own mutationId and
// stimulusInstanceId they reconstitute the full ResolvedEligibilityEntry,
// so entryHash is recomputable from the frozen bundle alone.
export interface InstanceInteropEligibility {
  readonly value: InteropEligibility;
  readonly source: 'class-default' | 'stimulus-override';
  readonly entryHash: string;
}

export interface MutationInstanceResult {
  readonly mutationId: string;
  readonly stimulusInstanceId: string; // exactly one -- never absent, never plural
  readonly operation: string;
  readonly observations: readonly string[];
  readonly coverage: ObservationCoverage;
  readonly complete: boolean;
  readonly interopEligibility?: InstanceInteropEligibility;
  /**
   * M3-H13 -- relations with a pre-registered structural barrier, recorded so
   * aggregation reads the plan's decision instead of recomputing one, and so
   * the dataset can show WHY a cell is absent.
   */
  readonly structurallyNonComparable?: readonly PlannedObservation['relation'][];
}

// M3.2.1-R (M3-H1a) -- corrected identity: a PlannedObservation is resolved
// by (relation, scope), never by relation alone. A relation with multiple
// planned scopes (e.g. R_interop's own up-to-six directions) previously let
// ONE arbitrary real observation satisfy every planned scope's own
// completeness check via a bare `o.relation === p.relation` match --
// discarding scope entirely. Root-caused during M3.2.1's own audit,
// reproduced concretely (6 planned R_interop directions, 1 real
// observation -> falsely complete=true), before this fix.
//
// Fail-closed invariant: |Match(i,p)|=1 for every required p. Zero matches
// is the original incompleteness case (unchanged). Two-or-more matches is a
// NEW, distinct failure mode this fix makes possible to detect: it signals
// a harness-level inconsistency (the same (relation,scope) resolved twice),
// which must never be silently resolved by picking one arbitrarily -- that
// would just be the identical defect in a new disguise.
export class DuplicateObservationError extends Error {}

// A required scope resolving to insufficient-evidence/harness-error/
// environment-error/timeout forces complete=false. A scope pre-registered
// structurally-not-executable resolves to not-executed and never blocks
// completeness (§5.4's own completeness gate, restated here structurally).
/**
 * M3-H11.4-Core.3 -- an observation is REQUIRED, not merely planned.
 *
 *     Required(c,s,R,scope) = Applicable(R) & Eligible(c,s,R) & Executable(c,s,R,scope)
 *
 * Applicable is implied by the observation's presence in the plan; the
 * planner emits nothing for an inapplicable relation. Executable is the
 * scope's own PlannedExecutability. Eligible is the class/stimulus decision
 * resolved from the pre-derived registry.
 *
 * For every relation other than R_interop, Eligible is LOGICAL IDENTITY: no
 * fictitious eligibility record is invented for them, and the absence of the
 * field means "not applicable to this question", never "unknown".
 */
export function isRequiredEvidence(
  p: PlannedObservation,
  interopEligibility?: InstanceInteropEligibility,
  // M3-H13: relations with a PRE-REGISTERED structural barrier. Supplied by
  // the caller, never derived here: the gate consumes the plan's decision, it
  // does not recompute one at run time.
  structurallyNonComparable?: ReadonlySet<PlannedObservation['relation']>,
): boolean {
  if (p.executability.kind === 'structurally-not-executable') return false;
  if (p.relation === 'R_interop' && interopEligibility?.value.kind === 'non-eligible') return false;
  if (structurallyNonComparable?.has(p.relation) === true) return false;
  return true;
}

export function computeCompleteness(
  planned: readonly PlannedObservation[],
  observations: readonly RelationObservation[],
  // Optional so every pre-existing M2 caller keeps its exact behaviour: with
  // no eligibility recorded, Required reduces to Executable, which is what
  // the frozen gate already computed.
  interopEligibility?: InstanceInteropEligibility,
  structurallyNonComparable?: ReadonlySet<PlannedObservation['relation']>,
): { complete: boolean; outstanding: readonly PlannedObservation[] } {
  const outstanding: PlannedObservation[] = [];

  for (const p of planned) {
    // M3-H10, resolved here rather than by pruning the plan.
    //
    // Planned stays exactly as M2.4.5 built it -- Planned(c,R) =
    // Applicability(o,R) -- so the ledger still records that this relation
    // was meant to be observed. What changes is that completeness now
    // measures satisfaction of REALISABLE obligations, not execution of
    // everything planned. Before this, aggregation excused a non-eligible
    // R_interop while the gate still demanded evidence for the same scope,
    // and the two could not both be right about it: 124 observations across
    // 26 pairs sat outstanding forever.
    //
    //     Planned != Required
    if (!isRequiredEvidence(p, interopEligibility, structurallyNonComparable)) continue;

    const matches = observations.filter((o) => o.relation === p.relation && scopeEquals(o.scope, p.scope));
    if (matches.length > 1) {
      throw new DuplicateObservationError(
        `${matches.length} observations resolve the same required (relation=${p.relation}, scope) -- ` +
        `harness-level inconsistency, never resolved arbitrarily.`,
      );
    }

    const match = matches[0];
    const terminalValid =
      match !== undefined &&
      (match.status === 'pass' || match.status === 'fail' || match.status === 'n/a');
    // 'not-executed' (a NonExecution object) or 'insufficient-evidence' or
    // simply missing all count as non-terminal for a REQUIRED scope.
    if (!terminalValid) outstanding.push(p);
  }

  return { complete: outstanding.length === 0, outstanding };
}

export function makeMutationInstanceResult(params: {
  readonly mutationId: string;
  readonly stimulusInstanceId: string;
  readonly operation: string;
  readonly planned: readonly PlannedObservation[];
  readonly observations: readonly RelationObservation[];
  // Copied verbatim from the plan when present. This factory neither
  // resolves nor validates it: a runner that could recompute the decision
  // could disagree with the pre-registration, which is exactly what the
  // registry exists to prevent.
  readonly interopEligibility?: InstanceInteropEligibility;
  readonly structurallyNonComparable?: readonly PlannedObservation['relation'][];
}): MutationInstanceResult {
  const { complete, outstanding } = computeCompleteness(params.planned, params.observations, params.interopEligibility,
    params.structurallyNonComparable === undefined ? undefined : new Set(params.structurallyNonComparable));
  return {
    mutationId: params.mutationId,
    stimulusInstanceId: params.stimulusInstanceId,
    operation: params.operation,
    ...(params.interopEligibility !== undefined ? { interopEligibility: params.interopEligibility } : {}),
    ...(params.structurallyNonComparable !== undefined
      ? { structurallyNonComparable: [...params.structurallyNonComparable] } : {}),
    observations: params.observations.map((o) => o.observationId),
    coverage: {
      planned: params.planned,
      reached: params.observations.map((o) => o.observationId),
      outstanding,
    },
    complete,
  };
}
