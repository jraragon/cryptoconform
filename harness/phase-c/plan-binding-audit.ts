// Bloque C2 -- plan binding audit and the cardinality recount.
//
// The recount deferred since M3.2.4b-3 and repeatedly postponed on purpose:
// it could not mean anything until eligibility, Planned != Required and the
// transfer capability existed, because until then the categories overlapped
// in ways no single figure could express.
//
// The rule this module exists to enforce is that the categories are NOT
// disjoint and must never be added as if they were:
//
//     Planned            every (class, stimulus, relation, scope) in the plan
//     Required           Applicable & Eligible & Executable & StructuralComparable
//                        -- decided by isRequiredEvidence, never restated here
//     NonEligible        R_interop with EligibleSet(c,s) = {}   -- normative
//     NotExecutable      the scope cannot run on these backends -- environmental
//
// A non-eligible pair's scopes are Planned; some of them are ALSO
// NotExecutable; none of them is Required. Reporting 26 + 101 as though they
// partitioned anything would double-count exactly the observations whose
// two causes we spent M3-H10 and M3-H11 separating.

import { MUTATION_REGISTRY } from '../registry/mutations.js';
import { APPLICABILITY_MATRIX } from '../applicability/matrix.js';
import { resolveInteropEligibility } from './interop-eligibility/resolve.js';
import { structurallyNonComparableRelations } from './structural-comparability.js';
import { isRequiredEvidence } from '../evidence/mutation-instance-result.js';
import { resolveGroundTruth } from './ground-truth/resolve.js';
import { getFixtureResolver } from './fixture-index.js';
import { getMutationImplementation } from './mutation-index.js';
import type { StructuralExecutionPlan } from './plan-assembly.js';
import type { FrozenMaterialPool } from './material/pool.js';
import { ROLES_BY_OPERATION } from '../orchestration/dispatch.js';

export class PlanBindingError extends Error {}

export interface PlanRecount {
  /** Every planned observation in the assembled plan. */
  readonly planned: number;
  /**
   * Planned AND required, decided by isRequiredEvidence -- the single source
   * of truth. Never by a formula restated here.
   */
  readonly required: number;
  /**
   * Not-required, by CAUSE. These three sets OVERLAP and their sum is not the
   * size of the union: quoting the sum overstates the excluded population.
   * The pairwise overlaps are reported so no consumer has to guess.
   */
  readonly notRequiredContractuallyNonEligible: number;
  readonly notRequiredStructurallyNonComparable: number;
  readonly notRequiredNotExecutable: number;
  readonly overlapNonEligibleAndNotExecutable: number;
  readonly overlapNonComparableAndNotExecutable: number;
  readonly overlapNonEligibleAndNonComparable: number;
  /** Distinct not-required observations: the union, never the sum. */
  readonly notRequiredDistinct: number;
  /** Required observations by relation. */
  readonly requiredByRelation: Readonly<Record<string, number>>;
}

/**
 * M3.7.1 -- recomputed from the assembled plan through the SAME predicate
 * completeness uses.
 *
 * D13: this function previously restated Required as
 *     Applicable & Eligible & Executable
 * and was not revisited when M3-H13 added the fourth conjunct. Two functions
 * of one artifact then operated on two definitions of obligation, and the
 * freeze gate asserted the stale one -- 1416 where the instrument's own
 * predicate yields 1264.
 *
 * The repair is not to add the missing conjunct here. It is to stop having a
 * second copy of the formula at all: this function now CALLS
 * isRequiredEvidence, so a future change to Required cannot leave the counter
 * behind. The scientific definition is untouched; only the counter is.
 *
 * The causes are read from structuralComparability's own verdict rather than
 * re-derived, so the specialised interop provenance is preserved:
 * 'contractually-non-eligible' stays distinct from
 * 'structurally-non-comparable' even though both are structural barriers.
 */
export function recountPlan(plan: StructuralExecutionPlan): PlanRecount {
  let planned = 0, required = 0, notRequired = 0;
  let nonEligible = 0, nonComparable = 0, notExecutable = 0;
  let neAndNx = 0, sncAndNx = 0, neAndSnc = 0;
  const requiredByRelation: Record<string, number> = {};

  for (const c of plan.classes) {
    for (const si of c.stimulusInstances) {
      const barriers = structurallyNonComparableRelations(c.mutationId, si.stimulusInstanceId);
      const barrierRelations = new Set(barriers.keys());
      for (const x of si.executability) {
        planned += 1;
        const planned_ = { relation: x.relation, scope: x.scope, executability: x.state };
        if (isRequiredEvidence(planned_, si.interopEligibility, barrierRelations)) {
          required += 1;
          requiredByRelation[x.relation] = (requiredByRelation[x.relation] ?? 0) + 1;
          continue;
        }
        notRequired += 1;
        const verdict = barriers.get(x.relation);
        const isNonEligible = verdict?.cause === 'contractually-non-eligible';
        const isNonComparable = verdict?.cause === 'structurally-non-comparable';
        const isNotExecutable = x.state.kind === 'structurally-not-executable';
        if (isNonEligible) nonEligible += 1;
        if (isNonComparable) nonComparable += 1;
        if (isNotExecutable) notExecutable += 1;
        if (isNonEligible && isNotExecutable) neAndNx += 1;
        if (isNonComparable && isNotExecutable) sncAndNx += 1;
        if (isNonEligible && isNonComparable) neAndSnc += 1;
      }
    }
  }

  return {
    planned, required,
    notRequiredContractuallyNonEligible: nonEligible,
    notRequiredStructurallyNonComparable: nonComparable,
    notRequiredNotExecutable: notExecutable,
    overlapNonEligibleAndNotExecutable: neAndNx,
    overlapNonComparableAndNotExecutable: sncAndNx,
    overlapNonEligibleAndNonComparable: neAndSnc,
    notRequiredDistinct: notRequired,
    requiredByRelation,
  };
}

export interface PairBinding {
  readonly mutationId: string;
  readonly stimulusInstanceId: string;
  readonly hasFixture: boolean;
  readonly hasGroundTruth: boolean;
  readonly relationsPlanned: readonly string[];
  readonly rolesDispatchable: readonly string[];
}

/**
 * "Is every plan entry completely bound?" answered per (class, stimulus):
 * a resolvable fixture, a pre-registered ground-truth row, the relations its
 * operation makes applicable, and the execution roles dispatch can resolve.
 *
 * Fail-closed: a pair missing any of these throws rather than being reported
 * as a zero, because a zero in a coverage table reads as measured absence.
 */
export function auditPlanBinding(
  plan: StructuralExecutionPlan,
  pool: FrozenMaterialPool,
): readonly PairBinding[] {
  const out: PairBinding[] = [];
  for (const c of plan.classes) {
    const entry = MUTATION_REGISTRY.find((e) => e.mutationId === c.mutationId);
    if (entry === undefined) throw new PlanBindingError(`Plan class '${c.mutationId}' is not in the frozen registry.`);
    for (const si of c.stimulusInstances) {
      const s = si.stimulusInstanceId;
      // Fixture: resolvable and actually resolving, not merely registered.
      getFixtureResolver(c.mutationId, s)(c.mutationId, s, pool);
      getMutationImplementation(c.mutationId);
      // Ground truth: pre-registered, never derived here.
      resolveGroundTruth(c.mutationId, s);
      const relations = [...new Set(si.executability.map((x) => x.relation))];
      out.push({
        mutationId: c.mutationId, stimulusInstanceId: s,
        hasFixture: true, hasGroundTruth: true,
        relationsPlanned: relations,
        rolesDispatchable: [...(ROLES_BY_OPERATION[c.operation] ?? [])],
      });
    }
  }
  return out;
}

/** The 26 non-eligible pairs must never begin an interop flow. */
export function nonEligibleInteropPairs(): readonly string[] {
  const out: string[] = [];
  for (const e of MUTATION_REGISTRY) {
    if (!APPLICABILITY_MATRIX[e.operation].R_interop) continue;
    for (const si of e.stimulusInstances) {
      if (resolveInteropEligibility(e.mutationId, si.stimulusInstanceId).eligibility.kind !== 'eligible') {
        out.push(`${e.mutationId}::${si.stimulusInstanceId}`);
      }
    }
  }
  return out;
}
