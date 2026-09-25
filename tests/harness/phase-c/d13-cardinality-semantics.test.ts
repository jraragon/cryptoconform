// M3.7.1 -- D13 regression cover.
//
// The defect was not a wrong number. It was a SECOND COPY of the definition
// of Required, which drifted when H13 added a fourth conjunct and was not
// revisited. So the cover here is not "assert 1264": that would drift again
// the next time the definition moves. It is:
//
//     recountPlan MUST agree with isRequiredEvidence, observation by
//     observation, whatever either of them says.
//
// A future change to Required that forgets the counter fails here rather
// than at a freeze gate, and fails with a diagnosis rather than a mismatch.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';

import { recountPlan } from '../../../harness/phase-c/plan-binding-audit.js';
import { assembleStructuralPlan, planCardinality } from '../../../harness/phase-c/plan-assembly.js';
import { loadFrozenMaterialPool } from '../../../harness/phase-c/material/load.js';
import { isRequiredEvidence, type PlannedObservation } from '../../../harness/evidence/mutation-instance-result.js';
import { structurallyNonComparableRelations } from '../../../harness/phase-c/structural-comparability.js';

const plan = assembleStructuralPlan(loadFrozenMaterialPool());

/** The independent recomputation, from the normative predicate alone. */
function requiredByPredicate(): { required: number; notRequired: number } {
  let required = 0, notRequired = 0;
  for (const c of plan.classes) {
    for (const si of c.stimulusInstances) {
      const barriers = new Set(structurallyNonComparableRelations(c.mutationId, si.stimulusInstanceId).keys());
      for (const x of si.executability) {
        const p: PlannedObservation = { relation: x.relation, scope: x.scope, executability: x.state };
        if (isRequiredEvidence(p, si.interopEligibility, barriers)) required += 1; else notRequired += 1;
      }
    }
  }
  return { required, notRequired };
}

test('D13: recountPlan agrees with isRequiredEvidence, whatever either says', () => {
  const rc = recountPlan(plan);
  const direct = requiredByPredicate();
  assert.equal(rc.required, direct.required,
    'the counter and the normative predicate must not hold two definitions of Required');
  assert.equal(rc.notRequiredDistinct, direct.notRequired);
  assert.equal(rc.required + rc.notRequiredDistinct, rc.planned);
});

test('D13: the counter does not restate the formula -- it calls it', () => {
  // The structural guarantee, not just the numeric one. A counter that
  // re-derived the conjuncts could agree today and drift tomorrow, which is
  // exactly what happened between Bloque C2 and M3-H13.
  const src = readFileSync(new URL('../../../harness/phase-c/plan-binding-audit.ts', import.meta.url), 'utf8');
  assert.ok(src.includes('isRequiredEvidence('), 'recountPlan must consume the normative predicate');
  const fn = src.slice(src.indexOf('export function recountPlan'), src.indexOf('export interface PairBinding'));
  // No re-derivation of the eligibility conjunct inside the counter.
  assert.ok(!fn.includes("interopEligibility?.value.kind === 'non-eligible'"),
    'the eligibility conjunct must not be restated here');
  assert.ok(!/&&\s*!is/.test(fn), 'no hand-rolled conjunction of Required');
});

test('D13: the three causes OVERLAP, and the recount says so explicitly', () => {
  const rc = recountPlan(plan);
  const sum = rc.notRequiredContractuallyNonEligible
    + rc.notRequiredStructurallyNonComparable + rc.notRequiredNotExecutable;
  const union = sum
    - rc.overlapNonEligibleAndNotExecutable - rc.overlapNonComparableAndNotExecutable
    - rc.overlapNonEligibleAndNonComparable;
  assert.equal(union, rc.notRequiredDistinct);
  assert.ok(sum > rc.notRequiredDistinct, 'the sum overstates; only the union is the population');
  // Every overlap is reported as its own field, so no consumer has to guess.
  assert.equal(rc.overlapNonEligibleAndNotExecutable, 32);
  assert.equal(rc.overlapNonComparableAndNotExecutable, 63);
  assert.equal(rc.overlapNonEligibleAndNonComparable, 0);
});

test('D13: the two causes keep their distinct provenance', () => {
  // 'contractually-non-eligible' is more informative than the general
  // barrier and was frozen first; M3-H13 defined the general dimension
  // THROUGH it rather than over it. The recount must not merge them.
  const rc = recountPlan(plan);
  assert.equal(rc.notRequiredContractuallyNonEligible, 126, '26 non-eligible pairs x 6 directions');
  // R_err and R_val barriers (156), plus the 18 PSS artifact-side R_interop
  // obligations M3.7-D2 added to the same cause.
  assert.equal(rc.notRequiredStructurallyNonComparable, 582);
  assert.equal(rc.overlapNonEligibleAndNonComparable, 0, 'and no observation carries both causes');
});

test('D13: the historical difference is reconciled, not merely superseded', () => {
  const rc = recountPlan(plan);
  // 1416 was the pre-H13 figure. The difference accumulates three repairs,
  // each recorded rather than absorbed into a new number.
  assert.equal(rc.required, 886);
  assert.equal(1416 - rc.required, 530);
});

test('D13: required by relation sums to required', () => {
  const rc = recountPlan(plan);
  const sum = Object.values(rc.requiredByRelation).reduce((a, b) => a + b, 0);
  assert.equal(sum, rc.required);
  assert.deepEqual(rc.requiredByRelation, {
    R_byte: 42, R_val: 209, R_cap: 238, R_err: 91, R_interop: 216, R_ser: 90,
  });
});


test('planCardinality counts a DIFFERENT thing, and the two must not be confused', () => {
  // Unexpected finding recorded rather than silently tolerated:
  // planCardinality.required counts PlannedExecutability states (1499), not
  // normative obligations (1264). Its field name is the same word for a
  // different concept -- which is the ambiguity that produced D13 in the
  // first place. Left unrenamed because renaming is outside M3.7.1's scope;
  // pinned here so the difference is deliberate and visible.
  const pc = planCardinality(plan);
  const rc = recountPlan(plan);
  assert.equal(pc.plannedObservations, rc.planned);
  assert.equal(pc.required, 1499, 'scopes whose executability state is required');
  assert.equal(rc.required, 886, 'observations that are a normative obligation');
  assert.notEqual(pc.required, rc.required);
  assert.equal(pc.required + pc.notExecutable, 1641);
});
