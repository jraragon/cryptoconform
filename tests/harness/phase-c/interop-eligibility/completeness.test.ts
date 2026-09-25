// M3-H11.4-Core.3 -- Required vs Planned, and the completeness gate.
//
// The six invariants C3.1..C3.6, plus the quantitative criterion against the
// state at 98760ce: the 124 spurious outstanding observations must be gone
// WITHOUT reducing the structural plan to achieve it.

import { test } from 'node:test';
import assert from 'node:assert/strict';

import { assembleStructuralPlan } from '../../../../harness/phase-c/plan-assembly.js';
import { loadFrozenMaterialPool } from '../../../../harness/phase-c/material/load.js';
import {
  computeCompleteness,
  isRequiredEvidence,
  makeMutationInstanceResult,
  type PlannedObservation,
} from '../../../../harness/evidence/mutation-instance-result.js';
import { makePhaseCScientificResult, ScientificResultIntegrityError } from '../../../../harness/evidence/phase-c-scientific-result.js';
import { computeEntryHash, resolveInteropEligibility } from '../../../../harness/phase-c/interop-eligibility/resolve.js';
import { CHROMIUM_WEBCRYPTO, CRYPTOPP } from '../../../../harness/schema/backend-identity.js';
import { APPLICABILITY_MATRIX } from '../../../../harness/applicability/matrix.js';
import type { RelationApplicability } from '../../../../harness/schema/registry-types.js';

const plan = assembleStructuralPlan(loadFrozenMaterialPool());
const interopScope = { kind: 'backend-pair', from: CHROMIUM_WEBCRYPTO, to: CRYPTOPP } as PlannedObservation['scope'];
const valScope = { kind: 'single-backend', backend: CHROMIUM_WEBCRYPTO } as PlannedObservation['scope'];

const eligibilityOf = (mutationId: string, stimulusInstanceId: string) => {
  const r = resolveInteropEligibility(mutationId, stimulusInstanceId);
  return { value: r.eligibility, source: r.source, entryHash: computeEntryHash(r) };
};

// ---------------------------------------------------------------------
// C3.1 -- Planned keeps its M2 structure
// ---------------------------------------------------------------------

test('C3.1: the structural plan is untouched -- Planned(c,R) = Applicability(o,R)', () => {
  // Core.3 must not prune the plan to fix completeness. The 23 H11 pairs and
  // the 1 H7 pair stay visible as planning that ended in non-obligation.
  let interopEntries = 0;
  for (const c of plan.classes) {
    const hasInterop = APPLICABILITY_MATRIX[c.operation].R_interop;
    const planned = c.entries.filter((e) => e.relation === 'R_interop').length;
    if (hasInterop) assert.ok(planned > 0, `${c.mutationId}: R_interop applicable but nothing planned`);
    else assert.equal(planned, 0, `${c.mutationId}: nothing may be planned for an inapplicable relation`);
    interopEntries += planned;
  }
  assert.ok(interopEntries > 0);
});

test('C3.1: the 26 non-eligible pairs still carry their 124 planned-and-required scopes', () => {
  // Structural planning is unchanged; only obligation changes. This is the
  // control for the quantitative criterion below.
  let stillPlannedRequired = 0;
  for (const c of plan.classes) {
    for (const si of c.stimulusInstances) {
      if (si.interopEligibility?.value.kind !== 'non-eligible') continue;
      stillPlannedRequired += si.executability.filter(
        (x) => x.relation === 'R_interop' && x.state.kind === 'required').length;
    }
  }
  assert.equal(stillPlannedRequired, 124, 'the plan did not shrink');
});

// ---------------------------------------------------------------------
// C3.2 -- Required = Applicable & Eligible & Executable
// ---------------------------------------------------------------------

test('C3.2: an executable scope of a non-eligible pair is planned but NOT required', () => {
  const p: PlannedObservation = { relation: 'R_interop', scope: interopScope, executability: { kind: 'required' } };
  assert.equal(isRequiredEvidence(p, eligibilityOf('GCM-PROVIDER-CAPABILITY-MISMATCH', 'default')), false);
  assert.equal(isRequiredEvidence(p, eligibilityOf('GCM-AUTHENTICATION-BYPASS', 'TAG-TAMPER')), true);
});

test('C3.2: a structurally-not-executable scope is not required, eligible or not', () => {
  const nx: PlannedObservation = {
    relation: 'R_interop', scope: interopScope,
    executability: { kind: 'structurally-not-executable', reason: 'backend-capability-absent' },
  };
  assert.equal(isRequiredEvidence(nx, eligibilityOf('GCM-AUTHENTICATION-BYPASS', 'TAG-TAMPER')), false);
});

test('C3.2: for relations other than R_interop, Eligible is logical identity', () => {
  // No fictitious eligibility record is invented for them, and an absent
  // field means "not applicable to this question", never "unknown".
  const p: PlannedObservation = { relation: 'R_val', scope: valScope, executability: { kind: 'required' } };
  assert.equal(isRequiredEvidence(p, eligibilityOf('GCM-PROVIDER-CAPABILITY-MISMATCH', 'default')), true,
    'a non-eligible INTEROP decision must not suppress an R_val obligation');
  assert.equal(isRequiredEvidence(p, undefined), true);
});

test('C3.2: with no eligibility recorded, Required reduces to Executable -- M2 behaviour preserved', () => {
  const planned: PlannedObservation[] = [
    { relation: 'R_interop', scope: interopScope, executability: { kind: 'required' } },
  ];
  assert.equal(computeCompleteness(planned, []).complete, false, 'unchanged for every pre-existing M2 caller');
});

// ---------------------------------------------------------------------
// C3.3 / C3.4 -- Outstanding and Complete
// ---------------------------------------------------------------------

test('C3.3 + C3.4: Outstanding = Required & not Satisfied; Complete <=> Outstanding empty', () => {
  const planned: PlannedObservation[] = [
    { relation: 'R_interop', scope: interopScope, executability: { kind: 'required' } },
    { relation: 'R_val', scope: valScope, executability: { kind: 'required' } },
  ];
  const nonEligible = computeCompleteness(planned, [], eligibilityOf('GCM-PROVIDER-CAPABILITY-MISMATCH', 'default'));
  assert.equal(nonEligible.outstanding.length, 1, 'only R_val remains an obligation');
  assert.equal(nonEligible.outstanding[0]!.relation, 'R_val');
  assert.equal(nonEligible.complete, false);
});

// ---------------------------------------------------------------------
// C3.5 -- the essence of H10
// ---------------------------------------------------------------------

test('C3.5: NonScoreable does NOT imply Incomplete', () => {
  const planned: PlannedObservation[] = [
    { relation: 'R_interop', scope: interopScope, executability: { kind: 'required' } },
  ];
  const inst = makeMutationInstanceResult({
    mutationId: 'GCM-PROVIDER-CAPABILITY-MISMATCH', stimulusInstanceId: 'default', operation: 'gcm',
    planned, observations: [],
    interopEligibility: eligibilityOf('GCM-PROVIDER-CAPABILITY-MISMATCH', 'default'),
  });
  // At 98760ce this instance was complete=false forever, with one permanent
  // outstanding observation. That was M3-H10.
  assert.equal(inst.complete, true);
  assert.equal(inst.coverage.outstanding.length, 0);

  const applicability: RelationApplicability =
    { R_byte: false, R_interop: true, R_ser: false, R_val: false, R_err: false, R_cap: false };
  const result = makePhaseCScientificResult({
    mutationId: 'GCM-PROVIDER-CAPABILITY-MISMATCH', operation: 'gcm', gamma0Ref: 'registry:x',
    applicability,
    // The five inapplicable relations are MATERIALISED as n/a; only
    // R_interop is absent, and it is absent because it is non-scoreable.
    observedSpectrum: { R_byte: 'n/a', R_ser: 'n/a', R_val: 'n/a', R_err: 'n/a', R_cap: 'n/a' },
    nonScoreable: [{
      mutationId: 'GCM-PROVIDER-CAPABILITY-MISMATCH', operation: 'gcm', relation: 'R_interop',
      cause: 'contractually-non-eligible', stimulusInstanceIds: ['default'],
    }],
    instanceResults: [inst], detectionSupport: { divergentInstances: 0, evaluatedInstances: 0 },
  });
  assert.equal(result.requiredEvidenceComplete, true, 'a non-scoreable relation cannot make a class incomplete');
  assert.deepEqual([...result.outstandingRequiredEvidence], []);
});

test('C3.5: the cross-invariant fires -- a non-scoreable cell may leave no outstanding obligation', () => {
  // Guards against completeness and non-scoreability becoming two
  // independent sources of truth about the same cell.
  const planned: PlannedObservation[] = [
    { relation: 'R_interop', scope: interopScope, executability: { kind: 'required' } },
  ];
  // Built WITHOUT the eligibility, so the gate still marks it outstanding,
  // while the cell claims it is non-scoreable. The two disagree and must be
  // refused rather than silently reconciled.
  const inconsistent = makeMutationInstanceResult({
    mutationId: 'X', stimulusInstanceId: 'default', operation: 'gcm', planned, observations: [],
  });
  const applicability: RelationApplicability =
    { R_byte: false, R_interop: true, R_ser: false, R_val: false, R_err: false, R_cap: false };
  assert.throws(() => makePhaseCScientificResult({
    mutationId: 'X', operation: 'gcm', gamma0Ref: 'registry:x', applicability,
    observedSpectrum: { R_byte: 'n/a', R_ser: 'n/a', R_val: 'n/a', R_err: 'n/a', R_cap: 'n/a' },
    nonScoreable: [{
      mutationId: 'X', operation: 'gcm', relation: 'R_interop',
      cause: 'zero-executable-support', stimulusInstanceIds: ['default'],
    }],
    instanceResults: [inconsistent], detectionSupport: { divergentInstances: 0, evaluatedInstances: 0 },
  }), ScientificResultIntegrityError);
});

test('a genuinely unsatisfied obligation still blocks completeness', () => {
  // The gate must not have become permissive: an eligible, executable scope
  // with no terminal observation is still outstanding.
  const planned: PlannedObservation[] = [
    { relation: 'R_interop', scope: interopScope, executability: { kind: 'required' } },
  ];
  const inst = makeMutationInstanceResult({
    mutationId: 'GCM-AUTHENTICATION-BYPASS', stimulusInstanceId: 'TAG-TAMPER', operation: 'gcm',
    planned, observations: [],
    interopEligibility: eligibilityOf('GCM-AUTHENTICATION-BYPASS', 'TAG-TAMPER'),
  });
  assert.equal(inst.complete, false);
  assert.equal(inst.coverage.outstanding.length, 1);
});

// ---------------------------------------------------------------------
// The quantitative criterion against 98760ce
// ---------------------------------------------------------------------

test('the 124 spurious outstanding observations of M3-H10 are gone', () => {
  let outstanding = 0, plannedRequiredScopes = 0;
  for (const c of plan.classes) {
    for (const si of c.stimulusInstances) {
      if (si.interopEligibility?.value.kind !== 'non-eligible') continue;
      const planned: PlannedObservation[] = si.executability
        .filter((x) => x.relation === 'R_interop' && x.state.kind === 'required')
        .map((x) => ({ relation: x.relation, scope: x.scope, executability: x.state }));
      plannedRequiredScopes += planned.length;
      outstanding += computeCompleteness(planned, [], si.interopEligibility).outstanding.length;
    }
  }
  assert.equal(plannedRequiredScopes, 124, 'the plan still carries them');
  assert.equal(outstanding, 0, 'none of them is an obligation any more');
});

// ---------------------------------------------------------------------
// C3.6 -- environment invariance separates the two causes
// ---------------------------------------------------------------------

test('C3.6: H11 is environment-invariant, H7 is not -- varying support, not reading the label', () => {
  const scope = interopScope;
  const nonEligible = eligibilityOf('GCM-PROVIDER-CAPABILITY-MISMATCH', 'default');
  const eligible = eligibilityOf('GCM-AUTHENTICATION-BYPASS', 'TAG-TAMPER');

  // H7's cause lives in the scope's executability, so declaring a backend
  // that can run it flips the obligation back on.
  const h7Before: PlannedObservation = {
    relation: 'R_interop', scope,
    executability: { kind: 'structurally-not-executable', reason: 'backend-capability-absent' },
  };
  const h7After: PlannedObservation = { relation: 'R_interop', scope, executability: { kind: 'required' } };
  assert.equal(isRequiredEvidence(h7Before, eligible), false);
  assert.equal(isRequiredEvidence(h7After, eligible), true, 'added support restores the obligation');

  // H11's cause is normative and sits above executability, so the same
  // change leaves it untouched.
  assert.equal(isRequiredEvidence(h7Before, nonEligible), false);
  assert.equal(isRequiredEvidence(h7After, nonEligible), false, 'no backend can create a contractual flow');
});
