// Bloque A -- cumulative gate for M3-H10 and M3-H11-Core.
//
// Covers Core.1 + Core.2 + Core.3 + persistence together, against the real
// frozen plan rather than fixtures wherever the fact is a property of the
// experiment rather than of the code.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';

import { assembleStructuralPlan } from '../../../../harness/phase-c/plan-assembly.js';
import { loadFrozenMaterialPool } from '../../../../harness/phase-c/material/load.js';
import { aggregateMutationClass } from '../../../../harness/aggregation/aggregator.js';
import {
  assertBundleConsistency, BundleConsistencyError, exportBundle, importBundle,
  reconstructScientificResult, type EvidenceBundle,
} from '../../../../harness/aggregation/evidence-export.js';
import {
  computeCompleteness, makeMutationInstanceResult, type PlannedObservation,
} from '../../../../harness/evidence/mutation-instance-result.js';
import {
  makePhaseCScientificResult, toRelationSpectrum,
} from '../../../../harness/evidence/phase-c-scientific-result.js';
import { makeMutationResult } from '../../../../harness/evidence/mutation-result.js';
import { computeEntryHash, resolveInteropEligibility } from '../../../../harness/phase-c/interop-eligibility/resolve.js';
import { CHROMIUM_WEBCRYPTO, CRYPTOPP } from '../../../../harness/schema/backend-identity.js';
import { APPLICABILITY_MATRIX } from '../../../../harness/applicability/matrix.js';
import type { RelationApplicability } from '../../../../harness/schema/registry-types.js';

const plan = assembleStructuralPlan(loadFrozenMaterialPool());
const interopScope = { kind: 'backend-pair', from: CHROMIUM_WEBCRYPTO, to: CRYPTOPP } as PlannedObservation['scope'];
const elig = (m: string, s: string) => {
  const r = resolveInteropEligibility(m, s);
  return { value: r.eligibility, source: r.source, entryHash: computeEntryHash(r) };
};
const NA_EXPECTED = { expectation: 'not-expected' } as const;
const EXPECTED_SPECTRUM = {
  R_byte: NA_EXPECTED, R_interop: NA_EXPECTED, R_ser: NA_EXPECTED,
  R_val: NA_EXPECTED, R_err: NA_EXPECTED, R_cap: NA_EXPECTED,
};

// =====================================================================
// The population, measured against the real plan
// =====================================================================

test('GATE: 23 contractually-non-eligible + 2 zero-executable-support, and no others', () => {
  let h11 = 0, h7 = 0;
  for (const c of plan.classes) {
    if (!APPLICABILITY_MATRIX[c.operation].R_interop) continue;
    const anyEligible = c.stimulusInstances.some((si) => si.interopEligibility?.value.kind === 'eligible');
    if (!anyEligible) { h11 += 1; continue; }
    const anySupport = c.stimulusInstances.some((si) =>
      si.interopEligibility?.value.kind === 'eligible'
      && si.executability.some((x) => x.relation === 'R_interop' && x.state.kind === 'required'));
    if (!anySupport) h7 += 1;
  }
  assert.equal(h11, 23);
  assert.equal(h7, 2);
});

test('GATE: the 124 scopes remain PLANNED and executable, and none is outstanding', () => {
  let planned = 0, outstanding = 0;
  for (const c of plan.classes) {
    for (const si of c.stimulusInstances) {
      if (si.interopEligibility?.value.kind !== 'non-eligible') continue;
      const ps: PlannedObservation[] = si.executability
        .filter((x) => x.relation === 'R_interop' && x.state.kind === 'required')
        .map((x) => ({ relation: x.relation, scope: x.scope, executability: x.state }));
      planned += ps.length;
      outstanding += computeCompleteness(ps, [], si.interopEligibility).outstanding.length;
    }
  }
  assert.equal(planned, 124, 'the structural plan was not reduced to fix completeness');
  assert.equal(outstanding, 0, 'and none of them is an obligation');
});

// =====================================================================
// No fabrication, in either direction
// =====================================================================

test('GATE: an absent cell is never fabricated as pass, fail or n/a', () => {
  const nx: PlannedObservation[] = [{
    relation: 'R_interop', scope: interopScope,
    executability: { kind: 'structurally-not-executable', reason: 'backend-capability-absent' },
  }];
  const inst = makeMutationInstanceResult({
    mutationId: 'GCM-AUTHENTICATION-BYPASS', stimulusInstanceId: 'TAG-TAMPER', operation: 'gcm',
    planned: nx, observations: [], interopEligibility: elig('GCM-AUTHENTICATION-BYPASS', 'TAG-TAMPER'),
  });
  const applicability: RelationApplicability =
    { R_byte: false, R_interop: true, R_ser: false, R_val: false, R_err: false, R_cap: false };
  const agg = aggregateMutationClass(applicability, [inst], []);
  for (const v of ['pass', 'fail', 'n/a']) assert.notEqual(agg.observedSpectrum.R_interop, v);
  assert.equal(agg.observedSpectrum.R_interop, undefined);
});

test('GATE: inapplicability is still expressed exclusively as n/a', () => {
  const applicability: RelationApplicability =
    { R_byte: false, R_interop: false, R_ser: false, R_val: false, R_err: false, R_cap: false };
  const inst = makeMutationInstanceResult({
    mutationId: 'X', stimulusInstanceId: 'default', operation: 'hkdf', planned: [], observations: [],
  });
  const agg = aggregateMutationClass(applicability, [inst], []);
  for (const r of ['R_byte', 'R_interop', 'R_ser', 'R_val', 'R_err', 'R_cap'] as const) {
    assert.equal(agg.observedSpectrum[r], 'n/a');
  }
  assert.equal(agg.nonScoreable.length, 0, 'inapplicable is not unscoreable');
});

test('GATE: a partial class keeps every other relation', () => {
  const valScope = { kind: 'single-backend', backend: CHROMIUM_WEBCRYPTO } as PlannedObservation['scope'];
  const planned: PlannedObservation[] = [
    { relation: 'R_interop', scope: interopScope, executability: { kind: 'required' } },
    { relation: 'R_val', scope: valScope, executability: { kind: 'required' } },
  ];
  const obs = {
    observationId: 'o1', applicable: true, relation: 'R_val' as const, scope: valScope,
    status: 'fail' as const, participants: [], evaluatorId: 'R_val', basis: 'gate',
    context: { kind: 'mutation' as const, phase: 'C' as const, mutationId: 'GCM-PROVIDER-CAPABILITY-MISMATCH', stimulusInstanceId: 'default' },
  };
  const inst = makeMutationInstanceResult({
    mutationId: 'GCM-PROVIDER-CAPABILITY-MISMATCH', stimulusInstanceId: 'default', operation: 'gcm',
    planned, observations: [obs], interopEligibility: elig('GCM-PROVIDER-CAPABILITY-MISMATCH', 'default'),
  });
  const applicability: RelationApplicability =
    { R_byte: false, R_interop: true, R_ser: false, R_val: true, R_err: false, R_cap: false };
  const agg = aggregateMutationClass(applicability, [inst], [obs]);
  assert.equal(agg.observedSpectrum.R_val, 'fail', 'the evidence Core.2 was written to save');
  assert.equal(agg.nonScoreable[0]!.cause, 'contractually-non-eligible');
  assert.equal(inst.complete, true, 'and H10: it is not incomplete for it');
});

// =====================================================================
// Persistence and dataset-alone reconstructibility
// =====================================================================

function bundleFor(nonScoreableRelation: 'R_interop' | null): EvidenceBundle {
  const applicability: RelationApplicability =
    { R_byte: false, R_interop: true, R_ser: false, R_val: true, R_err: false, R_cap: false };
  const inst = makeMutationInstanceResult({
    mutationId: 'C', stimulusInstanceId: 'default', operation: 'gcm', planned: [], observations: [],
  });
  const sr = makePhaseCScientificResult({
    mutationId: 'C', operation: 'gcm', gamma0Ref: 'registry:C', applicability,
    observedSpectrum: nonScoreableRelation
      ? { R_byte: 'n/a', R_ser: 'n/a', R_val: 'pass', R_err: 'n/a', R_cap: 'n/a' }
      : { R_byte: 'n/a', R_interop: 'pass', R_ser: 'n/a', R_val: 'pass', R_err: 'n/a', R_cap: 'n/a' },
    nonScoreable: nonScoreableRelation
      ? [{ mutationId: 'C', operation: 'gcm', relation: 'R_interop', cause: 'contractually-non-eligible', stimulusInstanceIds: ['default'] }]
      : [],
    instanceResults: [inst], detectionSupport: { divergentInstances: 0, evaluatedInstances: 1 },
  });
  const mutationResults = nonScoreableRelation ? [] : [makeMutationResult({
    mutationId: 'C', operation: 'gcm', gamma0Ref: 'registry:C', applicability,
    expectedSpectrum: EXPECTED_SPECTRUM, instanceResults: [inst],
    observedSpectrum: toRelationSpectrum(sr), detectionSupport: { divergentInstances: 0, evaluatedInstances: 1 },
  })];
  return {
    bundleVersion: '2.0', executions: [], observations: [], instanceResults: [inst],
    mutationResults, scientificResults: [sr], omittedClasses: [],
  };
}

test('GATE: the bundle round-trips both representations unchanged', () => {
  const b = bundleFor('R_interop');
  const back = importBundle(exportBundle(b));
  assert.deepEqual(back, b);
  assert.equal(back.scientificResults![0]!.nonScoreable[0]!.cause, 'contractually-non-eligible');
});

test('GATE: dataset-alone reconstructibility -- no registry, no plan, no exception', () => {
  const back = importBundle(exportBundle(bundleFor('R_interop')));
  const { result, instances } = reconstructScientificResult(back, 'C');
  assert.equal(result.observedSpectrum.R_val, 'pass');            // r~(c)
  assert.equal(result.observedSpectrum.R_interop, undefined);
  assert.equal(result.nonScoreable[0]!.relation, 'R_interop');    // NonScoreable(c,R) + cause
  assert.deepEqual([...result.outstandingRequiredEvidence], []);  // outstanding
  assert.equal(instances.length, 1);
});

test('GATE: scientificResults and mutationResults agree for a reducible class', () => {
  const b = bundleFor(null);
  assert.doesNotThrow(() => assertBundleConsistency(b));
  assert.deepEqual(b.mutationResults[0]!.observedSpectrum, toRelationSpectrum(b.scientificResults![0]!));
});

test('GATE: a partial class must NOT carry a MutationResult, and the check fires', () => {
  const partial = bundleFor('R_interop');
  const complete = bundleFor(null);
  const forged: EvidenceBundle = { ...partial, mutationResults: complete.mutationResults };
  assert.throws(() => assertBundleConsistency(forged), BundleConsistencyError);
  assert.throws(() => assertBundleConsistency(forged), /must not have been fabricated/);
});

test('GATE: a disagreeing projection is refused, so neither collection can drift', () => {
  const b = bundleFor(null);
  const tampered: EvidenceBundle = {
    ...b,
    mutationResults: [{ ...b.mutationResults[0]!, observedSpectrum: { ...b.mutationResults[0]!.observedSpectrum, R_val: 'fail' } }],
  };
  assert.throws(() => assertBundleConsistency(tampered), /disagrees with its MutationResult spectrum/);
});

test('GATE: omittedClasses is structured -- no exception text as science', () => {
  const src = readFileSync(new URL('../../../../harness/evidence/class-omission.ts', import.meta.url), 'utf8');
  assert.ok(src.includes("'harness-error'") && src.includes("'not-reached'"));
  const orch = readFileSync(new URL('../../../../harness/orchestration/phase-c-orchestrator.ts', import.meta.url), 'utf8');
  assert.ok(!orch.includes('reason: error.message'), 'a machine-readable cause must not be an exception message');
  assert.ok(!orch.includes('unscoredClasses'), 'the untyped collection is gone');
});

test('GATE: the bundle version changed with its contract', () => {
  assert.throws(() => importBundle(JSON.stringify({ bundleVersion: '3.0' })), /Unsupported EvidenceBundle version/);
  // 1.0 stays readable: those bundles predate partial results and remain
  // valid on their own terms.
  assert.equal(importBundle(JSON.stringify({ bundleVersion: '1.0' })).bundleVersion, '1.0');
});

// =====================================================================
// Boundaries
// =====================================================================

test('GATE: RelationSpectrum and MutationResult are untouched M2 types', () => {
  const spec = readFileSync(new URL('../../../../harness/evidence/relation-spectrum.ts', import.meta.url), 'utf8');
  assert.ok(spec.includes("export type RelationValue = 'pass' | 'fail' | 'n/a';"));
  assert.equal((spec.match(/readonly R_\w+: RelationValue;/g) ?? []).length, 6);
  const mr = readFileSync(new URL('../../../../harness/evidence/mutation-result.ts', import.meta.url), 'utf8');
  assert.ok(mr.includes('readonly observedSpectrum: RelationSpectrum;'));
  assert.ok(!mr.includes('nonScoreable'));
});

test('GATE: no cross-operation semantics from H12 entered Bloque A', () => {
  const files = [
    'harness/evidence/non-scoreable.ts',
    'harness/evidence/phase-c-scientific-result.ts',
    'harness/evidence/class-omission.ts',
    'harness/aggregation/aggregator.ts',
  ];
  for (const f of files) {
    const src = readFileSync(new URL(`../../../../${f}`, import.meta.url), 'utf8');
    for (const forbidden of ['DetectionGain', 'DiagnosticGain', 'Undetermined', 'O_min', 'H_obs']) {
      assert.ok(!src.includes(forbidden), `${f} must not reach for '${forbidden}'`);
    }
  }
});

test('GATE: legacy behaviour with no eligibility recorded is unchanged', () => {
  const planned: PlannedObservation[] = [
    { relation: 'R_interop', scope: interopScope, executability: { kind: 'required' } },
  ];
  assert.equal(computeCompleteness(planned, []).complete, false, 'Required reduces to Executable');
  const inst = makeMutationInstanceResult({
    mutationId: 'LEGACY', stimulusInstanceId: 'default', operation: 'gcm', planned, observations: [],
  });
  assert.equal(inst.complete, false);
  assert.ok(!('interopEligibility' in inst), 'and no field appears where none was supplied');
});
