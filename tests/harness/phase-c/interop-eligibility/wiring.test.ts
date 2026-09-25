// M3-H9.3a-3.2.5c -- the four connections, and the divergence the fourth
// exposes.
//
//     Registry -> Plan -> MutationInstanceResult -> Aggregation
//
// Each connection is checked at its own seam, in order, so a failure names
// the link that broke rather than the chain.

import { test } from 'node:test';
import assert from 'node:assert/strict';

import { assembleStructuralPlan } from '../../../../harness/phase-c/plan-assembly.js';
import { loadFrozenMaterialPool } from '../../../../harness/phase-c/material/load.js';
import {
  computeEntryHash,
  resolveInteropEligibility,
} from '../../../../harness/phase-c/interop-eligibility/resolve.js';
import {
  makeMutationInstanceResult,
  type MutationInstanceResult,
  type PlannedObservation,
} from '../../../../harness/evidence/mutation-instance-result.js';
import { aggregateMutationClass } from '../../../../harness/aggregation/aggregator.js';
import { exportBundle, importBundle, type EvidenceBundle } from '../../../../harness/aggregation/evidence-export.js';
import { CHROMIUM_WEBCRYPTO, CRYPTOPP, BOUNCY_CASTLE } from '../../../../harness/schema/backend-identity.js';
import { MUTATION_REGISTRY } from '../../../../harness/registry/mutations.js';
import { APPLICABILITY_MATRIX } from '../../../../harness/applicability/matrix.js';
import { makeRelationObservation } from '../../../../harness/evidence/relation-observation.js';
import type { RelationApplicability } from '../../../../harness/schema/registry-types.js';

const plan = assembleStructuralPlan(loadFrozenMaterialPool());

// ---------------------------------------------------------------------
// Connection 2 -- the assembler resolves, and only where the relation exists
// ---------------------------------------------------------------------

test('connection 2: every R_interop pair carries a resolved eligibility, and HKDF carries none', () => {
  let withEligibility = 0, without = 0;
  for (const c of plan.classes) {
    const hasInterop = APPLICABILITY_MATRIX[c.operation].R_interop;
    for (const si of c.stimulusInstances) {
      if (si.interopEligibility === undefined) {
        without += 1;
        assert.ok(!hasInterop, `${c.mutationId}::${si.stimulusInstanceId}: R_interop applies but no decision was resolved`);
      } else {
        withEligibility += 1;
        assert.ok(hasInterop, `${c.mutationId}::${si.stimulusInstanceId}: eligibility resolved where the relation does not apply`);
      }
    }
  }
  assert.equal(withEligibility, 81);
  assert.equal(without, 9, "HKDF's own 9 pairs answer a question the protocol never asks");
});

test('connection 2: the plan reproduces the registry partition exactly', () => {
  let eligible = 0, blocked = 0, noInput = 0, overrides = 0;
  for (const c of plan.classes) {
    for (const si of c.stimulusInstances) {
      const e = si.interopEligibility;
      if (e === undefined) continue;
      if (e.source === 'stimulus-override') overrides += 1;
      if (e.value.kind === 'eligible') eligible += 1;
      else if (e.value.reason === 'producer-contractually-blocked') blocked += 1;
      else noInput += 1;
    }
  }
  assert.deepEqual({ eligible, blocked, noInput, overrides }, { eligible: 55, blocked: 16, noInput: 10, overrides: 1 });
});

test('connection 2: the assembler consumes, it does not derive', () => {
  // The decision in the plan must be byte-identical to the registry's own
  // resolution -- not merely of the same kind.
  for (const c of plan.classes) {
    for (const si of c.stimulusInstances) {
      if (si.interopEligibility === undefined) continue;
      const direct = resolveInteropEligibility(c.mutationId, si.stimulusInstanceId);
      assert.deepEqual(si.interopEligibility.value, direct.eligibility);
      assert.equal(si.interopEligibility.source, direct.source);
      assert.equal(si.interopEligibility.entryHash, computeEntryHash(direct));
    }
  }
});

test('connection 2: eligibility is a SIBLING of executability, never a member of it', () => {
  // The 124 R_interop observations belonging to non-eligible pairs remain
  // 'required' at the scope level. That is deliberate: writing eligibility
  // into PlannedExecutability is architecture A, which M3-H9.3a-3.2.3
  // rejected on measurement.
  let requiredUnderNonEligible = 0;
  for (const c of plan.classes) {
    for (const si of c.stimulusInstances) {
      if (si.interopEligibility?.value.kind !== 'non-eligible') continue;
      for (const x of si.executability) {
        if (x.relation !== 'R_interop') continue;
        assert.ok(x.state.kind === 'required' || x.state.kind === 'structurally-not-executable');
        if (x.state.kind === 'required') requiredUnderNonEligible += 1;
      }
    }
  }
  assert.equal(requiredUnderNonEligible, 124, 'no eligibility decision leaked into an executability state');
});

// ---------------------------------------------------------------------
// Connections 1 and 3 -- the field, and the verbatim copy
// ---------------------------------------------------------------------

function instanceFor(mutationId: string, stimulusInstanceId: string, planned: PlannedObservation[]): MutationInstanceResult {
  const r = resolveInteropEligibility(mutationId, stimulusInstanceId);
  const frozen = MUTATION_REGISTRY.find((e) => e.mutationId === mutationId)!;
  return makeMutationInstanceResult({
    mutationId, stimulusInstanceId, operation: frozen.operation, planned, observations: [],
    interopEligibility: { value: r.eligibility, source: r.source, entryHash: computeEntryHash(r) },
  });
}

const interopScope = (from = CHROMIUM_WEBCRYPTO, to = CRYPTOPP) =>
  ({ kind: 'backend-pair', from, to }) as PlannedObservation['scope'];

test('connection 1: the field is optional, so every pre-existing M2 object stays valid', () => {
  const noField = makeMutationInstanceResult({
    mutationId: 'HKDF-INFO-TAMPER', stimulusInstanceId: 'default', operation: 'hkdf',
    planned: [], observations: [],
  });
  assert.equal(noField.interopEligibility, undefined);
  assert.ok(!('interopEligibility' in noField), 'absent means absent, never an explicit undefined');
});

test('connection 3: the factory copies verbatim and computes nothing', () => {
  const r = resolveInteropEligibility('OAEP-KEY-ROLE-BYPASS', 'decrypt-with-public');
  const inst = instanceFor('OAEP-KEY-ROLE-BYPASS', 'decrypt-with-public', []);
  assert.deepEqual(inst.interopEligibility!.value, r.eligibility);
  assert.equal(inst.interopEligibility!.source, 'stimulus-override');
});

test('connection 3: entryHash is recomputable from the bundle alone', () => {
  // The instance carries mutationId, stimulusInstanceId, value and source
  // -- exactly the four fields of ResolvedEligibilityEntry -- so a reader
  // holding only the frozen dataset can re-derive the pin.
  const inst = instanceFor('GCM-KEY-PROFILE-BOUNDARY-BYPASS', 'default', []);
  const reconstructed = computeEntryHash({
    mutationId: inst.mutationId,
    stimulusInstanceId: inst.stimulusInstanceId,
    eligibility: inst.interopEligibility!.value,
    source: inst.interopEligibility!.source,
  });
  assert.equal(reconstructed, inst.interopEligibility!.entryHash);
});

test('connection 3: the field survives the EvidenceBundle round trip unchanged', () => {
  const inst = instanceFor('PSS-KEY-ROLE-BYPASS', 'default', []);
  const bundle: EvidenceBundle = {
    bundleVersion: '1.0', executions: [], observations: [], instanceResults: [inst], mutationResults: [],
  };
  const back = importBundle(exportBundle(bundle));
  assert.deepEqual(back.instanceResults[0], inst);
  assert.deepEqual(back.instanceResults[0]!.interopEligibility, inst.interopEligibility);
  // And the provenance inside it, which is what makes the claim refutable.
  const v = back.instanceResults[0]!.interopEligibility!.value;
  assert.ok(v.kind === 'non-eligible' && v.reason === 'producer-contractually-blocked');
  if (v.kind !== 'non-eligible' || v.reason !== 'producer-contractually-blocked') throw new Error('unreachable');
  assert.deepEqual([...v.provenance.clauseIds], ['pss.key']);
});

// ---------------------------------------------------------------------
// Connection 4 -- eligibility is read BEFORE Required
// ---------------------------------------------------------------------

const GCM_APPLICABILITY: RelationApplicability =
  { R_byte: true, R_interop: true, R_ser: true, R_val: true, R_err: true, R_cap: true };

function obsFor(scope: PlannedObservation['scope'], status: 'pass' | 'fail', relation: 'R_interop' | 'R_val') {
  return makeRelationObservation({
    applicable: true,
    context: { kind: 'mutation', phase: 'C', mutationId: 'M', stimulusInstanceId: 'default' },
    relation, scope, status, participants: [], evaluatorId: relation, basis: 'connection-4 fixture',
  });
}

test('M3-H11 RESOLVED: a class whose every stimulus is non-eligible keeps its other relations', () => {
  // This assertion was inverted deliberately by M3-H11.4-Core.2. It
  // previously pinned the defect: aggregateRelation ended with
  // `supportingInstances === 0 => throw`, and that counter could not tell
  // "no instance was ELIGIBLE" from "no instance had executable SUPPORT", so
  // 24 of 71 classes lost their entire MutationResult.
  //
  // Now R_interop is reported as a non-scoreable cell and R_val is scored.
  const valScope = { kind: 'single-backend', backend: CHROMIUM_WEBCRYPTO } as PlannedObservation['scope'];
  const planned: PlannedObservation[] = [
    { relation: 'R_interop', scope: interopScope(), executability: { kind: 'required' } },
    { relation: 'R_val', scope: valScope, executability: { kind: 'required' } },
  ];
  const valObs = obsFor(valScope, 'fail', 'R_val');
  const r = resolveInteropEligibility('GCM-PROVIDER-CAPABILITY-MISMATCH', 'default');
  const inst = makeMutationInstanceResult({
    mutationId: 'GCM-PROVIDER-CAPABILITY-MISMATCH', stimulusInstanceId: 'default', operation: 'gcm',
    planned, observations: [valObs],
    interopEligibility: { value: r.eligibility, source: r.source, entryHash: computeEntryHash(r) },
  });

  const applicability: RelationApplicability =
    { R_byte: false, R_interop: true, R_ser: false, R_val: true, R_err: false, R_cap: false };
  const agg = aggregateMutationClass(applicability, [inst], [valObs]);

  assert.equal(agg.observedSpectrum.R_val, 'fail', 'the evidence that was being discarded survives');
  assert.equal(agg.observedSpectrum.R_interop, undefined, 'and no cell is fabricated for it');
  assert.equal(agg.nonScoreable.length, 1);
  assert.equal(agg.nonScoreable[0]!.cause, 'contractually-non-eligible',
    'the cause is normative, not environmental');
});

test('M3-H11: with one eligible sibling instance, the class is scored and the non-eligible one is simply excluded', () => {
  // The partial case already works, which is what localises the gap: the
  // defect is not in the `continue` but in the class-level counter that
  // follows it.
  const eligibleR = resolveInteropEligibility('GCM-AUTHENTICATION-BYPASS', 'TAG-TAMPER');
  const passObs = obsFor(interopScope(), 'pass', 'R_interop');
  const eligibleInst = makeMutationInstanceResult({
    mutationId: 'M', stimulusInstanceId: 'eligible', operation: 'gcm',
    planned: [{ relation: 'R_interop', scope: interopScope(), executability: { kind: 'required' } }],
    observations: [passObs],
    interopEligibility: { value: eligibleR.eligibility, source: eligibleR.source, entryHash: computeEntryHash(eligibleR) },
  });
  const blockedR = resolveInteropEligibility('GCM-KEY-PROFILE-BOUNDARY-BYPASS', 'default');
  const blockedInst = makeMutationInstanceResult({
    mutationId: 'M', stimulusInstanceId: 'blocked', operation: 'gcm',
    planned: [{ relation: 'R_interop', scope: interopScope(), executability: { kind: 'required' } }],
    observations: [],
    interopEligibility: { value: blockedR.eligibility, source: blockedR.source, entryHash: computeEntryHash(blockedR) },
  });

  const applicability: RelationApplicability =
    { R_byte: false, R_interop: true, R_ser: false, R_val: false, R_err: false, R_cap: false };
  // Without connection 4 this would have thrown AggregationIncompleteError
  // on the blocked instance's own missing observation.
  const { observedSpectrum } = aggregateMutationClass(applicability, [eligibleInst, blockedInst], [passObs]);
  assert.equal(observedSpectrum.R_interop, 'pass');
});

test('connection 4: H7 keeps its own CAUSE for an ELIGIBLE instance with no executable scope', () => {
  // Same structural shape, opposite cause. Here the relation DID carry an
  // obligation and the environment could not support it -- a real loss of
  // support, which must still refuse to fabricate a pass.
  const planned: PlannedObservation[] = [
    { relation: 'R_interop', scope: interopScope(), executability: { kind: 'structurally-not-executable', reason: 'backend-capability-absent' } },
  ];
  const r = resolveInteropEligibility('GCM-AUTHENTICATION-BYPASS', 'TAG-TAMPER');
  assert.equal(r.eligibility.kind, 'eligible');
  const inst = makeMutationInstanceResult({
    mutationId: 'GCM-AUTHENTICATION-BYPASS', stimulusInstanceId: 'TAG-TAMPER', operation: 'gcm',
    planned, observations: [],
    interopEligibility: { value: r.eligibility, source: r.source, entryHash: computeEntryHash(r) },
  });
  const applicability: RelationApplicability =
    { R_byte: false, R_interop: true, R_ser: false, R_val: false, R_err: false, R_cap: false };
  // Same structural shape as the test above, opposite cause -- and that is
  // the whole point of keeping two causes rather than one. Here the relation
  // DID carry an obligation and the environment could not support it.
  const agg = aggregateMutationClass(applicability, [inst], []);
  assert.equal(agg.nonScoreable[0]!.cause, 'zero-executable-support');
  assert.equal(agg.observedSpectrum.R_interop, undefined, 'still never a vacuous pass');
});

test('connection 4: an eligible instance still votes, and a fail is still fail-dominant', () => {
  const planned: PlannedObservation[] = [
    { relation: 'R_interop', scope: interopScope(), executability: { kind: 'required' } },
    { relation: 'R_interop', scope: interopScope(CHROMIUM_WEBCRYPTO, BOUNCY_CASTLE), executability: { kind: 'required' } },
  ];
  const a = obsFor(interopScope(), 'pass', 'R_interop');
  const b = obsFor(interopScope(CHROMIUM_WEBCRYPTO, BOUNCY_CASTLE), 'fail', 'R_interop');
  const r = resolveInteropEligibility('GCM-AUTHENTICATION-BYPASS', 'IV-TAMPER');
  const inst = makeMutationInstanceResult({
    mutationId: 'GCM-AUTHENTICATION-BYPASS', stimulusInstanceId: 'IV-TAMPER', operation: 'gcm',
    planned, observations: [a, b],
    interopEligibility: { value: r.eligibility, source: r.source, entryHash: computeEntryHash(r) },
  });
  const applicability: RelationApplicability =
    { R_byte: false, R_interop: true, R_ser: false, R_val: false, R_err: false, R_cap: false };
  const { observedSpectrum } = aggregateMutationClass(applicability, [inst], [a, b]);
  assert.equal(observedSpectrum.R_interop, 'fail', 'M3-H1b still holds: a real fail is not hidden behind an earlier pass');
});

test('connection 4: aggregation reads the RECORDED decision, never re-resolves the registry', () => {
  // A hand-built instance declaring itself non-eligible is honoured even
  // though the registry says the class is eligible. That is the point: a
  // later registry change must not retroactively reinterpret evidence
  // already produced -- the same rule Required already follows by reading
  // coverage.planned instead of re-invoking the planner.
  const registryValue = resolveInteropEligibility('GCM-AUTHENTICATION-BYPASS', 'TAG-TAMPER');
  assert.equal(registryValue.eligibility.kind, 'eligible');

  const passObs = obsFor(interopScope(), 'pass', 'R_interop');
  const sibling = makeMutationInstanceResult({
    mutationId: 'GCM-AUTHENTICATION-BYPASS', stimulusInstanceId: 'IV-TAMPER', operation: 'gcm',
    planned: [{ relation: 'R_interop', scope: interopScope(), executability: { kind: 'required' } }],
    observations: [passObs],
    interopEligibility: { value: registryValue.eligibility, source: registryValue.source, entryHash: computeEntryHash(registryValue) },
  });
  // Same class, same registry verdict (eligible), but this instance RECORDS
  // non-eligible. Its missing observation must not raise
  // AggregationIncompleteError, because the recorded decision governs.
  const declaresNonEligible = makeMutationInstanceResult({
    mutationId: 'GCM-AUTHENTICATION-BYPASS', stimulusInstanceId: 'TAG-TAMPER', operation: 'gcm',
    planned: [{ relation: 'R_interop', scope: interopScope(), executability: { kind: 'required' } }],
    observations: [],
    interopEligibility: {
      value: { kind: 'non-eligible', reason: 'no-operational-input' },
      source: 'class-default', entryHash: 'recorded-at-run-time',
    },
  });
  const applicability: RelationApplicability =
    { R_byte: false, R_interop: true, R_ser: false, R_val: false, R_err: false, R_cap: false };
  const { observedSpectrum } = aggregateMutationClass(applicability, [sibling, declaresNonEligible], [passObs]);
  assert.equal(observedSpectrum.R_interop, 'pass', 'the recorded decision governs, not a re-resolution');
});

// ---------------------------------------------------------------------
// M3-H10 -- the divergence connection 4 exposes, pinned rather than papered over
// ---------------------------------------------------------------------

test('M3-H10 RESOLVED: completeness and aggregation now agree about a non-eligible pair', () => {
  // Inverted deliberately by M3-H11.4-Core.3. This test previously pinned
  // the divergence: aggregation treated the pair as outside S_interop(c)
  // while the completeness gate still listed the same scope as an
  // outstanding REQUIREMENT, so the instance could never be complete.
  //
  //     before:  aggregation excuses it, completeness demands it
  //     after:   Required = Applicable & Eligible & Executable, so neither does
  //
  // The plan is NOT pruned to achieve this: the scope remains planned and
  // its executability remains 'required'. Only the obligation changed.
  const planned: PlannedObservation[] = [
    { relation: 'R_interop', scope: interopScope(), executability: { kind: 'required' } },
  ];
  const inst = instanceFor('GCM-PROVIDER-CAPABILITY-MISMATCH', 'default', planned);
  assert.equal(inst.interopEligibility!.value.kind, 'non-eligible');
  assert.equal(inst.complete, true);
  assert.equal(inst.coverage.outstanding.length, 0);
  assert.equal(inst.coverage.planned.length, 1, 'the ledger still records that it was planned');
  assert.equal(inst.coverage.planned[0]!.executability.kind, 'required',
    'and that the scope itself was executable -- Planned != Required');
});

test('the 124 observations across 26 pairs remain PLANNED, and are no longer obligations', () => {
  let pairs = 0, observations = 0;
  for (const c of plan.classes) {
    for (const si of c.stimulusInstances) {
      if (si.interopEligibility?.value.kind !== 'non-eligible') continue;
      pairs += 1;
      observations += si.executability.filter(
        (x) => x.relation === 'R_interop' && x.state.kind === 'required').length;
    }
  }
  assert.equal(pairs, 26);
  assert.equal(observations, 124);
});
