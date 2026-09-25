import { test } from 'node:test';
import assert from 'node:assert/strict';

import {
  assembleStructuralPlan, planCardinality, zeroSupportInstances, zeroSupportRelations,
  PLAN_BACKENDS,
} from '../../../harness/phase-c/plan-assembly.js';
import { loadFrozenMaterialPool } from '../../../harness/phase-c/material/load.js';
import { planObservations } from '../../../harness/capability/observation-planner.js';
import { APPLICABILITY_MATRIX } from '../../../harness/applicability/matrix.js';
import { scopeEquals } from '../../../harness/evidence/observation-scope.js';
import { CHROMIUM_WEBCRYPTO, CRYPTOPP, BOUNCY_CASTLE } from '../../../harness/schema/backend-identity.js';

const pool = loadFrozenMaterialPool();
const plan = assembleStructuralPlan(pool);

// ---------------------------------------------------------------------
// M3-H8 -- Phase-C R_byte Scope Semantics Mismatch.
//
// planObservations materialised R_byte in Phase C as three single-backend
// scopes, comparing Baseline_p against Mutated_p. The frozen design
// (Harness v0.26, sec:5.12) states the opposite: R_byte uses one evaluator
// under two scope kinds, one per phase --
//     single-backend -> Phase A, same-backend repeatability
//     backend set    -> Phase B/C, cross-provider byte equality
// so Phase C must compare Bytes(y_{p,s}) =? Bytes(y_{q,s}) for the SAME
// stimulus instance. The mutation is the common stimulus both providers
// receive, never one side of the comparison.
//
// Direction is discarded for R_byte and load-bearing for R_interop, hence
//     R_byte    : C(P,2) unordered sets      = 3
//     R_interop : P*(P-1) directed pairs     = 6
// ---------------------------------------------------------------------

// --- Corrected quantitative gate ------------------------------------------

test('M3-H8: 79 classes, 90 stimulus instances, 1641 planned observations -- the instrument size is UNCHANGED', () => {
  const c = planCardinality(plan);
  assert.equal(c.classes, 79);
  assert.equal(c.stimulusInstances, 90);
  assert.equal(c.plannedObservations, 1641,
    'H8 corrects the identity and semantics of 186 R_byte observations, it does not add or remove any');
});

test('M3-H8: 1641 = 1499 required-state + 142 structurally-not-executable', () => {
  const c = planCardinality(plan);
  assert.equal(c.required, 1499);
  assert.equal(c.notExecutable, 142);
  assert.equal(c.required + c.notExecutable, 1641);
});

test('M3-H8: the -3 comes only from stimuli with fewer than three executable providers', () => {
  // C(k,2) vs k: equal at k=3 and k=0, one fewer at k=2 and at k=1.
  // + 0 normalises -0, which strictEqual would otherwise reject.
  const delta = (k: number) => (k * (k - 1)) / 2 - k + 0;
  assert.equal(delta(3) === 0, true);
  assert.equal(delta(2), -1);
  assert.equal(delta(1), -1);
  assert.equal(delta(0) === 0, true);
});

// --- Semantic scope invariants --------------------------------------------

test('M3-H8: every R_byte scope is a cross-backend-set of exactly two distinct providers', () => {
  let seen = 0;
  for (const cls of plan.classes) {
    for (const e of cls.entries) {
      if (e.relation !== 'R_byte') continue;
      seen += 1;
      assert.equal(e.scope.kind, 'cross-backend-set', cls.mutationId);
      if (e.scope.kind === 'cross-backend-set') {
        assert.equal(e.scope.backends.length, 2);
        assert.notEqual(e.scope.backends[0]!.sourcePin, e.scope.backends[1]!.sourcePin, 'two DISTINCT providers');
      }
    }
  }
  // Counted over the 79 CLASS entry sets, not over the 90 instances -- the
  // two are different magnitudes and both are pinned, below.
  assert.equal(seen, 156, 'R_byte applies to four of the six operations');
});

test('M3-H8: every R_interop scope remains a directed backend-pair -- direction is untouched', () => {
  let seen = 0;
  for (const cls of plan.classes) {
    for (const e of cls.entries) {
      if (e.relation !== 'R_interop') continue;
      seen += 1;
      assert.equal(e.scope.kind, 'backend-pair', cls.mutationId);
    }
  }
  assert.equal(seen, 426, 'per-class entries; the per-instance figure is pinned separately');
});

test('M3-H8: per-INSTANCE observation counts, which is what the 1641 total is made of', () => {
  const perRelation = new Map<string, number>();
  for (const cls of plan.classes) {
    for (const si of cls.stimulusInstances) {
      for (const x of si.executability) perRelation.set(x.relation, (perRelation.get(x.relation) ?? 0) + 1);
    }
  }
  assert.equal(perRelation.get('R_byte'), 186);
  assert.equal(perRelation.get('R_interop'), 486);
  assert.equal(perRelation.get('R_ser'), 159);
  assert.equal(perRelation.get('R_val'), 270);
  assert.equal(perRelation.get('R_err'), 270);
  assert.equal(perRelation.get('R_cap'), 270);
  assert.equal([...perRelation.values()].reduce((a, b) => a + b, 0), 1641);
});

test('M3-H8: the other four relations keep their own scopes', () => {
  const kinds = new Map<string, Set<string>>();
  for (const cls of plan.classes) {
    for (const e of cls.entries) {
      if (!kinds.has(e.relation)) kinds.set(e.relation, new Set());
      kinds.get(e.relation)!.add(e.scope.kind);
    }
  }
  assert.deepEqual([...kinds.get('R_ser')!], ['single-backend']);
  assert.deepEqual([...kinds.get('R_val')!], ['single-backend']);
  assert.deepEqual([...kinds.get('R_err')!], ['single-backend']);
  assert.deepEqual([...kinds.get('R_cap')!], ['manifest']);
});

test('M3-H8: exactly 3 R_byte scopes per applicable class, with no reverse duplicates', () => {
  for (const cls of plan.classes) {
    if (!APPLICABILITY_MATRIX[cls.operation]!.R_byte) continue;
    const byteScopes = cls.entries.filter((e) => e.relation === 'R_byte');
    assert.equal(byteScopes.length, 3, cls.mutationId);

    // {A,B} and {B,A} are the SAME scope by type, so scopeEquals catches a
    // reverse duplicate without needing a separate canonicalisation rule.
    for (let i = 0; i < byteScopes.length; i++) {
      for (let j = i + 1; j < byteScopes.length; j++) {
        assert.ok(!scopeEquals(byteScopes[i]!.scope, byteScopes[j]!.scope),
          `${cls.mutationId}: duplicate R_byte scope`);
      }
    }
  }
});

test('M3-H8: {A,B} and {B,A} are the same scope -- unordered by TYPE, not by convention', () => {
  const ab = { kind: 'cross-backend-set' as const, backends: [CHROMIUM_WEBCRYPTO, CRYPTOPP] };
  const ba = { kind: 'cross-backend-set' as const, backends: [CRYPTOPP, CHROMIUM_WEBCRYPTO] };
  assert.ok(scopeEquals(ab, ba));
  // Whereas a directed pair is not.
  const dirAb = { kind: 'backend-pair' as const, from: CHROMIUM_WEBCRYPTO, to: CRYPTOPP };
  const dirBa = { kind: 'backend-pair' as const, from: CRYPTOPP, to: CHROMIUM_WEBCRYPTO };
  assert.ok(!scopeEquals(dirAb, dirBa));
});

test('M3-H8: the three R_byte sets are exactly the three unordered pairs of the pinned providers', () => {
  const cls = plan.classes.find((c) => APPLICABILITY_MATRIX[c.operation]!.R_byte)!;
  const expected = [
    [CHROMIUM_WEBCRYPTO, CRYPTOPP], [CHROMIUM_WEBCRYPTO, BOUNCY_CASTLE], [CRYPTOPP, BOUNCY_CASTLE],
  ].map((b) => ({ kind: 'cross-backend-set' as const, backends: b }));
  const actual = cls.entries.filter((e) => e.relation === 'R_byte').map((e) => e.scope);
  for (const want of expected) {
    assert.equal(actual.filter((s) => scopeEquals(s, want)).length, 1);
  }
  assert.equal(PLAN_BACKENDS.length, 3);
});

test('M3-H8: generation is combinatorial -- four providers would give six R_byte sets, not three', () => {
  const FOURTH = { ...BOUNCY_CASTLE, family: 'fourth', sourcePin: 'fourth-pin' };
  const { planned } = planObservations(
    'gcm', APPLICABILITY_MATRIX['gcm']!, [CHROMIUM_WEBCRYPTO, CRYPTOPP, BOUNCY_CASTLE, FOURTH as never],
  );
  const byte = planned.filter((p) => p.relation === 'R_byte');
  assert.equal(byte.length, 6, 'C(4,2) = 6; the three pairs are not written by hand');
  const interop = planned.filter((p) => p.relation === 'R_interop');
  assert.equal(interop.length, 12, 'and R_interop stays P*(P-1) = 12');
});

// --- Executability under the corrected scope ------------------------------

test('M3-H8: R_byte executability is relation-local and every structural refusal retains the capability cause', () => {
  let required = 0;
  let nonExecutable = 0;

  for (const cls of plan.classes) {
    for (const si of cls.stimulusInstances) {
      for (const x of si.executability) {
        if (x.relation !== 'R_byte') continue;

        assert.equal(x.scope.kind, 'cross-backend-set');

        if (x.state.kind === 'required') {
          required += 1;
        } else {
          nonExecutable += 1;
          assert.equal(x.state.reason, 'backend-capability-absent');
        }
      }
    }
  }

  assert.equal(required + nonExecutable, 186);
  assert.ok(required > 0);
  assert.ok(nonExecutable > 0);
});

// --- H7 gate under the corrected semantics --------------------------------

test('M3-H8: 8 instance-level zero-support cases after the reopen', () => {
  const cases = zeroSupportInstances(plan);
  assert.equal(cases.length, 8);
  assert.deepEqual(cases.map((c) => `${c.mutationId}::${c.stimulusInstanceId}::${c.relation}`), [
    'GCM-TAGLENGTH-PROFILE-BOUNDARY-BYPASS::tagLength-below-floor-0::R_byte',
    'GCM-TAGLENGTH-PROFILE-BOUNDARY-BYPASS::tagLength-below-floor-0::R_interop',
    'GCM-TAGLENGTH-PROFILE-BOUNDARY-BYPASS::tagLength-below-floor-16::R_byte',
    'GCM-TAGLENGTH-PROFILE-BOUNDARY-BYPASS::tagLength-below-floor-16::R_interop',
    'OAEP-KEY-ROLE-BYPASS::decrypt-with-public::R_interop',
    'OAEP-MGF-COUPLING-BYPASS::default::R_interop',
    'PSS-MGF-COUPLING-BYPASS::default::R_interop',
    'PSS-SALT-BYTES-INTERFACE-LEAK::default::R_interop',
  ]);
  // The two new ones exist because a cross-provider byte comparison is
  // impossible with a single executable provider: C(1,2) = 0. Under the old
  // single-backend materialisation these counted as required and would have
  // produced evidence -- for a different relation than the frozen one.
  assert.equal(cases.filter((c) => c.relation === 'R_byte').length, 2);
  assert.equal(cases.filter((c) => c.relation === 'R_interop').length, 6);
});

test('M3-H8: class-level unscorable stays at 3 -- tagLength-80 keeps R_byte supported', () => {
  const classLevel = zeroSupportRelations(plan);
  assert.equal(classLevel.length, 3);
  assert.deepEqual(classLevel.map((c) => `${c.mutationId}::${c.relation}`), [
    'OAEP-MGF-COUPLING-BYPASS::R_interop',
    'PSS-MGF-COUPLING-BYPASS::R_interop',
    'PSS-SALT-BYTES-INTERFACE-LEAK::R_interop',
  ]);

  // tagLength-80 has k = 2, so C(2,2) = 1 supporting R_byte scope: the class
  // is instance-level twice yet class-level never, for R_byte as for R_interop.
  const cls = plan.classes.find((c) => c.mutationId === 'GCM-TAGLENGTH-PROFILE-BOUNDARY-BYPASS')!;
  const supporting = cls.stimulusInstances.filter((si) =>
    si.executability.some((x) => x.relation === 'R_byte' && x.state.kind === 'required'));
  assert.equal(supporting.length, 1);
  assert.equal(supporting[0]!.stimulusInstanceId, 'tagLength-80');
});

// --- Nothing else was contaminated ----------------------------------------

test('M3-H8: applicability, class count and stimulus pairs are untouched', () => {
  for (const cls of plan.classes) {
    assert.deepEqual(cls.applicability, APPLICABILITY_MATRIX[cls.operation]);
  }
  assert.equal(plan.classes.length, 79);
  assert.equal(plan.classes.reduce((n, c) => n + c.stimulusInstances.length, 0), 90);
});

test('M3-H8: inputsEquivalent is NOT wired here -- premise materialisation belongs to b-3.6', async () => {
  const { readFileSync } = await import('node:fs');
  for (const file of ['../../../harness/phase-c/plan-assembly.ts', '../../../harness/capability/observation-planner.ts']) {
    const src = readFileSync(new URL(file, import.meta.url), 'utf8');
    assert.ok(!src.includes('inputsEquivalent'), `${file} must not materialise the premise yet`);
  }
});
