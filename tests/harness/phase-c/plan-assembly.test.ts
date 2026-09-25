import { test } from 'node:test';
import assert from 'node:assert/strict';

import {
  FIXTURE_INDEX, getFixtureResolver, indexedPairKeys, pairKey, FixtureIndexError,
} from '../../../harness/phase-c/fixture-index.js';
import {
  assembleStructuralPlan, planCardinality, zeroSupportInstances, zeroSupportRelations,
  PLAN_BACKENDS, PlanAssemblyError,
} from '../../../harness/phase-c/plan-assembly.js';
import { loadFrozenMaterialPool } from '../../../harness/phase-c/material/load.js';
import { MUTATION_REGISTRY } from '../../../harness/registry/mutations.js';
import { APPLICABILITY_MATRIX } from '../../../harness/applicability/matrix.js';
import { MUTATION_INDEX } from '../../../harness/phase-c/mutation-index.js';
import { scopeEquals } from '../../../harness/evidence/observation-scope.js';

const pool = loadFrozenMaterialPool();
const plan = assembleStructuralPlan(pool);

// ---------------------------------------------------------------------
// M3.2.4b-3.5 -- FIXTURE_INDEX + structural ExecutionPlan assembly.
//
// The gate asserts what the plan IS, never what it will score: no claim
// about pass/fail appears here, since relation evaluation is b-3.6's work.
//     plan structurally complete  AND  NOT scientifically executable yet
// ---------------------------------------------------------------------

// --- FIXTURE_INDEX exactness ---------------------------------------------

test('b-3.5: Keys(FIXTURE_INDEX) = RegistryPairs, |Keys| = 90', () => {
  const registry = MUTATION_REGISTRY
    .flatMap((e) => e.stimulusInstances.map((si) => pairKey(e.mutationId, si.stimulusInstanceId)))
    .sort();
  assert.equal(registry.length, 90);
  assert.deepEqual(indexedPairKeys(), registry);
  assert.equal(FIXTURE_INDEX.size, 90);
});

test('b-3.5: the difference is empty in BOTH directions', () => {
  const registry = new Set(MUTATION_REGISTRY
    .flatMap((e) => e.stimulusInstances.map((si) => pairKey(e.mutationId, si.stimulusInstanceId))));
  const indexed = new Set(indexedPairKeys());
  assert.deepEqual([...registry].filter((k) => !indexed.has(k)), [], 'no registry pair lacks a resolver');
  assert.deepEqual([...indexed].filter((k) => !registry.has(k)), [], 'no resolver serves a pair that cannot be scored');
});

test('b-3.5: exactly one resolver per pair, and an unknown pair fails closed', () => {
  for (const e of MUTATION_REGISTRY) {
    for (const si of e.stimulusInstances) {
      assert.doesNotThrow(() => getFixtureResolver(e.mutationId, si.stimulusInstanceId));
    }
  }
  assert.throws(() => getFixtureResolver('NO-SUCH-MUTATION', 'default'), FixtureIndexError);
  assert.throws(() => getFixtureResolver(MUTATION_REGISTRY[0]!.mutationId, 'no-such-stimulus'), FixtureIndexError);
});

test('b-3.5: the index is built by composition -- no mutationId literal in its source', async () => {
  const { readFileSync } = await import('node:fs');
  const src = readFileSync(new URL('../../../harness/phase-c/fixture-index.ts', import.meta.url), 'utf8');
  for (const e of MUTATION_REGISTRY) {
    assert.ok(!src.includes(`'${e.mutationId}'`), `found a hard-coded id: ${e.mutationId}`);
  }
});

// --- Structural cardinalities ---------------------------------------------

test('b-3.5: 79 classes, 90 stimulus instances, 1641 planned observations', () => {
  const c = planCardinality(plan);
  assert.equal(c.classes, 79);
  assert.equal(c.stimulusInstances, 90);
  assert.equal(c.plannedObservations, 1641);
});

test('b-3.5: 1641 = 1499 required-state + 142 structurally-not-executable', () => {
  // Corrected by M3-H8: R_byte's Phase C scope is a cross-provider pair, so
  // its executability is C(k,2) rather than k. The observation TOTAL is
  // unchanged; only the required/NX split moved.
  const c = planCardinality(plan);
  assert.equal(c.required, 1499);
  assert.equal(c.notExecutable, 142);
  assert.equal(c.required + c.notExecutable, c.plannedObservations);
});

test('b-3.5: sum over classes of |entries| x |stimuli| equals the observation total', () => {
  let total = 0;
  for (const cls of plan.classes) total += cls.entries.length * cls.stimulusInstances.length;
  assert.equal(total, 1641);
});

// --- The H6 invariant ------------------------------------------------------

test('b-3.5: forall (c,s): Keys(ExecMap_{c,s}) = Entries_c -- same count, same pairs, no duplicates', () => {
  for (const cls of plan.classes) {
    for (const si of cls.stimulusInstances) {
      assert.equal(si.executability.length, cls.entries.length, `${cls.mutationId}::${si.stimulusInstanceId}`);
      for (const entry of cls.entries) {
        const matches = si.executability.filter(
          (x) => x.relation === entry.relation && scopeEquals(x.scope, entry.scope));
        assert.equal(matches.length, 1, `${cls.mutationId}::${si.stimulusInstanceId} (${entry.relation})`);
      }
    }
  }
});

test('b-3.5: scopes are class-invariant -- every stimulus of a class sees the same entry set', () => {
  for (const cls of plan.classes) {
    if (cls.stimulusInstances.length < 2) continue;
    const reference = cls.stimulusInstances[0]!.executability.map((x) => x.relation).join('|');
    for (const si of cls.stimulusInstances) {
      assert.equal(si.executability.map((x) => x.relation).join('|'), reference, cls.mutationId);
    }
  }
});

test('b-3.5: executability genuinely varies where M3-H6 said it does', () => {
  const cls = plan.classes.find((c) => c.mutationId === 'GCM-TAGLENGTH-PROFILE-BOUNDARY-BYPASS')!;
  const signatures = new Set(cls.stimulusInstances.map((si) => si.executability.map((x) => x.state.kind).join('')));
  assert.equal(cls.stimulusInstances.length, 3);
  assert.equal(signatures.size, 2, 'the class-level representation could not have expressed this');
});

// --- Normative sources are consumed, not reinvented -----------------------

test('b-3.5: applicability comes from the normative matrix, per operation', () => {
  for (const cls of plan.classes) {
    assert.deepEqual(cls.applicability, APPLICABILITY_MATRIX[cls.operation], cls.mutationId);
  }
});

test('b-3.5: every class carries its own registry expectedSpectrum and indexed implementation', () => {
  for (const cls of plan.classes) {
    const entry = MUTATION_REGISTRY.find((e) => e.mutationId === cls.mutationId)!;
    assert.deepEqual(cls.expectedSpectrum, entry.expectedSpectrum);
    assert.equal(cls.operation, entry.operation);
    assert.equal(cls.mutation, MUTATION_INDEX.get(cls.mutationId), 'the same implementation object, not a copy');
    assert.equal(cls.stimulusInstances.length, entry.stimulusInstances.length);
  }
});

test('b-3.5: three backends are pinned, and every scope refers only to them', () => {
  assert.equal(PLAN_BACKENDS.length, 3);
  const pins = new Set(PLAN_BACKENDS.map((b) => b.sourcePin));
  for (const cls of plan.classes) {
    for (const e of cls.entries) {
      const s = e.scope;
      if (s.kind === 'backend-pair') {
        assert.ok(pins.has(s.from.sourcePin) && pins.has(s.to.sourcePin));
      } else if (s.kind === 'single-backend' || s.kind === 'manifest') {
        assert.ok(pins.has(s.backend.sourcePin));
      }
    }
  }
});

test('b-3.5: every stimulus carries a materialised baseFixture', () => {
  for (const cls of plan.classes) {
    for (const si of cls.stimulusInstances) {
      assert.notEqual(si.baseFixture, undefined, `${cls.mutationId}::${si.stimulusInstanceId}`);
      assert.notEqual(si.baseFixture, null);
    }
  }
});

// --- The H7 gate: two levels, deliberately distinct -----------------------

test('b-3.5 (H7): exactly 8 instance-level zero-support cases, across TWO pair relations', () => {
  // Corrected by M3-H8: R_byte became a pair relation too, so it can now
  // reach zero support for the same structural reason R_interop already did.
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
  // Both are relations over PAIRS of providers: a single executable provider
  // yields C(1,2) = 0 sets and 1*0 = 0 directions. No single-backend or
  // manifest relation can reach zero, since one executable provider suffices.
  assert.deepEqual([...new Set(cases.map((c) => c.relation))].sort(), ['R_byte', 'R_interop']);
});

test('b-3.5 (H7): exactly 3 CLASS-level unscorable relations -- a strict subset of the 5', () => {
  const classLevel = zeroSupportRelations(plan);
  assert.equal(classLevel.length, 3);
  assert.deepEqual(classLevel.map((c) => `${c.mutationId}::${c.relation}`), [
    'OAEP-MGF-COUPLING-BYPASS::R_interop',
    'PSS-MGF-COUPLING-BYPASS::R_interop',
    'PSS-SALT-BYTES-INTERFACE-LEAK::R_interop',
  ]);

  // The tag-length class is instance-level TWICE yet class-level NEVER,
  // because its third stimulus does support R_interop. Conflating the two
  // levels would either lose a real result or fabricate an unscorable one.
  const instanceLevel = new Set(zeroSupportInstances(plan).map((c) => c.mutationId));
  assert.ok(instanceLevel.has('GCM-TAGLENGTH-PROFILE-BOUNDARY-BYPASS'));
  assert.ok(!classLevel.some((c) => c.mutationId === 'GCM-TAGLENGTH-PROFILE-BOUNDARY-BYPASS'));
  for (const c of classLevel) assert.ok(instanceLevel.has(c.mutationId), 'class-level implies instance-level');
});

test('b-3.5 (H7): the tag-length class keeps exactly one supporting stimulus for R_interop', () => {
  const cls = plan.classes.find((c) => c.mutationId === 'GCM-TAGLENGTH-PROFILE-BOUNDARY-BYPASS')!;
  const supporting = cls.stimulusInstances.filter((si) =>
    si.executability.some((x) => x.relation === 'R_interop' && x.state.kind === 'required'));
  assert.equal(supporting.length, 1);
  assert.equal(supporting[0]!.stimulusInstanceId, 'tagLength-80');
});

// --- What this step deliberately does NOT deliver -------------------------

test('b-3.5: the structural plan has NO resolve callback -- a fake one is unconstructible', async () => {
  const { readFileSync } = await import('node:fs');
  const src = readFileSync(new URL('../../../harness/phase-c/plan-assembly.ts', import.meta.url), 'utf8');
  // No structural type declares `resolve`, so no stub can be supplied here.
  assert.ok(!/^\s*readonly resolve/m.test(src), 'the structural types must not carry a resolve field');
  for (const cls of plan.classes) {
    for (const e of cls.entries) {
      assert.ok(!('resolve' in e), 'a structural entry must not carry a callback');
    }
  }
});

test('b-3.5: assembly is deterministic -- two runs agree on every cardinality', () => {
  const again = assembleStructuralPlan(pool);
  assert.deepEqual(planCardinality(again), planCardinality(plan));
  assert.deepEqual(zeroSupportInstances(again), zeroSupportInstances(plan));
  assert.deepEqual(zeroSupportRelations(again), zeroSupportRelations(plan));
});

test('b-3.5: assembly performs no cryptography and no generation', async () => {
  const { readFileSync } = await import('node:fs');
  const src = readFileSync(new URL('../../../harness/phase-c/plan-assembly.ts', import.meta.url), 'utf8');
  for (const forbidden of ['webcrypto', 'subtle', 'generateKey', 'randomBytes', 'createHash']) {
    assert.ok(!src.includes(forbidden), `found '${forbidden}'`);
  }
  assert.ok(PlanAssemblyError !== undefined);
});

// ---------------------------------------------------------------------
// M3-H9.3a-3.1 -- a planned non-execution carries its REASON.
//
// The plan could previously say THAT an observation was not executable but
// never WHY. Adequate while M3-H6's capability cause was the only one; the
// R_interop eligibility audit found a second, contract-derived cause. Both
// are known before execution, so leaving the reason to the evidence layer
// would let the run discover what the protocol already knows.
// ---------------------------------------------------------------------

test('M3-H9.3a-3.1: every planned executability is a discriminated union, never a bare string', () => {
  for (const cls of plan.classes) {
    for (const si of cls.stimulusInstances) {
      for (const x of si.executability) {
        assert.equal(typeof x.state, 'object', `${cls.mutationId}: state must carry a discriminant`);
        assert.ok(x.state.kind === 'required' || x.state.kind === 'structurally-not-executable');
      }
    }
  }
});

test('M3-H9.3a-3.1: a non-executable entry always states a reason; a required one never does', () => {
  let withReason = 0;
  for (const cls of plan.classes) {
    for (const si of cls.stimulusInstances) {
      for (const x of si.executability) {
        if (x.state.kind === 'structurally-not-executable') {
          assert.ok(x.state.reason.length > 0, `${cls.mutationId}: missing reason`);
          withReason += 1;
        } else {
          assert.ok(!('reason' in x.state), 'a required entry must not carry a reason');
        }
      }
    }
  }
  assert.equal(withReason, 142, 'every one of the 142 non-executable observations is now explained');
});

test('M3-H9.3a-3.1: the vocabulary is the frozen NonExecution.reason, not a parallel one', () => {
  // Reusing it verbatim is what lets a planned non-execution map onto its
  // evidence counterpart without translation.
  const frozen = new Set(['backend-capability-absent', 'stimulus-not-expressible', 'direction-not-materializable']);
  for (const cls of plan.classes) {
    for (const si of cls.stimulusInstances) {
      for (const x of si.executability) {
        if (x.state.kind === 'structurally-not-executable') assert.ok(frozen.has(x.state.reason));
      }
    }
  }
});

test('M3-H9.3a-3.1: the reopened plan uses exactly the three frozen non-execution reasons', () => {
  const reasons = new Set<string>();
  for (const cls of plan.classes) {
    for (const si of cls.stimulusInstances) {
      for (const x of si.executability) {
        if (x.state.kind === 'structurally-not-executable') reasons.add(x.state.reason);
      }
    }
  }
  assert.deepEqual([...reasons].sort(), [
    'backend-capability-absent',
    'direction-not-materializable',
    'stimulus-not-expressible',
  ]);
});
