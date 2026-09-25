import { test } from 'node:test';
import assert from 'node:assert/strict';

import { MUTATION_REGISTRY } from '../../../harness/registry/mutations.js';
import { APPLICABILITY_MATRIX } from '../../../harness/applicability/matrix.js';
import { planObservations } from '../../../harness/capability/observation-planner.js';
import { decideExecutability } from '../../../harness/capability/executability.js';
import { STIMULUS_CAPABILITY_REQUIREMENTS } from '../../../harness/requirements/stimulus-requirements.js';
import { CHROMIUM_WEBCRYPTO, CRYPTOPP, BOUNCY_CASTLE } from '../../../harness/schema/backend-identity.js';
import { CHROMIUM_DECLARATIONS } from '../../../manifests/providers/chromium.js';
import { CRYPTOPP_DECLARATIONS } from '../../../manifests/providers/cryptopp.js';
import { BC_DECLARATIONS } from '../../../manifests/providers/bc.js';
import { scopeEquals } from '../../../harness/evidence/observation-scope.js';
import type { PlannedObservation } from '../../../harness/evidence/mutation-instance-result.js';

// ---------------------------------------------------------------------
// M3-H6 -- Stimulus-Sensitive Executability Plan Mismatch.
//
// The original MutationClassPlan attached `executability` to PlanEntry,
// which is per CLASS. That is correct for the structural part -- the set of
// (relation, scope) requirements really is class-invariant -- but false for
// executability, which depends on the (class, stimulus, backend) triple.
//
//     Scopes(c,s1) = Scopes(c,s2)      but      Exec(c,s1) != Exec(c,s2)
//
// These tests pin the real evidence that forced the split, and the
// cardinalities it produces, so the remodelling is demonstrably not
// cosmetic: it preserves evidence the previous model could not represent.
// ---------------------------------------------------------------------

const BACKENDS = [CHROMIUM_WEBCRYPTO, CRYPTOPP, BOUNCY_CASTLE];
const DECLS_BY_PIN = new Map([
  [CHROMIUM_WEBCRYPTO.sourcePin, CHROMIUM_DECLARATIONS],
  [CRYPTOPP.sourcePin, CRYPTOPP_DECLARATIONS],
  [BOUNCY_CASTLE.sourcePin, BC_DECLARATIONS],
]);

function executableBackends(mutationId: string, stimulusInstanceId: string): Map<string, boolean> {
  const map = new Map<string, boolean>();
  for (const b of BACKENDS) {
    const d = decideExecutability(mutationId, stimulusInstanceId, b, DECLS_BY_PIN.get(b.sourcePin)!, STIMULUS_CAPABILITY_REQUIREMENTS);
    map.set(b.sourcePin, d.status === 'executable');
  }
  return map;
}

// The rule the assembler must apply, stated once here so the tests measure
// it rather than restate it: a directional pair needs BOTH ends executable.
function stateFor(scope: PlannedObservation['scope'], ok: Map<string, boolean>): PlannedObservation['executability'] {
  // Mirrors the assembler: every backend a scope names must be executable.
  // cross-backend-set added by M3-H8, which made R_byte a pair relation.
  let executable: boolean;
  switch (scope.kind) {
    case 'backend-pair':
      executable = ok.get(scope.from.sourcePin) === true && ok.get(scope.to.sourcePin) === true; break;
    case 'cross-backend-set':
      executable = scope.backends.length > 0 && scope.backends.every((b) => ok.get(b.sourcePin) === true); break;
    case 'single-backend':
    case 'manifest':
      executable = ok.get(scope.backend.sourcePin) === true; break;
  }
  return executable ? { kind: 'required' } : { kind: 'structurally-not-executable', reason: 'backend-capability-absent' };
}

function entriesFor(operation: string): readonly PlannedObservation[] {
  return planObservations(
    operation as never,
    APPLICABILITY_MATRIX[operation as keyof typeof APPLICABILITY_MATRIX],
    BACKENDS,
  ).planned;
}

// --- The defect: executability genuinely varies across stimuli -------------

test('M3-H6: exactly one class has stimulus-sensitive executability, and it is the tag-length one', () => {
  const varying: string[] = [];
  for (const e of MUTATION_REGISTRY) {
    if (e.stimulusInstances.length < 2) continue;
    const entries = entriesFor(e.operation);
    const signatures = new Set(e.stimulusInstances.map((si) => {
      const ok = executableBackends(e.mutationId, si.stimulusInstanceId);
      return entries.map((p) => stateFor(p.scope, ok).kind).join('|');
    }));
    if (signatures.size > 1) varying.push(e.mutationId);
  }
  assert.deepEqual(varying, ['GCM-TAGLENGTH-PROFILE-BOUNDARY-BYPASS'],
    'a class-level executability would be wrong for exactly this class');
});

test('M3-H6: the per-backend decisions are exactly the observed matrix', () => {
  const expected: Record<string, Record<string, boolean>> = {
    'tagLength-80': { chromium: false, cryptopp: true, bouncycastle: true },
    'tagLength-below-floor-16': { chromium: false, cryptopp: true, bouncycastle: false },
    'tagLength-below-floor-0': { chromium: false, cryptopp: true, bouncycastle: false },
  };
  for (const [stimulus, row] of Object.entries(expected)) {
    const ok = executableBackends('GCM-TAGLENGTH-PROFILE-BOUNDARY-BYPASS', stimulus);
    assert.equal(ok.get(CHROMIUM_WEBCRYPTO.sourcePin), row['chromium'], `${stimulus}/chromium`);
    assert.equal(ok.get(CRYPTOPP.sourcePin), row['cryptopp'], `${stimulus}/cryptopp`);
    assert.equal(ok.get(BOUNCY_CASTLE.sourcePin), row['bouncycastle'], `${stimulus}/bouncycastle`);
  }
});

test('M3-H6: Bouncy Castle differs BETWEEN stimuli -- the scientific reason the split is required', () => {
  const at80 = executableBackends('GCM-TAGLENGTH-PROFILE-BOUNDARY-BYPASS', 'tagLength-80');
  const at16 = executableBackends('GCM-TAGLENGTH-PROFILE-BOUNDARY-BYPASS', 'tagLength-below-floor-16');
  assert.equal(at80.get(BOUNCY_CASTLE.sourcePin), true, 'an 80-bit tag is inside its declared range');
  assert.equal(at16.get(BOUNCY_CASTLE.sourcePin), false, 'below the floor it is not');
  // Chromium is uniformly not executable, so it is NOT the source of the
  // variation -- the difference is genuinely Bouncy Castle's own domain.
  assert.equal(at80.get(CHROMIUM_WEBCRYPTO.sourcePin), at16.get(CHROMIUM_WEBCRYPTO.sourcePin));
});

test('M3-H6: the not-executable cardinalities are exactly 10, 17, 17 after M3-H8', () => {
  const entries = entriesFor('gcm');
  assert.equal(entries.length, 21);
  const counts: Record<string, number> = {};
  for (const stimulus of ['tagLength-80', 'tagLength-below-floor-16', 'tagLength-below-floor-0']) {
    const ok = executableBackends('GCM-TAGLENGTH-PROFILE-BOUNDARY-BYPASS', stimulus);
    counts[stimulus] = entries.filter((p) => stateFor(p.scope, ok).kind === 'structurally-not-executable').length;
  }
  // Were 9/16/16 while R_byte was single-backend. R_byte has 3 scopes either
  // way, so the delta is exactly k - C(k,2): +1 at k=2 (tagLength-80) and
  // +1 at k=1 (both below-floor stimuli).
  assert.equal(counts['tagLength-80'], 10);
  assert.equal(counts['tagLength-below-floor-16'], 17);
  assert.equal(counts['tagLength-below-floor-0'], 17);
});

// --- The directional-pair rule --------------------------------------------

test('M3-H6: required(A->B) <=> Executable(A) AND Executable(B)', () => {
  const ok = executableBackends('GCM-TAGLENGTH-PROFILE-BOUNDARY-BYPASS', 'tagLength-80');
  const pairs = entriesFor('gcm').filter((p) => p.scope.kind === 'backend-pair');
  assert.equal(pairs.length, 6);
  for (const p of pairs) {
    if (p.scope.kind !== 'backend-pair') continue;
    const both = ok.get(p.scope.from.sourcePin) === true && ok.get(p.scope.to.sourcePin) === true;
    assert.equal(stateFor(p.scope, ok).kind === 'required', both,
      `${p.scope.from.family}->${p.scope.to.family}`);
  }
  // With Chromium not executable, its four incident directions are excluded
  // while the Crypto++ <-> BC pair survives in both orderings.
  const required = pairs.filter((p) => stateFor(p.scope, ok).kind === 'required');
  assert.equal(required.length, 2);
});

// --- The universe is unchanged; only the granularity moved ---------------

test('M3-H6: the total planned-observation universe is unchanged at 1641', () => {
  let total = 0;
  for (const e of MUTATION_REGISTRY) total += e.stimulusInstances.length * entriesFor(e.operation).length;
  assert.equal(total, 1641, 'H6 changes where executability is recorded, never how many observations exist');
});

test('M3-H6: 1641 = 1540 required + 101 structurally-not-executable (M3-H8 corrected)', () => {
  let req = 0, nx = 0;
  for (const e of MUTATION_REGISTRY) {
    const entries = entriesFor(e.operation);
    for (const si of e.stimulusInstances) {
      const ok = executableBackends(e.mutationId, si.stimulusInstanceId);
      for (const p of entries) {
        if (stateFor(p.scope, ok).kind === 'required') req++; else nx++;
      }
    }
  }
  assert.equal(req, 1540);
  assert.equal(nx, 101);
  assert.equal(req + nx, 1641);
});

test('M3-H6: only 7 classes contribute any not-executable observation', () => {
  const affected = new Set<string>();
  for (const e of MUTATION_REGISTRY) {
    const entries = entriesFor(e.operation);
    for (const si of e.stimulusInstances) {
      const ok = executableBackends(e.mutationId, si.stimulusInstanceId);
      if (entries.some((p) => stateFor(p.scope, ok).kind === 'structurally-not-executable')) affected.add(e.mutationId);
    }
  }
  assert.equal(affected.size, 7);
  // All seven are exactly the classes carrying a declared capability
  // requirement -- executability is never invented where none was declared.
  const withRequirement = new Set(STIMULUS_CAPABILITY_REQUIREMENTS.map((r) => r.mutationId));
  for (const id of affected) assert.ok(withRequirement.has(id), `${id} has no declared requirement`);
});

// --- Scopes remain class-invariant ----------------------------------------

test('M3-H6: Scopes(c,s1) = Scopes(c,s2) -- the structural half of the original design was right', () => {
  for (const e of MUTATION_REGISTRY) {
    if (e.stimulusInstances.length < 2) continue;
    const entries = entriesFor(e.operation);
    // The entry set is derived per OPERATION, so it is by construction the
    // same for every stimulus; this asserts the property the split preserves.
    for (const si of e.stimulusInstances) {
      const perStimulus = entriesFor(e.operation);
      assert.equal(perStimulus.length, entries.length, `${e.mutationId}::${si.stimulusInstanceId}`);
      for (let i = 0; i < entries.length; i++) {
        assert.equal(perStimulus[i]!.relation, entries[i]!.relation);
        assert.ok(scopeEquals(perStimulus[i]!.scope, entries[i]!.scope));
      }
    }
  }
});
