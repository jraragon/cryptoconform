import { test } from 'node:test';
import assert from 'node:assert/strict';

import { aggregateMutationClass, AggregationIncompleteError, DuplicateObservationError } from '../../../harness/aggregation/aggregator.js';
import { makeRelationObservation } from '../../../harness/evidence/relation-observation.js';
import type { PlannedObservation, MutationInstanceResult } from '../../../harness/evidence/mutation-instance-result.js';
import type { RelationApplicability } from '../../../harness/schema/registry-types.js';
import { CHROMIUM_WEBCRYPTO, CRYPTOPP, BOUNCY_CASTLE } from '../../../harness/schema/backend-identity.js';

// ---------------------------------------------------------------------
// M3-H7 -- Zero-Executable-Support Aggregation Gap.
//
// M3-H6 made executability per (class, stimulus). Once represented
// correctly, a legitimate configuration appears that the frozen aggregation
// never defined: an APPLICABLE relation with zero executable scope in a
// given instance -- and, for three real classes, in EVERY instance.
//
// The frozen Harness rule (v0.26 sec:5.3) aggregates over
//     S_i(c) = { s : R_i has at least one executable scope for s }
// so an instance outside S_i(c) simply does not participate. But the same
// formula's universal quantifier is VACUOUSLY TRUE over the empty set,
// which would yield 'pass' with no interoperability ever observed.
//
//     Applicability = 1  AND  |S_i(c)| = 0   =>   R_i(c) is unscorable
//
// not pass, not fail, and not n/a -- the last reserved strictly for
// Applicability = 0:
//     NotExecutable(c,s,R)  =/=>  n/a
// ---------------------------------------------------------------------

const REQ = { kind: 'required' } as const;
const NX = { kind: 'structurally-not-executable', reason: 'backend-capability-absent' } as const;
const INTEROP_ONLY: RelationApplicability = { R_byte: false, R_interop: true, R_ser: false, R_val: false, R_err: false, R_cap: false };

function pairScope(from: typeof CHROMIUM_WEBCRYPTO, to: typeof CHROMIUM_WEBCRYPTO) {
  return { kind: 'backend-pair' as const, from, to };
}
function obs(from: typeof CHROMIUM_WEBCRYPTO, to: typeof CHROMIUM_WEBCRYPTO, status: 'pass' | 'fail', stimulusInstanceId: string) {
  return makeRelationObservation({
    applicable: true, context: { kind: 'mutation', phase: 'C', mutationId: 'M', stimulusInstanceId },
    relation: 'R_interop', scope: pairScope(from, to), status, participants: [],
    evaluatorId: 'R_interop', basis: 'H7 fixture',
  });
}
function instance(
  stimulusInstanceId: string,
  planned: PlannedObservation[],
  observations: ReturnType<typeof obs>[],
): MutationInstanceResult {
  return {
    mutationId: 'M', stimulusInstanceId, operation: 'gcm',
    observations: observations.map((o) => o.observationId),
    coverage: { planned, reached: observations.map((o) => o.observationId), outstanding: [] },
    complete: true,
  } as MutationInstanceResult;
}

// --- 1. The GCM-TAGLENGTH shape: only the supported stimulus contributes --

test('M3-H7 (1): only the stimulus with executable scopes contributes to R_interop(c)', () => {
  // tagLength-80: cryptopp <-> bouncycastle executable, both directions.
  // below-floor-*: only cryptopp executable, so ALL six directions are NX.
  const supportedPlanned: PlannedObservation[] = [
    { relation: 'R_interop', scope: pairScope(CRYPTOPP, BOUNCY_CASTLE), executability: REQ },
    { relation: 'R_interop', scope: pairScope(BOUNCY_CASTLE, CRYPTOPP), executability: REQ },
    { relation: 'R_interop', scope: pairScope(CHROMIUM_WEBCRYPTO, CRYPTOPP), executability: NX },
  ];
  const unsupportedPlanned: PlannedObservation[] = supportedPlanned.map((p) => ({ ...p, executability: NX }));

  const a = obs(CRYPTOPP, BOUNCY_CASTLE, 'fail', 'tagLength-80');
  const b = obs(BOUNCY_CASTLE, CRYPTOPP, 'pass', 'tagLength-80');

  const result = aggregateMutationClass(INTEROP_ONLY, [
    instance('tagLength-80', supportedPlanned, [a, b]),
    instance('tagLength-below-floor-16', unsupportedPlanned, []),
    instance('tagLength-below-floor-0', unsupportedPlanned, []),
  ], [a, b]);

  assert.equal(result.observedSpectrum.R_interop, 'fail', 'the supported stimulus own fail decides');
  // The two unsupported instances neither threw nor voted.
  assert.equal(result.detectionSupport.evaluatedInstances, 1);
  assert.equal(result.detectionSupport.divergentInstances, 1);
});

test('M3-H7 (1b): an instance outside S_i(c) no longer throws -- the H1b guard was too strong', () => {
  const planned: PlannedObservation[] = [
    { relation: 'R_interop', scope: pairScope(CRYPTOPP, BOUNCY_CASTLE), executability: REQ },
  ];
  const nxPlanned: PlannedObservation[] = [{ ...planned[0]!, executability: NX }];
  const o = obs(CRYPTOPP, BOUNCY_CASTLE, 'pass', 's1');

  assert.doesNotThrow(() => aggregateMutationClass(INTEROP_ONLY, [
    instance('s1', planned, [o]),
    instance('s2', nxPlanned, []),
  ], [o]));
});

// --- 2 & 3. |S_i(c)| = 0 must never be 'pass' ----------------------------

test('M3-H7 (2): |S_i(c)| = 0 refuses to score -- never a vacuous pass', () => {
  const allNx: PlannedObservation[] = [
    { relation: 'R_interop', scope: pairScope(CHROMIUM_WEBCRYPTO, CRYPTOPP), executability: NX },
    { relation: 'R_interop', scope: pairScope(CRYPTOPP, CHROMIUM_WEBCRYPTO), executability: NX },
  ];
  // M3-H11.4-Core.2 updated this assertion deliberately. H7's own reasoning
  // is unchanged and still correct -- pass would be vacuous, fail unobserved,
  // n/a a denial of applicability. What changed is the CONSEQUENCE: the fact
  // is now reported for that relation instead of raised for the whole class.
  const r = aggregateMutationClass(INTEROP_ONLY, [instance('default', allNx, [])], []);
  assert.equal(r.observedSpectrum.R_interop, undefined, 'still never a vacuous pass');
  assert.equal(r.nonScoreable.length, 1);
  assert.equal(r.nonScoreable[0]!.relation, 'R_interop');
  assert.equal(r.nonScoreable[0]!.cause, 'zero-executable-support');
});

test('M3-H7 (3): the same holds when EVERY instance of a multi-stimulus class is unsupported', () => {
  const allNx: PlannedObservation[] = [
    { relation: 'R_interop', scope: pairScope(CHROMIUM_WEBCRYPTO, CRYPTOPP), executability: NX },
  ];
  const r = aggregateMutationClass(INTEROP_ONLY, [
    instance('s1', allNx, []), instance('s2', allNx, []),
  ], []);
  assert.equal(r.observedSpectrum.R_interop, undefined);
  assert.deepEqual([...r.nonScoreable[0]!.stimulusInstanceIds], ['s1', 's2'],
    'both stimuli are named, so the cell is reconstructible');
});

test('M3-H7: zero support is still NOT an AggregationIncompleteError -- the two states remain distinct', () => {
  // The distinction survives Core.2 and is now visible in the RESULT rather
  // than in which exception was raised: zero support reports a cell, while a
  // malformed plan or a missing required observation still throws.
  const allNx: PlannedObservation[] = [
    { relation: 'R_interop', scope: pairScope(CHROMIUM_WEBCRYPTO, CRYPTOPP), executability: NX },
  ];
  assert.doesNotThrow(() => aggregateMutationClass(INTEROP_ONLY, [instance('default', allNx, [])], []));
  const r = aggregateMutationClass(INTEROP_ONLY, [instance('default', allNx, [])], []);
  assert.equal(r.nonScoreable.length, 1, 'nothing is missing; nothing was ever required');

  // A relation with NO planned scope at all is still a malformed plan.
  assert.throws(
    () => aggregateMutationClass(INTEROP_ONLY, [instance('default', [], [])], []),
    AggregationIncompleteError,
  );
});

// --- 4. An isolated NX scope still does not block completeness -----------

test('M3-H7 (4): a single NX scope alongside executable ones changes nothing', () => {
  const planned: PlannedObservation[] = [
    { relation: 'R_interop', scope: pairScope(CRYPTOPP, BOUNCY_CASTLE), executability: REQ },
    { relation: 'R_interop', scope: pairScope(CHROMIUM_WEBCRYPTO, CRYPTOPP), executability: NX },
  ];
  const o = obs(CRYPTOPP, BOUNCY_CASTLE, 'pass', 'default');
  const result = aggregateMutationClass(INTEROP_ONLY, [instance('default', planned, [o])], [o]);
  assert.equal(result.observedSpectrum.R_interop, 'pass');
});

// --- 5. A required scope with missing evidence still fails ---------------

test('M3-H7 (5): a REQUIRED scope with no observation still raises AggregationIncompleteError', () => {
  const planned: PlannedObservation[] = [
    { relation: 'R_interop', scope: pairScope(CRYPTOPP, BOUNCY_CASTLE), executability: REQ },
    { relation: 'R_interop', scope: pairScope(BOUNCY_CASTLE, CRYPTOPP), executability: REQ },
  ];
  const only = obs(CRYPTOPP, BOUNCY_CASTLE, 'pass', 'default');
  assert.throws(
    () => aggregateMutationClass(INTEROP_ONLY, [instance('default', planned, [only])], [only]),
    AggregationIncompleteError,
    'H7 must not weaken the missing-evidence guard',
  );
});

// --- 6. H1b's own guarantees survive -------------------------------------

test('M3-H7 (6): fail-dominance across scopes is preserved', () => {
  const planned: PlannedObservation[] = [
    { relation: 'R_interop', scope: pairScope(CRYPTOPP, BOUNCY_CASTLE), executability: REQ },
    { relation: 'R_interop', scope: pairScope(BOUNCY_CASTLE, CRYPTOPP), executability: REQ },
  ];
  const first = obs(CRYPTOPP, BOUNCY_CASTLE, 'pass', 'default'); // collected first
  const second = obs(BOUNCY_CASTLE, CRYPTOPP, 'fail', 'default');
  const result = aggregateMutationClass(INTEROP_ONLY, [instance('default', planned, [first, second])], [first, second]);
  assert.equal(result.observedSpectrum.R_interop, 'fail');
});

test('M3-H7 (6b): duplicate-scope resolution is still fail-closed', () => {
  const planned: PlannedObservation[] = [
    { relation: 'R_interop', scope: pairScope(CRYPTOPP, BOUNCY_CASTLE), executability: REQ },
  ];
  const a = obs(CRYPTOPP, BOUNCY_CASTLE, 'pass', 'default');
  const b = obs(CRYPTOPP, BOUNCY_CASTLE, 'fail', 'default');
  assert.throws(
    () => aggregateMutationClass(INTEROP_ONLY, [instance('default', planned, [a, b])], [a, b]),
    DuplicateObservationError,
  );
});

// --- 7. n/a remains exclusively an applicability statement ---------------

test('M3-H7 (7): n/a appears if and only if applicability = 0', () => {
  const noneApplicable: RelationApplicability = { R_byte: false, R_interop: false, R_ser: false, R_val: false, R_err: false, R_cap: false };
  const result = aggregateMutationClass(noneApplicable, [instance('default', [], [])], []);
  for (const r of ['R_byte', 'R_interop', 'R_ser', 'R_val', 'R_err', 'R_cap'] as const) {
    assert.equal(result.observedSpectrum[r], 'n/a');
  }

  // And an APPLICABLE relation with zero support is still never labelled
  // n/a -- the distinction H7 exists to protect, now expressed as an absent
  // key plus a cell rather than as an exception.
  const allNx: PlannedObservation[] = [
    { relation: 'R_interop', scope: pairScope(CHROMIUM_WEBCRYPTO, CRYPTOPP), executability: NX },
  ];
  const nx = aggregateMutationClass(INTEROP_ONLY, [instance('default', allNx, [])], []);
  assert.equal(nx.observedSpectrum.R_interop, undefined);
  assert.notEqual(nx.observedSpectrum.R_interop, 'n/a');
  assert.equal(nx.nonScoreable[0]!.cause, 'zero-executable-support');
});
