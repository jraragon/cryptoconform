import { test } from 'node:test';
import assert from 'node:assert/strict';

import { computeCompleteness, DuplicateObservationError, type PlannedObservation } from '../../../harness/evidence/mutation-instance-result.js';
import { scopeEquals } from '../../../harness/evidence/observation-scope.js';
import { makeRelationObservation } from '../../../harness/evidence/relation-observation.js';
import { CHROMIUM_WEBCRYPTO, CRYPTOPP, BOUNCY_CASTLE } from '../../../harness/schema/backend-identity.js';

// M3.2.1-R (M3-H1a) -- computeCompleteness previously matched a
// PlannedObservation by `relation` alone, letting ONE arbitrary real
// observation satisfy every planned scope of that relation. Root-caused
// during M3.2.1's own audit of Phase-C composition, reproduced concretely
// below BEFORE the fix (6 planned R_interop directions, 1 real observation
// -> falsely complete=true), fixed by matching on (relation, scope) via
// scopeEquals.

const DIRECTIONS: ReadonlyArray<readonly [typeof CHROMIUM_WEBCRYPTO, typeof CRYPTOPP]> = [
  [CHROMIUM_WEBCRYPTO, CRYPTOPP], [CRYPTOPP, CHROMIUM_WEBCRYPTO],
] as const;

function plannedInterop(from: typeof CHROMIUM_WEBCRYPTO, to: typeof CHROMIUM_WEBCRYPTO): PlannedObservation {
  return { relation: 'R_interop', scope: { kind: 'backend-pair', from, to }, executability: { kind: 'required' } };
}

test('M3-H1a: the exact originally-demonstrated bug scenario -- 6 planned R_interop directions, only 1 real observation, must now correctly report incomplete', () => {
  const allSixDirections: readonly [typeof CHROMIUM_WEBCRYPTO, typeof CHROMIUM_WEBCRYPTO][] = [
    [CHROMIUM_WEBCRYPTO, CRYPTOPP], [CRYPTOPP, CHROMIUM_WEBCRYPTO],
    [CHROMIUM_WEBCRYPTO, BOUNCY_CASTLE], [BOUNCY_CASTLE, CHROMIUM_WEBCRYPTO],
    [CRYPTOPP, BOUNCY_CASTLE], [BOUNCY_CASTLE, CRYPTOPP],
  ];
  const planned = allSixDirections.map(([from, to]) => plannedInterop(from, to));

  // Only ONE of the 6 directions was actually observed.
  const onlyObservation = makeRelationObservation({
    applicable: true, context: { kind: 'mutation', phase: 'C', mutationId: 'test', stimulusInstanceId: 's1' }, relation: 'R_interop',
    scope: { kind: 'backend-pair', from: CHROMIUM_WEBCRYPTO, to: CRYPTOPP }, status: 'pass',
    participants: [], evaluatorId: 'R_interop', basis: 'only one direction actually run',
  });

  const result = computeCompleteness(planned, [onlyObservation]);

  // Before the fix this incorrectly returned complete=true, outstanding=[].
  assert.equal(result.complete, false, 'must NOT be reported complete with 5/6 directions never observed');
  assert.equal(result.outstanding.length, 5, 'exactly the 5 unobserved directions must be outstanding');
});

test('M3-H1a: the positive case -- all 6 directions genuinely observed -- correctly reports complete', () => {
  const allSixDirections: readonly [typeof CHROMIUM_WEBCRYPTO, typeof CHROMIUM_WEBCRYPTO][] = [
    [CHROMIUM_WEBCRYPTO, CRYPTOPP], [CRYPTOPP, CHROMIUM_WEBCRYPTO],
    [CHROMIUM_WEBCRYPTO, BOUNCY_CASTLE], [BOUNCY_CASTLE, CHROMIUM_WEBCRYPTO],
    [CRYPTOPP, BOUNCY_CASTLE], [BOUNCY_CASTLE, CRYPTOPP],
  ];
  const planned = allSixDirections.map(([from, to]) => plannedInterop(from, to));
  const observations = allSixDirections.map(([from, to]) =>
    makeRelationObservation({
      applicable: true, context: { kind: 'mutation', phase: 'C', mutationId: 'test', stimulusInstanceId: 's1' }, relation: 'R_interop',
      scope: { kind: 'backend-pair', from, to }, status: 'pass', participants: [], evaluatorId: 'R_interop', basis: 'genuine',
    }),
  );

  const result = computeCompleteness(planned, observations);
  assert.equal(result.complete, true);
  assert.equal(result.outstanding.length, 0);
});

test('M3-H1a: backend-pair directionality is respected -- an A->B observation must NOT satisfy a B->A requirement', () => {
  const planned = [plannedInterop(CRYPTOPP, CHROMIUM_WEBCRYPTO)]; // Crypto++ -> Chromium required
  const wrongDirectionObservation = makeRelationObservation({
    applicable: true, context: { kind: 'mutation', phase: 'C', mutationId: 'test', stimulusInstanceId: 's1' }, relation: 'R_interop',
    scope: { kind: 'backend-pair', from: CHROMIUM_WEBCRYPTO, to: CRYPTOPP }, status: 'pass', // Chromium -> Crypto++, the OPPOSITE direction
    participants: [], evaluatorId: 'R_interop', basis: 'wrong direction',
  });

  const result = computeCompleteness(planned, [wrongDirectionObservation]);
  assert.equal(result.complete, false, 'the opposite-direction observation must never satisfy this requirement');
  assert.equal(result.outstanding.length, 1);
});

test('M3-H1a: two observations resolving the identical (relation, scope) is rejected fail-closed, never resolved arbitrarily', () => {
  const planned = [plannedInterop(CHROMIUM_WEBCRYPTO, CRYPTOPP)];
  const scope = { kind: 'backend-pair' as const, from: CHROMIUM_WEBCRYPTO, to: CRYPTOPP };
  const duplicate1 = makeRelationObservation({
    applicable: true, context: { kind: 'mutation', phase: 'C', mutationId: 'test', stimulusInstanceId: 's1' }, relation: 'R_interop',
    scope, status: 'pass', participants: [], evaluatorId: 'R_interop', basis: 'first',
  });
  const duplicate2 = makeRelationObservation({
    applicable: true, context: { kind: 'mutation', phase: 'C', mutationId: 'test', stimulusInstanceId: 's1' }, relation: 'R_interop',
    scope, status: 'fail', participants: [], evaluatorId: 'R_interop', basis: 'second, conflicting',
  });

  assert.throws(() => computeCompleteness(planned, [duplicate1, duplicate2]), DuplicateObservationError);
});

test('M3-H1a: scopeEquals itself -- single-backend, manifest, and cross-backend-set semantics', () => {
  assert.equal(scopeEquals({ kind: 'single-backend', backend: CHROMIUM_WEBCRYPTO }, { kind: 'single-backend', backend: CHROMIUM_WEBCRYPTO }), true);
  assert.equal(scopeEquals({ kind: 'single-backend', backend: CHROMIUM_WEBCRYPTO }, { kind: 'single-backend', backend: CRYPTOPP }), false);

  assert.equal(scopeEquals({ kind: 'backend-pair', from: CHROMIUM_WEBCRYPTO, to: CRYPTOPP }, { kind: 'backend-pair', from: CHROMIUM_WEBCRYPTO, to: CRYPTOPP }), true);
  assert.equal(scopeEquals({ kind: 'backend-pair', from: CHROMIUM_WEBCRYPTO, to: CRYPTOPP }, { kind: 'backend-pair', from: CRYPTOPP, to: CHROMIUM_WEBCRYPTO }), false, 'A->B != B->A');

  assert.equal(scopeEquals({ kind: 'manifest', backend: CHROMIUM_WEBCRYPTO, apiSurface: 'x' }, { kind: 'manifest', backend: CHROMIUM_WEBCRYPTO, apiSurface: 'x' }), true);
  assert.equal(scopeEquals({ kind: 'manifest', backend: CHROMIUM_WEBCRYPTO, apiSurface: 'x' }, { kind: 'manifest', backend: CHROMIUM_WEBCRYPTO, apiSurface: 'y' }), false);

  // Order-independent set equality.
  assert.equal(
    scopeEquals({ kind: 'cross-backend-set', backends: [CHROMIUM_WEBCRYPTO, CRYPTOPP, BOUNCY_CASTLE] }, { kind: 'cross-backend-set', backends: [BOUNCY_CASTLE, CHROMIUM_WEBCRYPTO, CRYPTOPP] }),
    true,
  );
  assert.equal(
    scopeEquals({ kind: 'cross-backend-set', backends: [CHROMIUM_WEBCRYPTO, CRYPTOPP] }, { kind: 'cross-backend-set', backends: [CHROMIUM_WEBCRYPTO, BOUNCY_CASTLE] }),
    false,
  );

  // Different kinds are never equal.
  assert.equal(scopeEquals({ kind: 'single-backend', backend: CHROMIUM_WEBCRYPTO }, { kind: 'manifest', backend: CHROMIUM_WEBCRYPTO, apiSurface: 'x' }), false);
});
