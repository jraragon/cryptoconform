import type { RelationSpectrum } from '../../../harness/evidence/relation-spectrum.js';
import { test } from 'node:test';
import assert from 'node:assert/strict';

import { aggregateMutationClass, AggregationIncompleteError, DuplicateObservationError } from '../../../harness/aggregation/aggregator.js';
import { exportBundle, importBundle, reconstructTraceability, type EvidenceBundle } from '../../../harness/aggregation/evidence-export.js';
import { makeRelationObservation, makeNotApplicableObservation } from '../../../harness/evidence/relation-observation.js';
import { makeMutationInstanceResult, type PlannedObservation } from '../../../harness/evidence/mutation-instance-result.js';
import { makeMutationResult } from '../../../harness/evidence/mutation-result.js';
import { makeMutationExecution } from '../../../harness/evidence/execution-evidence.js';
import { CHROMIUM_WEBCRYPTO, CRYPTOPP, BOUNCY_CASTLE, NODE_WEBCRYPTO_OPENSSL, backendIdentityEquals } from '../../../harness/schema/backend-identity.js';
import type { RelationApplicability } from '../../../harness/schema/registry-types.js';

const GCM_APPLICABILITY: RelationApplicability = { R_byte: true, R_interop: true, R_ser: true, R_val: true, R_err: true, R_cap: true };

const commonExecFields = {
  operation: 'gcm' as const,
  subject: { backend: NODE_WEBCRYPTO_OPENSSL, direction: 'encrypt' as const, path: 'sdk' as const },
  input: { kind: 'test' }, outcome: { kind: 'accept' }, clauseIdsEvaluated: [],
  executionStatus: 'completed' as const, provenance: { timestampIso: new Date().toISOString() },
};

function makeInstance(mutationId: string, stimulusInstanceId: string, valStatus: 'pass' | 'fail') {
  const exec = makeMutationExecution(mutationId, stimulusInstanceId, commonExecFields);
  const valObs = makeRelationObservation({
    applicable: true, context: exec.context, relation: 'R_val',
    scope: { kind: 'single-backend', backend: NODE_WEBCRYPTO_OPENSSL },
    status: valStatus, participants: [exec.executionId], evaluatorId: 'R_val', basis: 'test',
  });
  // The remaining applicable relations are scored 'pass' for simplicity --
  // this fixture focuses on R_val's own fail-dominant behavior. Marking
  // any of these 'n/a' here would be inconsistent with GCM_APPLICABILITY
  // declaring them applicable at the class level.
  const otherObs = (['R_byte', 'R_interop', 'R_ser', 'R_err', 'R_cap'] as const).map((relation) =>
    makeRelationObservation({
      applicable: true, context: exec.context, relation,
      scope: relation === 'R_cap'
        ? { kind: 'manifest', backend: NODE_WEBCRYPTO_OPENSSL, apiSurface: 'x' }
        : { kind: 'single-backend', backend: NODE_WEBCRYPTO_OPENSSL },
      status: 'pass', participants: [exec.executionId], evaluatorId: relation, basis: 'test',
    }),
  );
  const observations = [valObs, ...otherObs];
  const planned: PlannedObservation[] = observations.map((o) => ({ relation: o.relation, scope: o.scope, executability: { kind: 'required' } }));
  const instance = makeMutationInstanceResult({ mutationId, stimulusInstanceId, operation: 'gcm', planned, observations });
  return { exec, observations, instance };
}

test('fail-dominant: R_val(c) = fail if ANY instance fails, even if the other two pass', () => {
  const i80 = makeInstance('GCM-TAGLENGTH-PROFILE-BOUNDARY-BYPASS', 'tagLength-80', 'pass');
  const i16 = makeInstance('GCM-TAGLENGTH-PROFILE-BOUNDARY-BYPASS', 'tagLength-below-floor-16', 'fail');
  const i0 = makeInstance('GCM-TAGLENGTH-PROFILE-BOUNDARY-BYPASS', 'tagLength-below-floor-0', 'pass');
  const allObs = [...i80.observations, ...i16.observations, ...i0.observations];
  const { observedSpectrum } = aggregateMutationClass(GCM_APPLICABILITY, [i80.instance, i16.instance, i0.instance], allObs);
  assert.equal(observedSpectrum.R_val, 'fail');
});

test('all-pass: R_val(c) = pass only if EVERY instance passes', () => {
  const i80 = makeInstance('GCM-TAGLENGTH-PROFILE-BOUNDARY-BYPASS', 'tagLength-80', 'pass');
  const i16 = makeInstance('GCM-TAGLENGTH-PROFILE-BOUNDARY-BYPASS', 'tagLength-below-floor-16', 'pass');
  const i0 = makeInstance('GCM-TAGLENGTH-PROFILE-BOUNDARY-BYPASS', 'tagLength-below-floor-0', 'pass');
  const allObs = [...i80.observations, ...i16.observations, ...i0.observations];
  const { observedSpectrum } = aggregateMutationClass(GCM_APPLICABILITY, [i80.instance, i16.instance, i0.instance], allObs);
  assert.equal(observedSpectrum.R_val, 'pass');
});

test('n/a comes exclusively from inapplicability -- R_cap here was marked n/a per-instance but the CLASS-level applicability is what governs aggregation', () => {
  const i80 = makeInstance('GCM-TAGLENGTH-PROFILE-BOUNDARY-BYPASS', 'tagLength-80', 'pass');
  // R_cap is inapplicable at the CLASS level for this synthetic test.
  const inapplicableCap: RelationApplicability = { ...GCM_APPLICABILITY, R_cap: false };
  const { observedSpectrum } = aggregateMutationClass(inapplicableCap, [i80.instance], i80.observations);
  assert.equal(observedSpectrum.R_cap, 'n/a');
});

test('order-independence: shuffled instance array produces an identical aggregated result', () => {
  const i80 = makeInstance('GCM-TAGLENGTH-PROFILE-BOUNDARY-BYPASS', 'tagLength-80', 'pass');
  const i16 = makeInstance('GCM-TAGLENGTH-PROFILE-BOUNDARY-BYPASS', 'tagLength-below-floor-16', 'fail');
  const i0 = makeInstance('GCM-TAGLENGTH-PROFILE-BOUNDARY-BYPASS', 'tagLength-below-floor-0', 'pass');
  const allObs = [...i80.observations, ...i16.observations, ...i0.observations];
  const forward = aggregateMutationClass(GCM_APPLICABILITY, [i80.instance, i16.instance, i0.instance], allObs);
  const shuffled = aggregateMutationClass(GCM_APPLICABILITY, [i0.instance, i80.instance, i16.instance], allObs);
  assert.deepEqual(forward, shuffled);
});

test('non-terminal status (not-executed) is REFUSED, never promoted to pass', () => {
  const exec = makeMutationExecution('GCM-ERROR-MISCLASSIFICATION', 'default', commonExecFields);
  const notExecutedObs = {
    observationId: 'obs-manual-1', context: exec.context, relation: 'R_val' as const,
    scope: { kind: 'single-backend' as const, backend: NODE_WEBCRYPTO_OPENSSL },
    status: { state: 'not-executed' as const, reason: 'stimulus-not-expressible' as const },
    participants: [exec.executionId], evaluatorId: 'R_val', basis: 'test',
  };
  const planned: PlannedObservation[] = [{ relation: 'R_val', scope: notExecutedObs.scope, executability: { kind: 'required' } }];
  const instance = makeMutationInstanceResult({ mutationId: 'GCM-ERROR-MISCLASSIFICATION', stimulusInstanceId: 'default', operation: 'gcm', planned, observations: [notExecutedObs] });

  assert.throws(() => {
    aggregateMutationClass(GCM_APPLICABILITY, [instance], [notExecutedObs]);
  }, AggregationIncompleteError);
});

test('a completely missing observation for an applicable relation is refused, not defaulted', () => {
  const instance = makeMutationInstanceResult({ mutationId: 'X', stimulusInstanceId: 'default', operation: 'gcm', planned: [], observations: [] });
  assert.throws(() => aggregateMutationClass(GCM_APPLICABILITY, [instance], []), AggregationIncompleteError);
});

// ---------------------------------------------------------------------
// Export/import: the critical BackendIdentity regression test
// ---------------------------------------------------------------------

test('CRITICAL: NODE_WEBCRYPTO_OPENSSL survives export -> import distinct from CHROMIUM_WEBCRYPTO, full structural equality', () => {
  const i80 = makeInstance('GCM-TAGLENGTH-PROFILE-BOUNDARY-BYPASS', 'tagLength-80', 'pass');
  const { observedSpectrum, detectionSupport } = aggregateMutationClass(GCM_APPLICABILITY, [i80.instance], i80.observations);
  const mutationResult = makeMutationResult({
    mutationId: 'GCM-TAGLENGTH-PROFILE-BOUNDARY-BYPASS', operation: 'gcm',
    gamma0Ref: 'registry:GCM-TAGLENGTH-PROFILE-BOUNDARY-BYPASS', applicability: GCM_APPLICABILITY,
    expectedSpectrum: { R_byte: { expectation: 'not-expected' }, R_interop: { expectation: 'not-expected' }, R_ser: { expectation: 'not-expected' }, R_val: { expectation: 'detect' }, R_err: { expectation: 'not-expected' }, R_cap: { expectation: 'not-expected' } },
    instanceResults: [i80.instance], observedSpectrum: observedSpectrum as RelationSpectrum, detectionSupport,
  });

  const bundle: EvidenceBundle = {
    bundleVersion: '1.0', executions: [i80.exec], observations: i80.observations,
    instanceResults: [i80.instance], mutationResults: [mutationResult],
  };

  const serialized = exportBundle(bundle);
  const reimported = importBundle(serialized);

  const reimportedBackend = reimported.executions[0]!.subject.backend;
  assert.ok(backendIdentityEquals(reimportedBackend, NODE_WEBCRYPTO_OPENSSL), 'must survive as NODE_WEBCRYPTO_OPENSSL exactly');
  assert.ok(!backendIdentityEquals(reimportedBackend, CHROMIUM_WEBCRYPTO), 'must NEVER collapse into CHROMIUM_WEBCRYPTO');
  assert.notEqual(reimportedBackend.sourcePin, CHROMIUM_WEBCRYPTO.sourcePin);
  // Full structural equality, not just family:
  assert.deepEqual(reimportedBackend, NODE_WEBCRYPTO_OPENSSL);
});

test('export -> import is lossless: deep-equal round trip for the full bundle', () => {
  const i80 = makeInstance('GCM-TAGLENGTH-PROFILE-BOUNDARY-BYPASS', 'tagLength-80', 'pass');
  const bundle: EvidenceBundle = {
    bundleVersion: '1.0', executions: [i80.exec], observations: i80.observations,
    instanceResults: [i80.instance], mutationResults: [],
  };
  const reimported = importBundle(exportBundle(bundle));
  assert.deepEqual(reimported, bundle);
});

test('full traceability chain reconstructible from an exported+reimported bundle alone', () => {
  const i80 = makeInstance('GCM-TAGLENGTH-PROFILE-BOUNDARY-BYPASS', 'tagLength-80', 'pass');
  const { observedSpectrum, detectionSupport } = aggregateMutationClass(GCM_APPLICABILITY, [i80.instance], i80.observations);
  const mutationResult = makeMutationResult({
    mutationId: 'GCM-TAGLENGTH-PROFILE-BOUNDARY-BYPASS', operation: 'gcm',
    gamma0Ref: 'registry:GCM-TAGLENGTH-PROFILE-BOUNDARY-BYPASS', applicability: GCM_APPLICABILITY,
    expectedSpectrum: { R_byte: { expectation: 'not-expected' }, R_interop: { expectation: 'not-expected' }, R_ser: { expectation: 'not-expected' }, R_val: { expectation: 'detect' }, R_err: { expectation: 'not-expected' }, R_cap: { expectation: 'not-expected' } },
    instanceResults: [i80.instance], observedSpectrum: observedSpectrum as RelationSpectrum, detectionSupport,
  });
  const bundle: EvidenceBundle = {
    bundleVersion: '1.0', executions: [i80.exec], observations: i80.observations,
    instanceResults: [i80.instance], mutationResults: [mutationResult],
  };
  const reimported = importBundle(exportBundle(bundle));
  const trace = reconstructTraceability(reimported, 'GCM-TAGLENGTH-PROFILE-BOUNDARY-BYPASS', 'tagLength-80');

  assert.equal(trace.executions.length, 1);
  assert.equal(trace.executions[0]!.executionId, i80.exec.executionId);
  assert.equal(trace.observations.length, i80.observations.length);
  assert.ok(trace.mutationResult);
  assert.equal(trace.mutationResult!.mutationId, 'GCM-TAGLENGTH-PROFILE-BOUNDARY-BYPASS');
});

test('aggregator contains ZERO mutationId/operation/backend-specific branching (grep-confirmed)', async () => {
  const { readFileSync } = await import('node:fs');
  const src = readFileSync(new URL('../../../harness/aggregation/aggregator.ts', import.meta.url), 'utf8');
  assert.ok(!/mutationId\s*===/.test(src));
  assert.ok(!/operation\s*===\s*'(hkdf|gcm|oaep|pss|rsa-ser|ec-ser)'/.test(src));
  assert.ok(!/backend.*===.*'(chromium|cryptopp|bouncycastle)'/.test(src));
});

// ---------------------------------------------------------------------
// M3-H1b regression -- discovered alongside M3-H1a during M3.2.1's own
// audit. aggregateRelation previously resolved a bare `o.relation ===
// relation` match per instance -- letting ONE arbitrary observation (of
// possibly several scopes under the same relation) stand in for the
// entire relation, discarding every other scope's own evidence. The
// sharpest failure: a real fail hidden behind an earlier-collected pass
// was never seen at all, silently reporting a fully-conformant relation
// on a genuinely divergent mutation. Fixed to resolve every
// Required(i,R) = {p in i.coverage.planned | p.relation=R, required} via
// scopeEquals, validating full coverage BEFORE reducing, then applying
// fail>pass>n/a over the complete collected set -- never the first match.
// ---------------------------------------------------------------------

const INTEROP_APPLICABILITY: RelationApplicability = { R_byte: false, R_interop: true, R_ser: false, R_val: false, R_err: false, R_cap: false };

function interopScope(from: typeof CHROMIUM_WEBCRYPTO, to: typeof CHROMIUM_WEBCRYPTO) {
  return { kind: 'backend-pair' as const, from, to };
}
function interopObs(id: string, from: typeof CHROMIUM_WEBCRYPTO, to: typeof CHROMIUM_WEBCRYPTO, status: 'pass' | 'fail' | 'n/a') {
  const context = { kind: 'mutation' as const, phase: 'C' as const, mutationId: 'M3-H1B-TEST', stimulusInstanceId: 'unused' };
  if (status === 'n/a') {
    // A specific (relation,scope) can legitimately be n/a even while the
    // relation is applicable overall at the class level -- makeNotApplicableObservation
    // is the correct factory for this exact per-scope case, distinct from
    // makeRelationObservation, which structurally forbids status='n/a' for
    // an applicable relation.
    return makeNotApplicableObservation({ context, relation: 'R_interop', scope: interopScope(from, to), evaluatorId: 'R_interop', basis: 'H1b fixture (per-scope n/a)' });
  }
  return makeRelationObservation({
    applicable: true, context, relation: 'R_interop', scope: interopScope(from, to), status, participants: [], evaluatorId: 'R_interop', basis: 'H1b fixture',
  });
}
function interopInstance(stimulusInstanceId: string, pairs: ReadonlyArray<readonly [typeof CHROMIUM_WEBCRYPTO, typeof CHROMIUM_WEBCRYPTO]>, observations: ReadonlyArray<ReturnType<typeof interopObs>>) {
  const planned: PlannedObservation[] = pairs.map(([from, to]) => ({ relation: 'R_interop', scope: interopScope(from, to), executability: { kind: 'required' } }));
  return { mutationId: 'M3-H1B-TEST', stimulusInstanceId, operation: 'ec-ser', observations: observations.map((o) => o.observationId), coverage: { planned, reached: observations.map((o) => o.observationId), outstanding: [] }, complete: true };
}

test('M3-H1b: the exact originally-demonstrated bug -- pass collected first, a real fail on a different scope of the SAME relation must not be hidden -> fail', () => {
  const o1 = interopObs('o1', CHROMIUM_WEBCRYPTO, CRYPTOPP, 'pass'); // collected/observed first
  const o2 = interopObs('o2', CHROMIUM_WEBCRYPTO, BOUNCY_CASTLE, 'fail'); // must still be seen
  const instance = interopInstance('s1', [[CHROMIUM_WEBCRYPTO, CRYPTOPP], [CHROMIUM_WEBCRYPTO, BOUNCY_CASTLE]], [o1, o2]);
  const result = aggregateMutationClass(INTEROP_APPLICABILITY, [instance], [o1, o2]);
  assert.equal(result.observedSpectrum.R_interop, 'fail', 'the real fail must never be hidden behind an earlier-collected pass');
  assert.equal(result.detectionSupport.divergentInstances, 1);
});

test('M3-H1b: n/a + pass -> pass (n/a is scientifically neutral, never blocks a real pass)', () => {
  const o1 = interopObs('o1', CHROMIUM_WEBCRYPTO, CRYPTOPP, 'n/a');
  const o2 = interopObs('o2', CHROMIUM_WEBCRYPTO, BOUNCY_CASTLE, 'pass');
  const instance = interopInstance('s1', [[CHROMIUM_WEBCRYPTO, CRYPTOPP], [CHROMIUM_WEBCRYPTO, BOUNCY_CASTLE]], [o1, o2]);
  const result = aggregateMutationClass(INTEROP_APPLICABILITY, [instance], [o1, o2]);
  assert.equal(result.observedSpectrum.R_interop, 'pass');
});

test('M3-H1b: n/a + n/a -> n/a (never fabricate a pass from the mere absence of a fail)', () => {
  const o1 = interopObs('o1', CHROMIUM_WEBCRYPTO, CRYPTOPP, 'n/a');
  const o2 = interopObs('o2', CHROMIUM_WEBCRYPTO, BOUNCY_CASTLE, 'n/a');
  const instance = interopInstance('s1', [[CHROMIUM_WEBCRYPTO, CRYPTOPP], [CHROMIUM_WEBCRYPTO, BOUNCY_CASTLE]], [o1, o2]);
  const result = aggregateMutationClass(INTEROP_APPLICABILITY, [instance], [o1, o2]);
  assert.equal(result.observedSpectrum.R_interop, 'n/a');
});

test('M3-H1b: pass + n/a + fail -> fail (fail-dominant holds over a mixed set, not just two states)', () => {
  const o1 = interopObs('o1', CHROMIUM_WEBCRYPTO, CRYPTOPP, 'pass');
  const o2 = interopObs('o2', CHROMIUM_WEBCRYPTO, BOUNCY_CASTLE, 'n/a');
  const o3 = interopObs('o3', CRYPTOPP, BOUNCY_CASTLE, 'fail');
  const instance = interopInstance('s1', [[CHROMIUM_WEBCRYPTO, CRYPTOPP], [CHROMIUM_WEBCRYPTO, BOUNCY_CASTLE], [CRYPTOPP, BOUNCY_CASTLE]], [o1, o2, o3]);
  const result = aggregateMutationClass(INTEROP_APPLICABILITY, [instance], [o1, o2, o3]);
  assert.equal(result.observedSpectrum.R_interop, 'fail');
});

test('M3-H1b: multiple stimuli of the same class, fail in only one -> class-level fail, detectionSupport correctly counts both instances', () => {
  const s1o = interopObs('s1o', CHROMIUM_WEBCRYPTO, CRYPTOPP, 'pass');
  const s2o = interopObs('s2o', CHROMIUM_WEBCRYPTO, CRYPTOPP, 'fail');
  const i1 = interopInstance('s1', [[CHROMIUM_WEBCRYPTO, CRYPTOPP]], [s1o]);
  const i2 = interopInstance('s2', [[CHROMIUM_WEBCRYPTO, CRYPTOPP]], [s2o]);
  const result = aggregateMutationClass(INTEROP_APPLICABILITY, [i1, i2], [s1o, s2o]);
  assert.equal(result.observedSpectrum.R_interop, 'fail');
  assert.equal(result.detectionSupport.evaluatedInstances, 2, 'both stimuli were evaluated');
  assert.equal(result.detectionSupport.divergentInstances, 1, 'only one of the two stimuli was divergent');
});

test('M3-H1b: a required scope with no matching observation at all throws AggregationIncompleteError, never silently promoted', () => {
  const o1 = interopObs('o1', CHROMIUM_WEBCRYPTO, CRYPTOPP, 'pass');
  // Required, but Chromium->BouncyCastle was never actually observed.
  const instance = interopInstance('s1', [[CHROMIUM_WEBCRYPTO, CRYPTOPP], [CHROMIUM_WEBCRYPTO, BOUNCY_CASTLE]], [o1]);
  assert.throws(() => aggregateMutationClass(INTEROP_APPLICABILITY, [instance], [o1]), AggregationIncompleteError);
});

test('M3-H1b: two observations resolving the identical required (relation,scope) throws DuplicateObservationError, never resolved arbitrarily', () => {
  const o1 = interopObs('o1', CHROMIUM_WEBCRYPTO, CRYPTOPP, 'pass');
  const o2 = interopObs('o2', CHROMIUM_WEBCRYPTO, CRYPTOPP, 'fail'); // same (relation,scope) as o1
  const instance = interopInstance('s1', [[CHROMIUM_WEBCRYPTO, CRYPTOPP]], [o1, o2]);
  assert.throws(() => aggregateMutationClass(INTEROP_APPLICABILITY, [instance], [o1, o2]), DuplicateObservationError);
});

test('M3-H1b: DetectionSupport counts by instance, never by scope -- a 6-direction relation does not outweigh a single-scope one', () => {
  const pairs: Array<readonly [typeof CHROMIUM_WEBCRYPTO, typeof CHROMIUM_WEBCRYPTO]> = [
    [CHROMIUM_WEBCRYPTO, CRYPTOPP], [CRYPTOPP, CHROMIUM_WEBCRYPTO],
    [CHROMIUM_WEBCRYPTO, BOUNCY_CASTLE], [BOUNCY_CASTLE, CHROMIUM_WEBCRYPTO],
    [CRYPTOPP, BOUNCY_CASTLE], [BOUNCY_CASTLE, CRYPTOPP],
  ];
  const observations = pairs.map(([from, to], i) => interopObs(`o${i}`, from, to, 'pass'));
  const instance = interopInstance('s1', pairs, observations);
  const result = aggregateMutationClass(INTEROP_APPLICABILITY, [instance], observations);
  assert.equal(result.detectionSupport.evaluatedInstances, 1, 'one instance, regardless of how many scopes it produced');
  assert.equal(result.detectionSupport.divergentInstances, 0);
});
