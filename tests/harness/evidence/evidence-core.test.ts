import { test } from 'node:test';
import assert from 'node:assert/strict';

import { makeBaselineExecution, makeMutationExecution } from '../../../harness/evidence/execution-evidence.js';
import { makeRelationObservation, makeNotApplicableObservation, IllegalObservationStateError } from '../../../harness/evidence/relation-observation.js';
import { computeCompleteness, makeMutationInstanceResult, type PlannedObservation } from '../../../harness/evidence/mutation-instance-result.js';
import { makeMutationResult } from '../../../harness/evidence/mutation-result.js';
import { toRelationValue } from '../../../harness/evidence/relation-spectrum.js';
import { CHROMIUM_WEBCRYPTO } from '../../../harness/schema/backend-identity.js';

const commonFields = {
  operation: 'gcm' as const,
  subject: { backend: CHROMIUM_WEBCRYPTO, direction: 'encrypt' as const, path: 'sdk' as const },
  input: { kind: 'test-input' },
  outcome: { kind: 'accept' },
  clauseIdsEvaluated: [],
  executionStatus: 'completed' as const,
  provenance: { timestampIso: new Date().toISOString() },
};

test('phase in {A,B} <=> context.kind=baseline; phase=C <=> context.kind=mutation', () => {
  const baseline = makeBaselineExecution('A', 'baseline-1', commonFields);
  assert.equal(baseline.context.kind, 'baseline');
  assert.equal(baseline.context.phase, 'A');

  const mutation = makeMutationExecution('GCM-TAGLENGTH-PROFILE-BOUNDARY-BYPASS', 'tagLength-80', commonFields);
  assert.equal(mutation.context.kind, 'mutation');
  assert.equal(mutation.context.phase, 'C');

  // Illegal-by-construction: there is no code path through either factory
  // that could produce phase='C' with kind='baseline', or vice versa --
  // confirmed by the factories' own signatures, not by a runtime check.
});

test('MutationResult has no stimulusInstanceId and no backend field', () => {
  const instance = makeMutationInstanceResult({
    mutationId: 'GCM-TAGLENGTH-PROFILE-BOUNDARY-BYPASS',
    stimulusInstanceId: 'tagLength-80',
    operation: 'gcm',
    planned: [],
    observations: [],
  });
  const result = makeMutationResult({
    mutationId: 'GCM-TAGLENGTH-PROFILE-BOUNDARY-BYPASS',
    operation: 'gcm',
    gamma0Ref: 'registry:GCM-TAGLENGTH-PROFILE-BOUNDARY-BYPASS',
    applicability: { R_byte: true, R_interop: true, R_ser: true, R_val: true, R_err: true, R_cap: true },
    expectedSpectrum: {
      R_byte: { expectation: 'not-expected' }, R_interop: { expectation: 'not-expected' },
      R_ser: { expectation: 'not-expected' }, R_val: { expectation: 'detect' },
      R_err: { expectation: 'not-expected' }, R_cap: { expectation: 'detect' },
    },
    instanceResults: [instance],
    observedSpectrum: { R_byte: 'n/a', R_interop: 'n/a', R_ser: 'n/a', R_val: 'fail', R_err: 'n/a', R_cap: 'fail' },
    detectionSupport: { divergentInstances: 1, evaluatedInstances: 3 },
  });

  const keys = Object.keys(result);
  assert.ok(!keys.includes('stimulusInstanceId'), 'MutationResult must not carry stimulusInstanceId');
  assert.ok(!keys.includes('backend'), 'MutationResult must not carry a backend field');
  assert.ok(!keys.includes('backendIdentity'), 'MutationResult must not carry a backendIdentity field');
});

test('MutationInstanceResult carries exactly one stimulusInstanceId', () => {
  const instance = makeMutationInstanceResult({
    mutationId: 'PSS-SALTLENGTH-PROFILE-BYPASS', stimulusInstanceId: 'default', operation: 'pss',
    planned: [], observations: [],
  });
  assert.equal(typeof instance.stimulusInstanceId, 'string');
  assert.equal(instance.stimulusInstanceId, 'default');
});

test('n/a <=> Applicability=0, enforced by the factory, not left to caller discipline', () => {
  // Applicable relation, status='n/a' -> illegal.
  assert.throws(() => {
    makeRelationObservation({
      applicable: true,
      context: { kind: 'baseline', phase: 'B', baselineInstanceId: 'b1' },
      relation: 'R_val',
      scope: { kind: 'single-backend', backend: CHROMIUM_WEBCRYPTO },
      // @ts-expect-error -- 'n/a' is intentionally excluded from the accepted status type
      status: 'n/a',
      participants: [], evaluatorId: 'R_val', basis: 'test',
    });
  }, IllegalObservationStateError);

  // Inapplicable relation, status='pass' -> illegal.
  assert.throws(() => {
    makeRelationObservation({
      applicable: false,
      context: { kind: 'baseline', phase: 'B', baselineInstanceId: 'b1' },
      relation: 'R_byte',
      scope: { kind: 'single-backend', backend: CHROMIUM_WEBCRYPTO },
      status: 'pass',
      participants: [], evaluatorId: 'R_byte', basis: 'test',
    });
  }, IllegalObservationStateError);

  // Inapplicable relation via the dedicated factory -> legal, produces 'n/a'.
  const obs = makeNotApplicableObservation({
    context: { kind: 'baseline', phase: 'B', baselineInstanceId: 'b1' },
    relation: 'R_byte',
    scope: { kind: 'single-backend', backend: CHROMIUM_WEBCRYPTO },
    evaluatorId: 'R_byte', basis: 'test',
  });
  assert.equal(obs.status, 'n/a');
});

test('not-executed / insufficient-evidence can never become a scored RelationValue', () => {
  assert.equal(toRelationValue('conformant'), 'pass');
  assert.equal(toRelationValue('divergent'), 'fail');
  assert.equal(toRelationValue('n/a'), 'n/a');
  assert.equal(toRelationValue('not-executed'), undefined);
  assert.equal(toRelationValue('insufficient-evidence'), undefined);
});

test('complete=false forced when a required observation is non-terminal', () => {
  const planned: PlannedObservation[] = [
    { relation: 'R_val', scope: { kind: 'single-backend', backend: CHROMIUM_WEBCRYPTO }, executability: { kind: 'required' } },
  ];
  const { complete, outstanding } = computeCompleteness(planned, []); // no observations reached at all
  assert.equal(complete, false);
  assert.equal(outstanding.length, 1);
});

test('a structurally-not-executable planned observation never blocks completeness', () => {
  const planned: PlannedObservation[] = [
    { relation: 'R_cap', scope: { kind: 'single-backend', backend: CHROMIUM_WEBCRYPTO }, executability: { kind: 'structurally-not-executable', reason: 'backend-capability-absent' } },
  ];
  const { complete } = computeCompleteness(planned, []);
  assert.equal(complete, true);
});

// M3-H1a's own regression coverage lives in the dedicated
// tests/harness/evidence/m3-h1a-scope-completeness.test.ts (including a
// direct scopeEquals unit test across all four ObservationScope variants)
// -- not duplicated here.

test('traceability chain is constructible: MutationID -> StimulusInstanceID -> ExecutionID[] -> RelationObservationID[] -> MutationInstanceResult -> MutationResult', () => {
  const exec = makeMutationExecution('GCM-TAGLENGTH-PROFILE-BOUNDARY-BYPASS', 'tagLength-80', commonFields);
  const obs = makeRelationObservation({
    applicable: true,
    context: exec.context,
    relation: 'R_val',
    scope: { kind: 'single-backend', backend: CHROMIUM_WEBCRYPTO },
    status: 'fail',
    participants: [exec.executionId],
    evaluatorId: 'R_val', basis: 'test',
  });
  const instance = makeMutationInstanceResult({
    mutationId: 'GCM-TAGLENGTH-PROFILE-BOUNDARY-BYPASS', stimulusInstanceId: 'tagLength-80', operation: 'gcm',
    planned: [{ relation: 'R_val', scope: obs.scope, executability: { kind: 'required' } }],
    observations: [obs],
  });
  const result = makeMutationResult({
    mutationId: 'GCM-TAGLENGTH-PROFILE-BOUNDARY-BYPASS', operation: 'gcm',
    gamma0Ref: 'registry:GCM-TAGLENGTH-PROFILE-BOUNDARY-BYPASS',
    applicability: { R_byte: true, R_interop: true, R_ser: true, R_val: true, R_err: true, R_cap: true },
    expectedSpectrum: {
      R_byte: { expectation: 'not-expected' }, R_interop: { expectation: 'not-expected' },
      R_ser: { expectation: 'not-expected' }, R_val: { expectation: 'detect' },
      R_err: { expectation: 'not-expected' }, R_cap: { expectation: 'detect' },
    },
    instanceResults: [instance],
    observedSpectrum: { R_byte: 'n/a', R_interop: 'n/a', R_ser: 'n/a', R_val: 'fail', R_err: 'n/a', R_cap: 'n/a' },
    detectionSupport: { divergentInstances: 1, evaluatedInstances: 1 },
  });

  // Reconstruct the chain end to end.
  assert.equal(exec.context.kind, 'mutation');
  assert.equal(obs.participants[0], exec.executionId);
  assert.ok(instance.observations.includes(obs.observationId));
  assert.ok(result.instanceResultRefs.includes(`${instance.mutationId}::${instance.stimulusInstanceId}`));
  assert.equal(result.complete, true);
});
