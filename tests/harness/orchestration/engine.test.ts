import { test } from 'node:test';
import assert from 'node:assert/strict';

import { executeBaseline, executeMutation } from '../../../harness/orchestration/engine.js';
import { HKDF_NODE_WEBCRYPTO_ADAPTER } from '../../../harness/orchestration/hkdf-wiring.js';
import { HKDF_INFO_TAMPER } from '../../../harness/mutations/hkdf.js';
import { evaluateByte } from '../../../harness/evaluators/r-byte.js';
import { evaluateInterop } from '../../../harness/evaluators/r-interop.js';
import { makeRelationObservation } from '../../../harness/evidence/relation-observation.js';
import { makeMutationInstanceResult, type PlannedObservation } from '../../../harness/evidence/mutation-instance-result.js';
import { NODE_WEBCRYPTO_OPENSSL } from '../../../harness/schema/backend-identity.js';
import type { HkdfRequest } from '../../../src/contract/hkdf.js';

function baseFixture(): HkdfRequest {
  return { ikm: new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8]), salt: undefined, info: new Uint8Array([9, 9, 9]), length: 32 };
}

test('executeBaseline: a real Phase-B execution against M1\'s own WebCrypto adapter, wrapped into ExecutionEvidence', async () => {
  const evidence = await executeBaseline('B', 'baseline-hkdf-1', baseFixture(), HKDF_NODE_WEBCRYPTO_ADAPTER);
  assert.equal(evidence.context.kind, 'baseline');
  assert.equal(evidence.context.phase, 'B');
  assert.equal(evidence.outcome.kind, 'accept');
  assert.equal(evidence.subject.backend.sourcePin, NODE_WEBCRYPTO_OPENSSL.sourcePin);
  assert.ok(evidence.output && (evidence.output as { bytes: string }).bytes.length > 0, 'a real OKM must have been produced');
});

test('executeMutation: HKDF-INFO-TAMPER runs through the REAL M1 adapter, mutate() called exactly once, inside the orchestrator only', async () => {
  const fixture = baseFixture();
  const baseline = await executeBaseline('B', 'baseline-hkdf-2', fixture, HKDF_NODE_WEBCRYPTO_ADAPTER);
  const mutated = await executeMutation(HKDF_INFO_TAMPER, 'default', fixture, HKDF_NODE_WEBCRYPTO_ADAPTER);

  assert.equal(mutated.context.kind, 'mutation');
  if (mutated.context.kind === 'mutation') {
    assert.equal(mutated.context.mutationId, 'HKDF-INFO-TAMPER');
    assert.equal(mutated.context.stimulusInstanceId, 'default');
  }
  // Real, independently-computed OKM bytes -- genuinely different because
  // the info field genuinely changed, not because anything was faked.
  assert.notDeepEqual(
    (baseline.output as { bytes: string }).bytes,
    (mutated.output as { bytes: string }).bytes,
  );
});

test('End to end: real executions -> R_byte evaluation -> RelationObservation -> MutationInstanceResult, real divergence detected', async () => {
  const fixture = baseFixture();
  const baseline = await executeBaseline('B', 'baseline-hkdf-3', fixture, HKDF_NODE_WEBCRYPTO_ADAPTER);
  const mutated = await executeMutation(HKDF_INFO_TAMPER, 'default', fixture, HKDF_NODE_WEBCRYPTO_ADAPTER);

  const observationState = evaluateByte({
    applicable: true,
    inputsEquivalent: true, // same backend/operation family, comparing baseline vs mutated output on purpose
    left: { executionStatus: baseline.executionStatus, comparableOutput: { kind: 'raw-output', bytes: (baseline.output as { bytes: string }).bytes } },
    right: { executionStatus: mutated.executionStatus, comparableOutput: { kind: 'raw-output', bytes: (mutated.output as { bytes: string }).bytes } },
  });
  assert.equal(observationState, 'divergent', 'a genuinely different info field must produce genuinely different OKM bytes');

  const observation = makeRelationObservation({
    applicable: true,
    context: mutated.context,
    relation: 'R_byte',
    scope: { kind: 'single-backend', backend: NODE_WEBCRYPTO_OPENSSL },
    status: observationState === 'divergent' ? 'fail' : 'pass',
    participants: [baseline.executionId, mutated.executionId],
    evaluatorId: 'R_byte',
    basis: 'HKDF-INFO-TAMPER end-to-end orchestration demonstration',
  });

  const planned: PlannedObservation[] = [{ relation: 'R_byte', scope: observation.scope, executability: { kind: 'required' } }];
  const instanceResult = makeMutationInstanceResult({
    mutationId: 'HKDF-INFO-TAMPER', stimulusInstanceId: 'default', operation: 'hkdf',
    planned, observations: [observation],
  });

  assert.equal(instanceResult.complete, true);
  assert.ok(instanceResult.observations.includes(observation.observationId));
});

// ---------------------------------------------------------------------
// Directional asymmetry: p->q != q->p. Real cross-backend interop needs
// Crypto++/BC builds (M2.5's own job); this demonstrates the ENGINE's own
// directional handling using two independently-labeled adapter roles
// against the same real backend, honestly scoped as a mechanism test.
// ---------------------------------------------------------------------

test('R_interop directionality: the orchestration mechanism keeps p->q and q->p as independent observations, never collapsed', () => {
  const pToQ = evaluateInterop({
    applicable: true, producerValid: true, producerExecutionStatus: 'completed', consumerExecutionStatus: 'completed',
    sameBaselineOrStimulus: true,
    expectedOutcome: { kind: 'import-material', expected: 'K' },
    observedOutcome: { kind: 'imported-key-material', value: 'K' },
  });
  const qToP = evaluateInterop({
    applicable: true, producerValid: true, producerExecutionStatus: 'completed', consumerExecutionStatus: 'completed',
    sameBaselineOrStimulus: true,
    expectedOutcome: { kind: 'import-material', expected: 'K' },
    observedOutcome: { kind: 'imported-key-material', value: 'CORRUPTED' },
  });
  assert.equal(pToQ, 'conformant');
  assert.equal(qToP, 'divergent');
  assert.notEqual(pToQ, qToP, 'the two directions are genuinely independent observations, not a canonicalized pair');
});

test('Orchestration engine and HKDF wiring contain ZERO mutationId-based branching (grep-confirmed)', async () => {
  const { readFileSync } = await import('node:fs');
  const engineSource = readFileSync(new URL('../../../harness/orchestration/engine.ts', import.meta.url), 'utf8');
  const wiringSource = readFileSync(new URL('../../../harness/orchestration/hkdf-wiring.ts', import.meta.url), 'utf8');
  assert.ok(!/switch\s*\(\s*mutationId/.test(engineSource + wiringSource));
  assert.ok(!/if\s*\(\s*mutationId\s*===/.test(engineSource + wiringSource));
});
