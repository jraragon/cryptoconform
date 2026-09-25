import { test } from 'node:test';
import assert from 'node:assert/strict';
import { evaluateInterop } from '../../../harness/evaluators/r-interop.js';

test('R_interop: n/a when not applicable', () => {
  assert.equal(evaluateInterop({
    applicable: false, producerValid: true, producerExecutionStatus: 'completed',
    consumerExecutionStatus: 'completed', sameBaselineOrStimulus: true,
    expectedOutcome: { kind: 'recover-bytes', expected: 'abc' },
  }), 'n/a');
});

test('R_interop: conformant when the consumer outcome matches expectations', () => {
  const r = evaluateInterop({
    applicable: true, producerValid: true, producerExecutionStatus: 'completed',
    consumerExecutionStatus: 'completed', sameBaselineOrStimulus: true,
    expectedOutcome: { kind: 'recover-bytes', expected: 'plaintext-M' },
    observedOutcome: { kind: 'recovered-plaintext', value: 'plaintext-M' },
  });
  assert.equal(r, 'conformant');
});

test('R_interop: divergent when the consumer outcome does not match', () => {
  const r = evaluateInterop({
    applicable: true, producerValid: true, producerExecutionStatus: 'completed',
    consumerExecutionStatus: 'completed', sameBaselineOrStimulus: true,
    expectedOutcome: { kind: 'recover-bytes', expected: 'plaintext-M' },
    observedOutcome: { kind: 'recovered-plaintext', value: 'WRONG' },
  });
  assert.equal(r, 'divergent');
});

test('R_interop: producer failure -> insufficient-evidence, NEVER a divergence', () => {
  const r = evaluateInterop({
    applicable: true, producerValid: false, producerExecutionStatus: 'completed',
    consumerExecutionStatus: 'completed', sameBaselineOrStimulus: true,
    expectedOutcome: { kind: 'recover-bytes', expected: 'plaintext-M' },
    observedOutcome: { kind: 'recovered-plaintext', value: 'plaintext-M' },
  });
  assert.equal(r, 'insufficient-evidence');
});

test('R_interop: expected rejection is a legitimate conformant outcome (tamper stimulus)', () => {
  const r = evaluateInterop({
    applicable: true, producerValid: true, producerExecutionStatus: 'completed',
    consumerExecutionStatus: 'completed', sameBaselineOrStimulus: true,
    expectedOutcome: { kind: 'reject', expectedErrorClass: 'authentication_failure' },
    observedOutcome: { kind: 'rejection', value: undefined, errorClass: 'authentication_failure' },
  });
  assert.equal(r, 'conformant');
});

test('R_interop: Obs(p->q) != Obs(q->p) as genuinely independent possibilities', () => {
  // Same underlying material, opposite directions: one conformant, one divergent.
  const pToQ = evaluateInterop({
    applicable: true, producerValid: true, producerExecutionStatus: 'completed',
    consumerExecutionStatus: 'completed', sameBaselineOrStimulus: true,
    expectedOutcome: { kind: 'import-material', expected: 'K' },
    observedOutcome: { kind: 'imported-key-material', value: 'K' }, // q correctly imports p's export
  });
  const qToP = evaluateInterop({
    applicable: true, producerValid: true, producerExecutionStatus: 'completed',
    consumerExecutionStatus: 'completed', sameBaselineOrStimulus: true,
    expectedOutcome: { kind: 'import-material', expected: 'K' },
    observedOutcome: { kind: 'imported-key-material', value: 'CORRUPTED' }, // p fails to import q's export
  });
  assert.equal(pToQ, 'conformant');
  assert.equal(qToP, 'divergent');
  assert.notEqual(pToQ, qToP); // demonstrates the evaluator does not canonicalize the pair like R_byte does
});
