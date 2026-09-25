import { test } from 'node:test';
import assert from 'node:assert/strict';
import { evaluateErr } from '../../../harness/evaluators/r-err.js';

test('R_err: n/a when not applicable', () => {
  assert.equal(evaluateErr({ applicable: false, executionStatus: 'completed', rejectionOccurred: true, expectedErrorClass: 'invalid_key', observedErrorClass: 'invalid_key' }), 'n/a');
});

test('R_err: conformant when the exposed class matches exactly', () => {
  const r = evaluateErr({ applicable: true, executionStatus: 'completed', rejectionOccurred: true, expectedErrorClass: 'invalid_key', observedErrorClass: 'invalid_key' });
  assert.equal(r, 'conformant');
});

test('R_err: divergent when the exposed class differs', () => {
  const r = evaluateErr({ applicable: true, executionStatus: 'completed', rejectionOccurred: true, expectedErrorClass: 'invalid_key', observedErrorClass: 'invalid_parameter' });
  assert.equal(r, 'divergent');
});

test('R_err: infrastructure failure -> insufficient-evidence, never divergent', () => {
  const r = evaluateErr({ applicable: true, executionStatus: 'timeout', rejectionOccurred: true, expectedErrorClass: 'invalid_key', observedErrorClass: 'invalid_key' });
  assert.equal(r, 'insufficient-evidence');
});

test('R_err: expected rejection never materializes -> insufficient-evidence, NOT divergent (R_val records the actual divergence elsewhere)', () => {
  const r = evaluateErr({
    applicable: true, executionStatus: 'completed',
    rejectionOccurred: false, // the input was wrongly ACCEPTED -- R_val's own concern, not R_err's
    expectedErrorClass: 'invalid_key', observedErrorClass: undefined,
  });
  assert.equal(r, 'insufficient-evidence');
  assert.notEqual(r, 'divergent');
});

test('R_err: native exception details are never consulted -- only the SDK-layer class is compared', () => {
  // The evaluator's own input type has no field for a native exception at
  // all -- this test documents that fact rather than exercising a branch.
  const r = evaluateErr({ applicable: true, executionStatus: 'completed', rejectionOccurred: true, expectedErrorClass: 'invalid_key', observedErrorClass: 'invalid_key' });
  assert.equal(r, 'conformant'); // matches regardless of what any native exception said
});
