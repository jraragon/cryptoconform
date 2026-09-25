import { test } from 'node:test';
import assert from 'node:assert/strict';
import { evaluateVal } from '../../../harness/evaluators/r-val.js';

test('R_val: n/a when not applicable', () => {
  assert.equal(evaluateVal({ applicable: false, executionStatus: 'completed', expected: { kind: 'accept' }, observed: { kind: 'accept' } }), 'n/a');
});

test('R_val: conformant when decisions match (accept/accept)', () => {
  assert.equal(evaluateVal({ applicable: true, executionStatus: 'completed', expected: { kind: 'accept' }, observed: { kind: 'accept' } }), 'conformant');
});

test('R_val: divergent when accept was expected but reject was observed', () => {
  assert.equal(evaluateVal({ applicable: true, executionStatus: 'completed', expected: { kind: 'accept' }, observed: { kind: 'reject' } }), 'divergent');
});

test('R_val: a contractual reject is not an execution failure -- executionStatus=completed with outcome=reject is a valid comparison', () => {
  assert.equal(evaluateVal({ applicable: true, executionStatus: 'completed', expected: { kind: 'reject' }, observed: { kind: 'reject' } }), 'conformant');
});

test('R_val: infrastructure failure -> insufficient-evidence, NEVER a decision', () => {
  assert.equal(evaluateVal({ applicable: true, executionStatus: 'harness-error', expected: { kind: 'accept' }, observed: { kind: 'accept' } }), 'insufficient-evidence');
});

test('R_val: expected=verified(false), observed=verified(false) -> conformant (a false verdict is NOT automatically a failure)', () => {
  const r = evaluateVal({
    applicable: true, executionStatus: 'completed',
    expected: { kind: 'verified', value: false },
    observed: { kind: 'verified', value: false },
  });
  assert.equal(r, 'conformant');
});

test('R_val: verified(true) expected but verified(false) observed -> divergent', () => {
  const r = evaluateVal({
    applicable: true, executionStatus: 'completed',
    expected: { kind: 'verified', value: true },
    observed: { kind: 'verified', value: false },
  });
  assert.equal(r, 'divergent');
});

test('R_val: accept-normalized with a specific expected form must match that form, not just the kind', () => {
  const wrongForm = evaluateVal({
    applicable: true, executionStatus: 'completed',
    expected: { kind: 'accept-normalized', normalizedForm: 'canonical-A' },
    observed: { kind: 'accept-normalized', normalizedForm: 'canonical-B' },
  });
  assert.equal(wrongForm, 'divergent');
});
