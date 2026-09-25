import { test } from 'node:test';
import assert from 'node:assert/strict';
import { evaluateByte } from '../../../harness/evaluators/r-byte.js';

test('R_byte: n/a when not applicable', () => {
  assert.equal(evaluateByte({ applicable: false, inputsEquivalent: true, left: { executionStatus: 'completed' }, right: { executionStatus: 'completed' } }), 'n/a');
});

test('R_byte: conformant when bytes are identical', () => {
  const out = { kind: 'raw-output' as const, bytes: 'deadbeef' };
  const r = evaluateByte({
    applicable: true, inputsEquivalent: true,
    left: { executionStatus: 'completed', comparableOutput: out },
    right: { executionStatus: 'completed', comparableOutput: { ...out } },
  });
  assert.equal(r, 'conformant');
});

test('R_byte: divergent when bytes differ', () => {
  const r = evaluateByte({
    applicable: true, inputsEquivalent: true,
    left: { executionStatus: 'completed', comparableOutput: { kind: 'raw-output', bytes: 'deadbeef' } },
    right: { executionStatus: 'completed', comparableOutput: { kind: 'raw-output', bytes: 'beefdead' } },
  });
  assert.equal(r, 'divergent');
});

test('R_byte: incomparable evidence -> insufficient-evidence, NEVER divergent', () => {
  const r1 = evaluateByte({
    applicable: true, inputsEquivalent: true,
    left: { executionStatus: 'harness-error' },
    right: { executionStatus: 'completed', comparableOutput: { kind: 'raw-output', bytes: 'deadbeef' } },
  });
  assert.equal(r1, 'insufficient-evidence');

  const r2 = evaluateByte({
    applicable: true, inputsEquivalent: false, // inputs not equivalent -> not comparable
    left: { executionStatus: 'completed', comparableOutput: { kind: 'raw-output', bytes: 'deadbeef' } },
    right: { executionStatus: 'completed', comparableOutput: { kind: 'raw-output', bytes: 'deadbeef' } },
  });
  assert.equal(r2, 'insufficient-evidence');
});

test('R_byte: strict equality only -- no normalization, "equivalent" but differently-formatted bytes are divergent', () => {
  // e.g. hypothetical case where a DER re-encoding would be "materially
  // equivalent" but is a genuinely different byte string -- R_byte must not
  // reconcile this; that distinction belongs to R_ser, never here.
  const r = evaluateByte({
    applicable: true, inputsEquivalent: true,
    left: { executionStatus: 'completed', comparableOutput: { kind: 'canonical-serialization', bytes: '3082010a...case-A' } },
    right: { executionStatus: 'completed', comparableOutput: { kind: 'canonical-serialization', bytes: '3082010a...case-B-reencoded' } },
  });
  assert.equal(r, 'divergent');
});
