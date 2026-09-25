import { test } from 'node:test';
import assert from 'node:assert/strict';
import { evaluateSer } from '../../../harness/evaluators/r-ser.js';

const bothRequired = { representationConformance: true, materialPreservation: true };

test('R_ser: n/a when not applicable', () => {
  assert.equal(evaluateSer({ applicable: false, comparable: true, checksRequired: bothRequired, repOK: true, materialOK: true }), 'n/a');
});

test('R_ser: conformant when RepOK and MaterialOK both hold', () => {
  assert.equal(evaluateSer({ applicable: true, comparable: true, checksRequired: bothRequired, repOK: true, materialOK: true }), 'conformant');
});

test('R_ser: incomparable -> insufficient-evidence, NEVER divergent', () => {
  assert.equal(evaluateSer({ applicable: true, comparable: false, checksRequired: bothRequired, repOK: true, materialOK: true }), 'insufficient-evidence');
});

test('R_ser: RepOK=true, MaterialOK=false -> divergent (wrong material in a valid representation)', () => {
  // e.g. RSA-SER-PUBLIC-MATERIAL-DIVERGENCE: a syntactically perfect DER
  // encoding a different, still-valid key -- R_val would pass, R_ser must not.
  const r = evaluateSer({ applicable: true, comparable: true, checksRequired: bothRequired, repOK: true, materialOK: false });
  assert.equal(r, 'divergent');
});

test('R_ser: RepOK=false, MaterialOK=true -> divergent (right material, wrong representation)', () => {
  const r = evaluateSer({ applicable: true, comparable: true, checksRequired: bothRequired, repOK: false, materialOK: true });
  assert.equal(r, 'divergent');
});

test('R_ser: only one check required, the other is simply not evaluated', () => {
  const r = evaluateSer({
    applicable: true, comparable: true,
    checksRequired: { representationConformance: true, materialPreservation: false },
    repOK: true, materialOK: undefined,
  });
  assert.equal(r, 'conformant');
});


test('M3-reopen R_ser: observed failure dominates unavailable companion check', () => {
  assert.equal(
    evaluateSer({
      applicable: true,
      comparable: true,
      checksRequired: bothRequired,
      repOK: false,
      materialOK: undefined,
    }),
    'divergent',
  );

  assert.equal(
    evaluateSer({
      applicable: true,
      comparable: true,
      checksRequired: bothRequired,
      repOK: undefined,
      materialOK: false,
    }),
    'divergent',
  );
});

test('M3-reopen R_ser: absence without an observed failure remains insufficient', () => {
  assert.equal(
    evaluateSer({
      applicable: true,
      comparable: true,
      checksRequired: bothRequired,
      repOK: true,
      materialOK: undefined,
    }),
    'insufficient-evidence',
  );
});
