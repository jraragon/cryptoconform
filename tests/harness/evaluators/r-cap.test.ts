import { test } from 'node:test';
import assert from 'node:assert/strict';
import { evaluateCap, CapabilityIndependenceViolation } from '../../../harness/evaluators/r-cap.js';

const supported = { kind: 'provider-support' as const, state: 'supported' as const };
const unsupported = { kind: 'provider-support' as const, state: 'unsupported' as const };

test('R_cap: n/a when not applicable', () => {
  const r = evaluateCap({ applicable: false, declared: supported, observed: supported, probeStatus: 'completed', declarationExecutionId: 'e1', scoredExecutionId: 'e2' });
  assert.equal(r, 'n/a');
});

test('R_cap: conformant when declared matches observed', () => {
  const r = evaluateCap({ applicable: true, declared: supported, observed: supported, probeStatus: 'completed', declarationExecutionId: 'e1', scoredExecutionId: 'e2' });
  assert.equal(r, 'conformant');
});

test('R_cap: divergent when declared differs from observed', () => {
  const r = evaluateCap({ applicable: true, declared: supported, observed: unsupported, probeStatus: 'completed', declarationExecutionId: 'e1', scoredExecutionId: 'e2' });
  assert.equal(r, 'divergent');
});

test('R_cap: probe failure -> insufficient-evidence, NEVER treated as observed=unsupported', () => {
  const r = evaluateCap({ applicable: true, declared: supported, observed: undefined, probeStatus: 'environment-error', declarationExecutionId: 'e1', scoredExecutionId: 'e2' });
  assert.equal(r, 'insufficient-evidence');
});

test('R_cap: same ExecutionID as both declared basis and scored evidence is rejected BEFORE any observation is produced', () => {
  assert.throws(() => {
    evaluateCap({
      applicable: true, declared: supported, observed: supported, probeStatus: 'completed',
      declarationExecutionId: 'exec-42', scoredExecutionId: 'exec-42', // identical -- tautology
    });
  }, CapabilityIndependenceViolation);
});

test('R_cap: distinct ExecutionIDs for the same operation type are legitimate (not a violation)', () => {
  // Both declaration and observation "ran HKDF" (or whatever operation) --
  // that shared mechanism is fine; only IDENTICAL execution identity is forbidden.
  const r = evaluateCap({ applicable: true, declared: supported, observed: supported, probeStatus: 'completed', declarationExecutionId: 'm1-exec-7', scoredExecutionId: 'm4-exec-91' });
  assert.equal(r, 'conformant');
});
