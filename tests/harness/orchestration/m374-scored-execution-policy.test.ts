// M3.7.4 / D14 -- the scored execution policy gate.
//
// The policy is exercised with the REAL plan for its cardinalities and with
// synthetic, unambiguously non-scored data for its mechanics. No scored run,
// not even a trial one.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';

import {
  assertCommitConsistent, assertRunComplete, assertRunIdentityComplete, assessCompletion,
  blockOf, compareObligations, dispositionOf, digestOf, ExecutionPolicyError, FAILURE_POLICY,
  MAX_ATTEMPTS, mayRetry, orderIsResultIndependent, RETRYABLE, scoredOrder,
  SCORED_EXECUTION_POLICY_VERSION, type BlockCommit, type FailureKind, type OrderableObligation,
} from '../../../harness/orchestration/scored-execution-policy.js';
import { assembleStructuralPlan } from '../../../harness/phase-c/plan-assembly.js';
import { loadFrozenMaterialPool } from '../../../harness/phase-c/material/load.js';
import { bindRequiredObligations } from '../../../harness/phase-c/execution-binding.js';

const pool = loadFrozenMaterialPool();
const all = bindRequiredObligations(assembleStructuralPlan(pool), pool);
const obligations: OrderableObligation[] = all.map((o) => ({
  operation: o.operation, mutationId: o.mutationId, stimulusInstanceId: o.stimulusInstanceId,
  relation: o.relation, scopeKey: JSON.stringify(o.scope),
}));

// =====================================================================
// 1. Unit: blockwise, and class-aligned BY CONSTRUCTION
// =====================================================================

test('D14: no block can split a mutation class', () => {
  // The property that makes blockwise safe: aggregation is per class, so a
  // class split across blocks would compute r(c) on partial instances.
  const blockByClass = new Map<string, Set<string>>();
  for (const o of all) {
    const s = blockByClass.get(o.mutationId) ?? new Set<string>();
    s.add(blockOf(o.operation));
    blockByClass.set(o.mutationId, s);
  }
  for (const [mutationId, blocks] of blockByClass) {
    assert.equal(blocks.size, 1, `${mutationId} spans ${blocks.size} blocks; r(c) would be computed on partial instances`);
  }
  assert.equal(blockByClass.size, 73);
});

test('D14: blocks partition the required population exactly', () => {
  const counts = new Map<string, number>();
  for (const o of all) counts.set(blockOf(o.operation), (counts.get(blockOf(o.operation)) ?? 0) + 1);
  assert.equal([...counts.values()].reduce((a, b) => a + b, 0), 886);
  assert.equal(counts.size, 6, 'one block per operation');
});

// =====================================================================
// 2. Total deterministic order
// =====================================================================

test('D14: the order is total and derived from normative identities alone', () => {
  const ordered = scoredOrder(obligations);
  assert.equal(ordered.length, 886);
  const keys = ordered.map((o) => `${o.operation}|${o.mutationId}|${o.stimulusInstanceId}|${o.relation}|${o.scopeKey}`);
  assert.equal(new Set(keys).size, keys.length, 'the order must be total: no ties');
  for (let i = 1; i < ordered.length; i += 1) {
    assert.ok(compareObligations(ordered[i - 1]!, ordered[i]!) < 0, 'strictly increasing');
  }
});

test('D14: the order does not depend on input order -- so no result can have shaped it', () => {
  assert.equal(orderIsResultIndependent(obligations), true);
  // And explicitly: a reversed input yields the identical sequence.
  const a = scoredOrder(obligations).map((o) => o.mutationId + o.relation + o.scopeKey);
  const b = scoredOrder([...obligations].reverse()).map((o) => o.mutationId + o.relation + o.scopeKey);
  assert.deepEqual(a, b);
});

test('D14: collation is codepoint-based, never locale-sensitive', () => {
  const src = readFileSync(new URL('../../../harness/orchestration/scored-execution-policy.ts', import.meta.url), 'utf8');
  const code = src.split('\n').filter((l) => !l.trimStart().startsWith('//') && !l.trimStart().startsWith('*'));
  assert.ok(!code.some((l) => l.includes('localeCompare')), 'locale collation would make the order machine-dependent');
});

// =====================================================================
// 3. Failure semantics
// =====================================================================

test('D14: an instrument failure NEVER becomes a scientific result', () => {
  for (const kind of ['environment-mismatch', 'projection-error', 'binding-error', 'harness-error', 'timeout', 'backend-crash'] as FailureKind[]) {
    assert.notEqual(dispositionOf(kind), 'experimental-observation', kind);
  }
  assert.equal(dispositionOf('environment-mismatch'), 'abort-run');
  assert.equal(dispositionOf('projection-error'), 'abort-run');
  assert.equal(dispositionOf('harness-error'), 'void-block');
});

test('D14: the three genuinely experimental states are recorded as science', () => {
  for (const kind of ['contractual-rejection', 'insufficient-evidence', 'non-scoreable'] as FailureKind[]) {
    assert.equal(dispositionOf(kind), 'experimental-observation', kind);
  }
});

test('D14: every classified kind states WHY, and an unlisted kind is refused', () => {
  for (const [kind, row] of Object.entries(FAILURE_POLICY)) {
    assert.ok(row.why.length > 60, `${kind}: a disposition needs a reason, not a label`);
  }
  assert.throws(() => dispositionOf('mystery' as FailureKind), ExecutionPolicyError);
  assert.throws(() => dispositionOf('mystery' as FailureKind), /must not be improvised into a result/);
});

// =====================================================================
// 4. Retry
// =====================================================================

test('D14: retry only where the backend never answered', () => {
  assert.deepEqual([...RETRYABLE].sort(), ['backend-crash', 'timeout']);
  assert.equal(mayRetry('timeout', 1), true);
  assert.equal(mayRetry('backend-crash', 1), true);
  assert.equal(mayRetry('timeout', MAX_ATTEMPTS), false, 'bounded');
});

test('D14: NO retry on a result -- there is no such path', () => {
  for (const kind of ['contractual-rejection', 'insufficient-evidence', 'non-scoreable', 'harness-error', 'projection-error'] as FailureKind[]) {
    assert.equal(mayRetry(kind, 1), false, `${kind} must never be retried`);
  }
});

// =====================================================================
// 5. Persistence and atomicity
// =====================================================================

const commit = (blockId: string, over: Partial<BlockCommit> = {}): BlockCommit => ({
  blockId, runId: 'run-1', policyVersion: SCORED_EXECUTION_POLICY_VERSION,
  obligationCount: 10, digest: digestOf(blockId), attempt: 1, ...over,
});

test('D14: a block cannot be committed twice -- two attempts are never mixed', () => {
  assert.doesNotThrow(() => assertCommitConsistent([commit('block:gcm'), commit('block:oaep')]));
  assert.throws(() => assertCommitConsistent([commit('block:gcm'), commit('block:gcm', { attempt: 2 })]),
    /committed twice/);
});

test('D14: blocks from different policies or different runs are not one dataset', () => {
  assert.throws(() => assertCommitConsistent([commit('block:gcm', { policyVersion: 'M3.7.4/0' })]),
    /not one dataset/);
  assert.throws(() => assertCommitConsistent([commit('block:gcm'), commit('block:pss', { runId: 'run-2' })]),
    /one dataset comes from one run/);
});

// =====================================================================
// 6. Run identity
// =====================================================================

test('D14: the dataset must be able to prove how it was produced', () => {
  assert.throws(() => assertRunIdentityComplete({ runId: 'r' }), /could not prove how it was produced/);
  assert.doesNotThrow(() => assertRunIdentityComplete({
    runId: 'r', policyVersion: SCORED_EXECUTION_POLICY_VERSION, instrumentCommit: 'abc',
    plannedObligations: 1641, requiredObligations: 1192, environmentDigest: 'def',
  }));
});

// =====================================================================
// 7. Completion gate
// =====================================================================

test('D14: complete means EXACTLY the required population, both directions', () => {
  assert.equal(assessCompletion(['a', 'b'], ['a', 'b']).complete, true);
  const missing = assessCompletion(['a', 'b'], ['a']);
  assert.deepEqual(missing.missing, ['b']);
  assert.equal(missing.complete, false);
  // A run that scored something nobody pre-registered is not complete either.
  const extra = assessCompletion(['a'], ['a', 'z']);
  assert.deepEqual(extra.unexpected, ['z']);
  assert.equal(extra.complete, false);
});

test('D14: there is no keep-what-succeeded path', () => {
  assert.throws(() => assertRunComplete(assessCompletion(['a', 'b'], ['a'])),
    /Refusing to treat a partial population as a dataset/);
  // The gate takes both sets and returns a verdict; it cannot return a subset.
  const src = readFileSync(new URL('../../../harness/orchestration/scored-execution-policy.ts', import.meta.url), 'utf8');
  assert.ok(!src.includes('keepSuccessful') && !src.includes('partialDataset'));
});

test('D14: the real required population is what the gate would demand', () => {
  const keys = all.map((o) => `${o.mutationId}|${o.stimulusInstanceId}|${o.relation}|${JSON.stringify(o.scope)}`);
  assert.equal(keys.length, 886);
  assert.equal(assessCompletion(keys, keys).complete, true);
  assert.equal(assessCompletion(keys, keys.slice(0, -1)).complete, false);
});

// =====================================================================
// 8. No adaptive inspection
// =====================================================================

test('D14: the policy reads no result to decide anything', () => {
  const src = readFileSync(new URL('../../../harness/orchestration/scored-execution-policy.ts', import.meta.url), 'utf8');
  const imports = src.split('\n').filter((l) => l.trimStart().startsWith('import'));
  for (const line of imports) {
    for (const forbidden of ['execution-evidence', 'relation-observation', 'relation-spectrum', 'evidence-export', 'aggregation/']) {
      assert.ok(!line.includes(forbidden), `the policy must not see results: ${line.trim()}`);
    }
  }
});

test('D14: the policy version is frozen and cited by every commit', () => {
  assert.equal(SCORED_EXECUTION_POLICY_VERSION, 'M3.7.4/1');
  assert.equal(commit('block:gcm').policyVersion, SCORED_EXECUTION_POLICY_VERSION);
});
