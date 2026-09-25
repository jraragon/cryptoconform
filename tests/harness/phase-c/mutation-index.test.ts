import { test } from 'node:test';
import assert from 'node:assert/strict';

import { MUTATION_INDEX, getMutationImplementation, indexedMutationIds, MutationIndexError } from '../../../harness/phase-c/mutation-index.js';
import { MUTATION_REGISTRY } from '../../../harness/registry/mutations.js';

// ---------------------------------------------------------------------
// M3.2.4b, first micro-step. Before any fixture resolver or plan binding
// exists, the most basic structural gap must be closed: there was no
// mutationId -> MutationImplementation lookup anywhere in the codebase, so
// no ExecutionPlan could be built systematically. These tests hold the
// index to EQUALITY with the frozen registry, never containment:
//     RegistryMutationIDs == IndexedMutationIDs
// ---------------------------------------------------------------------

test('M3.2.4b: the index resolves exactly 79 implementations', () => {
  assert.equal(MUTATION_INDEX.size, 79);
});

test('M3.2.4b: RegistryMutationIDs == IndexedMutationIDs -- no missing, no orphans (equality, not subset)', () => {
  const registryIds = MUTATION_REGISTRY.map((e) => e.mutationId).sort();
  assert.deepEqual(indexedMutationIds(), registryIds);
});

test('M3.2.4b: every registry class resolves to an implementation carrying its own id', () => {
  for (const entry of MUTATION_REGISTRY) {
    const impl = getMutationImplementation(entry.mutationId);
    assert.equal(impl.mutationId, entry.mutationId);
    assert.equal(typeof impl.mutate, 'function');
    assert.ok(Array.isArray(impl.directInterventionTargets));
    assert.ok(impl.directInterventionTargets.length > 0, `${entry.mutationId} must declare at least one direct intervention target`);
  }
});

test('M3.2.4b: an unknown mutationId fails closed', () => {
  assert.throws(() => getMutationImplementation('NO-SUCH-MUTATION'), MutationIndexError);
});

test('M3.2.4b: the index covers all six operations, in the registry own proportions', () => {
  const perOperation = new Map<string, number>();
  for (const entry of MUTATION_REGISTRY) {
    perOperation.set(entry.operation, (perOperation.get(entry.operation) ?? 0) + 1);
  }
  // Every counted class must be individually resolvable -- the totals alone
  // could hide a swap between operations.
  for (const entry of MUTATION_REGISTRY) {
    assert.ok(MUTATION_INDEX.has(entry.mutationId), `${entry.operation}: ${entry.mutationId} missing from the index`);
  }
  assert.equal([...perOperation.values()].reduce((a, b) => a + b, 0), 79);
  assert.equal(perOperation.size, 6);
});

test('M3.2.4b: mutationId is unique across the whole corpus', () => {
  const ids = MUTATION_REGISTRY.map((e) => e.mutationId);
  assert.equal(new Set(ids).size, ids.length, 'the frozen registry itself must carry no duplicate id');
  assert.equal(MUTATION_INDEX.size, new Set(ids).size);
});

test('M3.2.4b: the index is built structurally, not from a hand-maintained list -- it contains no literal 79-entry enumeration', async () => {
  const { readFileSync } = await import('node:fs');
  const src = readFileSync(new URL('../../../harness/phase-c/mutation-index.ts', import.meta.url), 'utf8');
  // A hand-written list would have to name individual mutation ids. The
  // index must derive its contents by walking the modules instead, so that
  // adding a class to a module cannot silently leave the index stale.
  const namedMutationIds = MUTATION_REGISTRY.filter((e) => src.includes(`'${e.mutationId}'`));
  assert.deepEqual(namedMutationIds, [], 'no individual mutationId may be hard-coded in the index');
});
