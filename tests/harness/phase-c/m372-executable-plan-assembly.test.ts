// M3.7.2 -- executable-plan assembly gate.
//
// Every figure below is a DERIVED RESULT of walking the plan, never a
// condition the binder was programmed against.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';

import { assembleStructuralPlan } from '../../../harness/phase-c/plan-assembly.js';
import { loadFrozenMaterialPool } from '../../../harness/phase-c/material/load.js';
import { PHASE_C_MATERIAL_IDS } from '../../../harness/phase-c/material/load.js';
import {
  bindMaterial, bindObservation, bindRequiredObligations, BindingError,
  directedTransferObligations, nonInteropObligations,
} from '../../../harness/phase-c/execution-binding.js';
import {
  dispatchSymbols, materializableSymbols, materializeDispatch, MaterializationError,
} from '../../../harness/orchestration/dispatch-materialization.js';
import { DISPATCH_TABLE, DispatchError } from '../../../harness/orchestration/dispatch.js';
import { wrapSerializationExecution } from '../../../harness/evidence/serialization-execution.js';
import { recountPlan } from '../../../harness/phase-c/plan-binding-audit.js';
import { BOUNCY_CASTLE, CHROMIUM_WEBCRYPTO, CRYPTOPP } from '../../../harness/schema/backend-identity.js';
import type { ObservationScope } from '../../../harness/evidence/observation-scope.js';

const pool = loadFrozenMaterialPool();
const plan = assembleStructuralPlan(pool);
const all = bindRequiredObligations(plan, pool);

// =====================================================================
// Selection: the predicate, and nothing else
// =====================================================================

test('M3.7.2: the binder selects through isRequiredEvidence, never by name or counter', () => {
  const src = readFileSync(new URL('../../../harness/phase-c/execution-binding.ts', import.meta.url), 'utf8');
  assert.ok(src.includes('isRequiredEvidence('), 'the normative predicate must be called');
  // The forbidden shortcuts, each checked on non-comment lines so the prose
  // explaining why they are forbidden does not trip the guard.
  const code = src.split('\n').filter((l) => !l.trimStart().startsWith('//') && !l.trimStart().startsWith('*'));
  for (const forbidden of ['planCardinality', "=== 'required'", '1264', '904', '316']) {
    assert.ok(!code.some((l) => l.includes(forbidden)), `the binder must not use '${forbidden}'`);
  }
});

test('M3.7.2: the binder agrees with recountPlan, because both consume one predicate', () => {
  assert.equal(all.length, recountPlan(plan).required,
    'two independent walks of the plan must agree -- this is what D13 lacked');
});

// =====================================================================
// The derived counts
// =====================================================================

test('M3.7.2: 886 = 670 non-interop + 216 directed-transfer', () => {
  const ni = nonInteropObligations(all);
  const dt = directedTransferObligations(all);
  assert.equal(all.length, 886); // final M3-reopen-v5 population
  assert.equal(ni.length, 670);
  assert.equal(dt.length, 216);
  assert.equal(ni.length + dt.length, all.length);
});

test('M3.7.2: the non-interop breakdown sums to 670', () => {
  const byRel: Record<string, number> = {};
  for (const o of nonInteropObligations(all)) byRel[o.relation] = (byRel[o.relation] ?? 0) + 1;
  assert.deepEqual(byRel, { R_cap: 238, R_val: 209, R_byte: 42, R_ser: 90, R_err: 91 });
  assert.equal(Object.values(byRel).reduce((a, b) => a + b, 0), 670);
});

test('M3.7.2: every obligation is bound -- none is left without a binding', () => {
  // 'manifest' joined the union at M3.8.2. Collapsing it into 'single-backend'
  // gave every R_cap obligation an execution role its relation does not have,
  // and the frozen model had always kept the two scopes distinct.
  for (const o of all) {
    assert.ok(['single-backend', 'backend-set', 'directed-transfer', 'manifest'].includes(o.binding.kind));
  }
  // The bijection that stops the collapse from returning silently.
  for (const o of all) {
    assert.equal(o.scope.kind === 'manifest', o.binding.kind === 'manifest', `${o.mutationId}/${o.relation}`);
  }
});

// =====================================================================
// Shapes: discriminated by EXECUTION, not by relation
// =====================================================================

test('M3.7.2: R_byte binds as a symmetric backend-set, with both backends from the SCOPE', () => {
  const rbyte = all.filter((o) => o.relation === 'R_byte');
  assert.equal(rbyte.length, 42);
  for (const o of rbyte) {
    assert.equal(o.binding.kind, 'backend-set');
    if (o.binding.kind !== 'backend-set') throw new Error('unreachable');
    assert.equal(o.binding.backends.length, 2);
    // The binder did not pick them: they are the scope's own.
    assert.equal(o.scope.kind, 'cross-backend-set');
    if (o.scope.kind !== 'cross-backend-set') throw new Error('unreachable');
    assert.deepEqual(o.binding.backends.map((b) => b.family), o.scope.backends.map((b) => b.family));
    // Symmetric: no producer, no consumer, and none inferable.
    assert.ok(!('from' in o.binding) && !('producerRole' in o.binding));
  }
});

test('M3.7.2: R_interop binds as a DIRECTED transfer with explicit roles', () => {
  const dt = directedTransferObligations(all);
  assert.equal(dt.length, 216);
  for (const o of dt) {
    if (o.binding.kind !== 'directed-transfer') throw new Error('unreachable');
    assert.equal(o.scope.kind, 'backend-pair');
    if (o.scope.kind !== 'backend-pair') throw new Error('unreachable');
    // Direction is DATA, not a closure: from, to and both roles are readable.
    assert.equal(o.binding.from.family, o.scope.from.family);
    assert.equal(o.binding.to.family, o.scope.to.family);
    assert.notEqual(o.binding.producerRole, o.binding.consumerRole);
    assert.notEqual(o.binding.from.family, o.binding.to.family);
    assert.ok(o.binding.producer.entry.role === o.binding.producerRole);
    assert.ok(o.binding.consumer.entry.role === o.binding.consumerRole);
  }
});

test('M3.7.2: A->B and B->A are bound as DISTINCT obligations', () => {
  const dt = directedTransferObligations(all);
  const keys = new Set(dt.map((o) => {
    if (o.binding.kind !== 'directed-transfer') throw new Error('unreachable');
    return `${o.mutationId}::${o.stimulusInstanceId}::${o.binding.from.family}->${o.binding.to.family}`;
  }));
  assert.equal(keys.size, 216, 'no direction may collapse into its reverse');
});

// =====================================================================
// M3.7.2 / M3.7.3 boundary: bound is NOT executable
// =====================================================================

test('M3.7.2: the directed-transfer population remains its own query, so no total absorbs it', () => {
  // INVERTED DELIBERATELY BY M3.7.3. This pin asserted that runTransfer was
  // not yet wired, and it was written to be broken by exactly that milestone.
  // What it protected survives and is what is asserted now: the count is
  // still its own query, so a bound obligation can never be quoted inside a
  // total as though it were something else -- the ambiguity D13 was.
  assert.equal(directedTransferObligations(all).length, 216);
  assert.equal(nonInteropObligations(all).length, 670);
  assert.equal(all.length, 886); // final M3-reopen-v5 population
  const glue = readFileSync(new URL('../../../harness/phase-c/resolve-glue.ts', import.meta.url), 'utf8');
  // And the refusal is NOT removed: it now guards the absence of the binding
  // rather than the relation, so an interop claim still cannot be assembled
  // from a single execution.
  assert.ok(glue.includes('Refusing rather than'), 'the refusal now guards the absence of the binding');
  assert.ok(glue.includes('runTransfer('), 'wired at M3.7.3');
});

// =====================================================================
// Material: NOMINAL identity, never uniqueness
// =====================================================================

test('M3.7.2: material is bound by frozen NOMINAL id, and the corpus is never searched', () => {
  const src = readFileSync(new URL('../../../harness/phase-c/execution-binding.ts', import.meta.url), 'utf8');
  assert.ok(src.includes('PHASE_C_MATERIAL_IDS.rsa'));
  assert.ok(src.includes('PHASE_C_MATERIAL_IDS.ec'));
  const code = src.split('\n').filter((l) => !l.trimStart().startsWith('//') && !l.trimStart().startsWith('*'));
  for (const forbidden of ['.find(', '.filter(', 'records']) {
    assert.ok(!code.some((l) => l.includes(forbidden) && l.includes('material')),
      `material must not be located by search ('${forbidden}')`);
  }
});

test('M3.7.2: the named material resolves for the operations that need it', () => {
  assert.equal(bindMaterial('oaep', pool)?.materialId, PHASE_C_MATERIAL_IDS.rsa);
  assert.equal(bindMaterial('pss', pool)?.materialId, PHASE_C_MATERIAL_IDS.rsa);
  assert.equal(bindMaterial('rsa-ser', pool)?.materialId, PHASE_C_MATERIAL_IDS.rsa);
  assert.equal(bindMaterial('ec-ser', pool)?.materialId, PHASE_C_MATERIAL_IDS.ec);
  // GCM binds the AES Phase-C record from M3.7.3 on: an ARTIFACT-SIDE
  // obligation needs the producer's own inputs, which live there and not in
  // the fixture. Request-side GCM ignores it.
  assert.equal(bindMaterial('gcm', pool)?.materialId, 'aes-phasec-primary-01');
  // HKDF binds none: it has no producer/consumer split at all.
  assert.equal(bindMaterial('hkdf', pool), undefined);
});

test('M3.7.2: material binding is fail-closed on a pool that lacks the named record', () => {
  const empty = { valueOf: () => { throw new Error('no such record'); } } as never;
  assert.throws(() => bindMaterial('oaep', empty), BindingError);
  assert.throws(() => bindMaterial('oaep', empty), /Refusing rather than binding a different record/);
});

// =====================================================================
// Dispatch materialization: total, mechanical, fail-closed
// =====================================================================

test('M3.7.2: materialization is TOTAL over the 33 frozen dispatch entries, both ways', () => {
  const inTable = new Set(dispatchSymbols());
  const materializable = new Set(materializableSymbols());
  assert.equal(DISPATCH_TABLE.length, 33);
  const missing = [...inTable].filter((s) => !materializable.has(s));
  const orphan = [...materializable].filter((s) => !inTable.has(s));
  assert.deepEqual(missing, [], 'every dispatch symbol must be materializable');
  assert.deepEqual(orphan, [], 'and nothing may be materializable that the table does not name');
});

test('M3.7.2: every dispatch entry materializes to a real value of its declared shape', () => {
  for (const d of DISPATCH_TABLE) {
    const m = materializeDispatch(d.operation, d.backend, d.role);
    assert.equal(m.entry.symbol, d.symbol);
    assert.notEqual(m.wiring, undefined);
    if (d.shape === 'execution-adapter-factory' || d.shape === 'roundtrip-function') {
      assert.equal(typeof m.wiring, 'function', `${d.symbol} must be callable`);
    } else {
      assert.equal(typeof m.wiring, 'object', `${d.symbol} must be an adapter object`);
    }
  }
});

test('M3.7.2: materialization is a LOOKUP, not a second dispatch', () => {
  const src = readFileSync(new URL('../../../harness/orchestration/dispatch-materialization.ts', import.meta.url), 'utf8');
  assert.ok(src.includes('resolveDispatch('), 'it must delegate the decision to the frozen table');
  const code = src.split('\n').filter((l) => !l.trimStart().startsWith('//') && !l.trimStart().startsWith('*'));
  for (const forbidden of ['switch (', 'if (operation', 'relation']) {
    assert.ok(!code.some((l) => l.includes(forbidden)), `no decision logic may appear ('${forbidden}')`);
  }
});

test('M3.7.2: an unknown backend is refused by the frozen dispatch, before materialization', () => {
  const ghost = { family: 'nodejs', apiVersion: 'x', sourcePin: 'y', apiSurface: 'z' } as never;
  assert.throws(() => materializeDispatch('gcm', ghost, 'encrypt'), DispatchError);
  assert.equal(typeof MaterializationError, 'function');
});

// =====================================================================
// Serialization: behaviour-preserving extraction
// =====================================================================

test('M3.7.2: the serialization transformation is shared, not reimplemented', () => {
  const dry = readFileSync(new URL('../../../harness/orchestration/dry-run.ts', import.meta.url), 'utf8');
  assert.ok(dry.includes("export { wrapSerializationExecution } from '../evidence/serialization-execution.js'"),
    'dry-run must re-export the extracted function, so its behaviour is byte-identical to what M3.5 validated');
  assert.ok(!dry.includes('makeMutationExecution('), 'and must not hold a second copy');
});

test('M3.7.2: the extracted transformation still judges nothing', () => {
  const accept = wrapSerializationExecution({
    operation: 'rsa-ser', backend: CRYPTOPP, direction: 'export',
    mutationId: 'M', stimulusInstanceId: 'default', inputKind: 'k',
    result: { ok: true, artifactHex: 'aabb' },
  });
  const reject = wrapSerializationExecution({
    operation: 'rsa-ser', backend: BOUNCY_CASTLE, direction: 'import',
    mutationId: 'M', stimulusInstanceId: 'default', inputKind: 'k',
    result: { ok: false, errorClass: 'invalid_key' },
  });
  assert.equal(accept.outcome.kind, 'accept');
  assert.equal(reject.outcome.kind, 'reject');
  // A contractual reject is not an execution failure -- unchanged from M3.5.
  assert.equal(accept.executionStatus, 'completed');
  assert.equal(reject.executionStatus, 'completed');
  assert.notEqual(accept.executionId, reject.executionId);
});

// =====================================================================
// Refusals
// =====================================================================

test('M3.7.2: R_interop cannot be bound from a scope that does not name both ends', () => {
  const single: ObservationScope = { kind: 'single-backend', backend: CHROMIUM_WEBCRYPTO };
  assert.throws(
    () => bindObservation({ operation: 'gcm', relation: 'R_interop', scope: single, pool }),
    /cannot be bound from a scope that does not name both ends/,
  );
});

test('M3.7.2: a cross-backend-set of the wrong size is refused', () => {
  const three: ObservationScope = {
    kind: 'cross-backend-set', backends: [CHROMIUM_WEBCRYPTO, CRYPTOPP, BOUNCY_CASTLE],
  };
  assert.throws(() => bindObservation({ operation: 'gcm', relation: 'R_byte', scope: three, pool }), BindingError);
});
