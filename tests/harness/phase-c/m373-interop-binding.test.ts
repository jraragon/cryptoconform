// M3.7.3 -- R_interop binding gate.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';

import { assembleStructuralPlan } from '../../../harness/phase-c/plan-assembly.js';
import { loadFrozenMaterialPool } from '../../../harness/phase-c/material/load.js';
import {
  bindRequiredObligations, directedTransferObligations, nonInteropObligations,
} from '../../../harness/phase-c/execution-binding.js';
import {
  assembleConsumerInput, ConsumerInputError, INTEROP_FAMILIES,
  type FieldProvenance,
} from '../../../harness/phase-c/consumer-input.js';
import { makeResolve } from '../../../harness/phase-c/resolve-glue.js';
import { CHROMIUM_WEBCRYPTO, CRYPTOPP } from '../../../harness/schema/backend-identity.js';
import type { OperationId } from '../../../harness/schema/capability.js';

const pool = loadFrozenMaterialPool();
const all = bindRequiredObligations(assembleStructuralPlan(pool), pool);
const interop = directedTransferObligations(all);

// =====================================================================
// The 316, derived
// =====================================================================

test('M3.7.3: 216 interop obligations after the reopen, in the five families', () => {
  assert.equal(interop.length, 216); // M3.7-D2
  const byOp: Record<string, number> = {};
  for (const o of interop) byOp[o.operation] = (byOp[o.operation] ?? 0) + 1;
  assert.deepEqual(byOp, { gcm: 66, oaep: 18, pss: 18, 'rsa-ser': 66, 'ec-ser': 48 });
  assert.equal(Object.values(byOp).reduce((a, b) => a + b, 0), 216);
  // HKDF has no producer/consumer split, so it carries none.
  assert.ok(!('hkdf' in byOp));
  assert.deepEqual([...INTEROP_FAMILIES].sort(), Object.keys(byOp).sort());
});

test('M3.7.3: 886 = 670 + 216, all with a resolution path', () => {
  assert.equal(all.length, 886);
  assert.equal(nonInteropObligations(all).length, 670);
  assert.equal(interop.length, 216); // M3.7-D2
});

// =====================================================================
// The direction is EXECUTED, never reconstructed
// =====================================================================

test('M3.7.3: every interop obligation carries producer and consumer explicitly', () => {
  for (const o of interop) {
    if (o.binding.kind !== 'directed-transfer') throw new Error('unreachable');
    if (o.scope.kind !== 'backend-pair') throw new Error('unreachable');
    assert.equal(o.binding.from.sourcePin, o.scope.from.sourcePin, 'from comes from the scope');
    assert.equal(o.binding.to.sourcePin, o.scope.to.sourcePin, 'to comes from the scope');
    assert.equal(o.binding.producer.entry.role, o.binding.producerRole);
    assert.equal(o.binding.consumer.entry.role, o.binding.consumerRole);
    assert.notEqual(o.binding.from.sourcePin, o.binding.to.sourcePin);
  }
});

test('M3.7.3: the resolver reconstructs no direction -- it reads the binding', () => {
  const src = readFileSync(new URL('../../../harness/phase-c/resolve-glue.ts', import.meta.url), 'utf8');
  const block = src.slice(src.indexOf("case 'R_interop':"), src.indexOf("      default:"));
  assert.ok(block.includes('runTransfer('), 'runTransfer is the path');
  assert.ok(block.includes('from: t.from') && block.includes('to: t.to'));
  // No heuristic may appear: no sorting, no array-order choice, no name test.
  for (const forbidden of ['.sort(', 'localeCompare', "family ===", '[0]', '[1]']) {
    assert.ok(!block.includes(forbidden), `no direction heuristic may appear ('${forbidden}')`);
  }
});

test('M3.7.3: it is NOT execute-A / execute-B / compare', () => {
  const src = readFileSync(new URL('../../../harness/phase-c/resolve-glue.ts', import.meta.url), 'utf8');
  const block = src.slice(src.indexOf("case 'R_interop':"), src.indexOf("      default:"));
  // The consumer's input is the transferred artifact, not the base fixture.
  assert.ok(block.includes('assembleConsumerInput('));
  assert.ok(block.includes('artifact.bytesHex'));
  assert.ok(!block.includes('ctx.runMutation(t.consumerAdapter)'),
    'the consumer must never re-run the mutation locally -- that is a different relation');
});

test('M3.7.3: an interop entry without a transfer binding is still refused', async () => {
  // The old refusal is not removed: it now guards the ABSENCE of the binding
  // rather than the relation itself, so an interop claim can still never be
  // assembled from one execution.
  const resolve = makeResolve('R_interop', { kind: 'single-backend', backend: CHROMIUM_WEBCRYPTO }, {
    adapter: {} as never,
  });
  await assert.rejects(
    () => resolve({
      mutationId: 'GCM-AAD-IGNORED', stimulusInstanceId: 'default',
      baseFixture: {}, mutation: { mutate: () => ({}) },
      getBaseline: async () => { throw new Error('unused'); },
      runMutation: async () => { throw new Error('unused'); },
      runOnInput: async () => { throw new Error('unused'); },
      runDeclarationProbe: async () => { throw new Error('unused'); },
    } as never),
    /Refusing rather than assembling/,
  );
});

// =====================================================================
// Consumer-input assembly: every field cites frozen provenance
// =====================================================================

const ADMISSIBLE: readonly FieldProvenance[] = ['transferred-artifact', 'producer-fixture', 'contract-role'];

const producerFixture = (op: OperationId): unknown => {
  switch (op) {
    case 'gcm': return { key: Buffer.alloc(32), iv: Buffer.alloc(12), plaintext: Buffer.alloc(4), aad: Buffer.alloc(3), tagLengthBits: 128 };
    case 'oaep': return { key: { role: 'public', modulusBits: 3072 }, plaintext: Buffer.alloc(4), label: undefined, hash: 'SHA-256', mgfHash: 'SHA-256' };
    case 'pss': return { key: { role: 'private', modulusBits: 3072 }, message: Buffer.alloc(8), hash: 'SHA-256', mgfHash: 'SHA-256', saltLengthBytes: 32 };
    default: return { role: 'private' };
  }
};

test('M3.7.3: all five families assemble, and every field cites one of three provenances', () => {
  for (const op of INTEROP_FAMILIES) {
    const a = assembleConsumerInput({ operation: op, producerFixture: producerFixture(op), artifactHex: 'aabbcc' });
    assert.equal(a.operation, op);
    assert.ok(Object.keys(a.provenance).length > 0, `${op}: the assembly must be auditable field by field`);
    for (const [field, prov] of Object.entries(a.provenance)) {
      assert.ok(ADMISSIBLE.includes(prov), `${op}.${field}: '${prov}' is not an admissible provenance`);
    }
    // Exactly one field carries the transferred artifact.
    const transferred = Object.values(a.provenance).filter((p) => p === 'transferred-artifact');
    assert.equal(transferred.length, 1, `${op}: exactly one field is the artifact`);
  }
});

test('M3.7.3: the consumer key ROLE is contract-determined, and it is not the producer\'s', () => {
  const oaep = assembleConsumerInput({ operation: 'oaep', producerFixture: producerFixture('oaep'), artifactHex: 'aa' });
  assert.equal(oaep.provenance['key.role'], 'contract-role');
  assert.equal((oaep.input as { key: { role: string } }).key.role, 'private',
    'Dec_q needs a private key where Enc_p needed a public one');
  const pss = assembleConsumerInput({ operation: 'pss', producerFixture: producerFixture('pss'), artifactHex: 'aa' });
  assert.equal(pss.provenance['key.role'], 'contract-role');
  assert.equal((pss.input as { key: { role: string } }).key.role, 'public');
});

test('M3.7.3: output-affecting parameters are copied VERBATIM from the producer', () => {
  const f = producerFixture('pss') as Record<string, unknown>;
  const a = assembleConsumerInput({ operation: 'pss', producerFixture: f, artifactHex: 'aa' });
  const input = a.input as Record<string, unknown>;
  for (const field of ['message', 'hash', 'mgfHash', 'saltLengthBytes']) {
    assert.deepEqual(input[field], f[field], `${field} must be the one the artifact was produced under`);
    assert.equal(a.provenance[field], 'producer-fixture');
  }
});

test('M3.7.3: a missing field is REFUSED, never defaulted', () => {
  assert.throws(
    () => assembleConsumerInput({ operation: 'pss', producerFixture: { key: { modulusBits: 3072 } }, artifactHex: 'aa' }),
    ConsumerInputError,
  );
  assert.throws(
    () => assembleConsumerInput({ operation: 'oaep', producerFixture: producerFixture('oaep'), artifactHex: '' }),
    /empty artifact cannot be consumed/,
  );
});

test('M3.7.3: HKDF can never reach the assembly', () => {
  assert.throws(
    () => assembleConsumerInput({ operation: 'hkdf', producerFixture: {}, artifactHex: 'aa' }),
    /no producer\/consumer split/,
  );
});

test('M3.7.3: the assembly interprets no artifact', () => {
  const src = readFileSync(new URL('../../../harness/phase-c/consumer-input.ts', import.meta.url), 'utf8');
  const imports = src.split('\n').filter((l) => l.trimStart().startsWith('import'));
  for (const line of imports) {
    assert.ok(!line.includes('src/contract'), 'parsing the artifact is the consumer\'s contractual job');
  }
  assert.ok(!src.includes('parseAeadArtifact') && !src.includes('importRsaSer'));
});

// =====================================================================
// The additive primitive
// =====================================================================

test('M3.7.3: runOnInput is additive and registers its evidence', () => {
  const src = readFileSync(new URL('../../../harness/orchestration/phase-c-orchestrator.ts', import.meta.url), 'utf8');
  // The three original primitives keep their own refusals.
  assert.ok(src.includes("A '${relation}' entry requested a baseline"));
  assert.ok(src.includes("A '${relation}' entry requested a declaration probe"));
  // And the new one pushes, which is what keeps the bundle reconstructible.
  const block = src.slice(src.indexOf('runOnInput: async'), src.indexOf('runDeclarationProbe: async'));
  assert.ok(block.includes('executions.push(evidence)'),
    'an execution the runner never sees would break reconstruction from the dataset alone');
  assert.ok(block.includes('executeBaseline('));
});

test('M3.7.3: runOnInput carries no relation policy', () => {
  const src = readFileSync(new URL('../../../harness/orchestration/phase-c-orchestrator.ts', import.meta.url), 'utf8');
  const block = src.slice(src.indexOf('runOnInput: async'), src.indexOf('runDeclarationProbe: async'));
  assert.ok(!block.includes("relation !=="), 'it is deliberately relation-agnostic');
  assert.ok(!block.includes('R_interop'), 'the binding decides who calls it, not this primitive');
});

test('M3.7.3: the resolver executes the consumer THROUGH the context', () => {
  const src = readFileSync(new URL('../../../harness/phase-c/resolve-glue.ts', import.meta.url), 'utf8');
  const block = src.slice(src.indexOf("case 'R_interop':"), src.indexOf("      default:"));
  assert.ok(block.includes('ctx.runOnInput('), 'bypassing the context would lose the evidence');
  assert.ok(!block.includes('executeBaseline('), 'and must not call the engine directly');
  // Both execution identities are recorded as participants.
  assert.ok(block.includes('record.producerExecution.executionId'));
  assert.ok(block.includes('record.consumerExecution.executionId'));
});
