// Bloque C2 -- gate. Dispatch, R_interop transfer, plan binding, recount.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';

import {
  DISPATCH_TABLE, DispatchError, ROLES_BY_OPERATION, consumerRole, producerRole, resolveDispatch,
} from '../../../../harness/orchestration/dispatch.js';
import {
  hashArtifact, makeTransferredArtifact, runTransfer, TransferError,
} from '../../../../harness/orchestration/interop-transfer.js';
import {
  auditPlanBinding, nonEligibleInteropPairs, recountPlan,
} from '../../../../harness/phase-c/plan-binding-audit.js';
import { assembleStructuralPlan } from '../../../../harness/phase-c/plan-assembly.js';
import { loadFrozenMaterialPool } from '../../../../harness/phase-c/material/load.js';
import { ALL_BACKENDS, BOUNCY_CASTLE, CHROMIUM_WEBCRYPTO, CRYPTOPP } from '../../../../harness/schema/backend-identity.js';
import type { BackendIdentity } from '../../../../harness/schema/backend-identity.js';
import type { OperationId } from '../../../../harness/schema/capability.js';
import type { ExecutionEvidence } from '../../../../harness/evidence/execution-evidence.js';

const pool = loadFrozenMaterialPool();
const plan = assembleStructuralPlan(pool);
const OPS: readonly OperationId[] = ['hkdf', 'gcm', 'oaep', 'pss', 'rsa-ser', 'ec-ser'];

// =====================================================================
// Dispatch: total and fail-closed
// =====================================================================

test('C2: dispatch is TOTAL over (operation, backend, role) for the three frozen backends', () => {
  assert.equal(ALL_BACKENDS.length, 3);
  let expected = 0;
  for (const op of OPS) {
    for (const backend of ALL_BACKENDS) {
      for (const role of ROLES_BY_OPERATION[op]) {
        expected += 1;
        assert.doesNotThrow(() => resolveDispatch(op, backend, role), `${op}/${backend.family}/${role}`);
      }
    }
  }
  // Recomputed from ROLES_BY_OPERATION x ALL_BACKENDS rather than hard-coded,
  // so adding a backend or an operation cannot leave the table silently partial.
  assert.equal(expected, DISPATCH_TABLE.length);
  assert.equal(expected, 33);
});

test('C2: an unknown backend fails CLOSED, never unmatched', () => {
  const ghost: BackendIdentity = {
    family: 'nodejs', apiVersion: 'x', sourcePin: 'y', apiSurface: 'z',
  } as unknown as BackendIdentity;
  assert.throws(() => resolveDispatch('gcm', ghost, 'encrypt'), DispatchError);
  assert.throws(() => resolveDispatch('gcm', ghost, 'encrypt'), /refused rather than silently unmatched/);
});

test('C2: a role the operation does not expose is refused', () => {
  assert.throws(() => resolveDispatch('hkdf', CHROMIUM_WEBCRYPTO, 'encrypt'), /exposes no 'encrypt' role/);
  assert.throws(() => resolveDispatch('rsa-ser', CRYPTOPP, 'sign'), /exposes no 'sign' role/);
});

test('C2: every dispatch symbol is really exported by the module it names', () => {
  // Guards the one thing a name-based table can get wrong: a symbol that
  // does not exist, or that moved.
  for (const d of DISPATCH_TABLE) {
    const src = readFileSync(new URL(`../../../../harness/orchestration/${d.module}.ts`, import.meta.url), 'utf8');
    assert.ok(
      src.includes(`export const ${d.symbol}`) || src.includes(`export function ${d.symbol}`)
      || src.includes(`export async function ${d.symbol}`),
      `${d.module} does not export ${d.symbol}`,
    );
  }
});

test('C2: producer and consumer roles are the operation\'s own, and ordered', () => {
  assert.equal(producerRole('gcm'), 'encrypt');
  assert.equal(consumerRole('gcm'), 'decrypt');
  assert.equal(producerRole('pss'), 'sign');
  assert.equal(consumerRole('pss'), 'verify');
  assert.equal(producerRole('rsa-ser'), 'export');
  assert.equal(consumerRole('rsa-ser'), 'import');
  // HKDF has no split, and asking for one is refused rather than guessed.
  assert.throws(() => producerRole('hkdf'), /no producer\/consumer split/);
});

// =====================================================================
// R_interop transfer: the artifact B consumes is the artifact A produced
// =====================================================================

const exec = (id: string): ExecutionEvidence => ({ executionId: id } as unknown as ExecutionEvidence);

test('C2: transfer carries the producer\'s own bytes to the consumer', async () => {
  let received = '';
  const r = await runTransfer({
    operation: 'gcm', from: CHROMIUM_WEBCRYPTO, to: CRYPTOPP,
    produce: async () => ({ bytesHex: '01ff02', execution: exec('E-prod') }),
    consume: async (a) => { received = a.bytesHex; return exec('E-cons'); },
  });
  assert.equal(received, '01ff02', 'the consumer received exactly the produced bytes');
  assert.equal(r.artifact.transferHash, hashArtifact('01ff02'));
  assert.equal(r.consumedHash, r.artifact.transferHash);
  assert.equal(r.artifact.producerExecutionId, 'E-prod');
  assert.equal(r.producerExecution.executionId, 'E-prod');
  assert.equal(r.consumerExecution.executionId, 'E-cons');
});

test('C2: the transfer is DIRECTIONAL -- A->B is not B->A', async () => {
  const ab = await runTransfer({
    operation: 'gcm', from: CHROMIUM_WEBCRYPTO, to: CRYPTOPP,
    produce: async () => ({ bytesHex: 'aa', execution: exec('1') }),
    consume: async () => exec('2'),
  });
  const ba = await runTransfer({
    operation: 'gcm', from: CRYPTOPP, to: CHROMIUM_WEBCRYPTO,
    produce: async () => ({ bytesHex: 'aa', execution: exec('3') }),
    consume: async () => exec('4'),
  });
  assert.equal(ab.from.family, 'chromium');
  assert.equal(ba.from.family, 'cryptopp');
  assert.notDeepEqual([ab.from.family, ab.to.family], [ba.from.family, ba.to.family]);
});

test('C2: a self-transfer is refused -- that is Phase A/B\'s local round trip', async () => {
  await assert.rejects(
    () => runTransfer({
      operation: 'gcm', from: CRYPTOPP, to: CRYPTOPP,
      produce: async () => ({ bytesHex: 'aa', execution: exec('1') }),
      consume: async () => exec('2'),
    }),
    TransferError,
  );
});

test('C2: an unknown backend is refused BEFORE anything executes', async () => {
  let produced = false;
  const ghost = { family: 'nodejs', apiVersion: 'x', sourcePin: 'y', apiSurface: 'z' } as unknown as BackendIdentity;
  await assert.rejects(() => runTransfer({
    operation: 'gcm', from: ghost, to: CRYPTOPP,
    produce: async () => { produced = true; return { bytesHex: 'aa', execution: exec('1') }; },
    consume: async () => exec('2'),
  }));
  assert.equal(produced, false, 'fail-closed happens before the producer runs');
});

test('C2: an operation with no producer/consumer split has no transfer', async () => {
  await assert.rejects(() => runTransfer({
    operation: 'hkdf', from: CHROMIUM_WEBCRYPTO, to: CRYPTOPP,
    produce: async () => ({ bytesHex: 'aa', execution: exec('1') }),
    consume: async () => exec('2'),
  }), /no producer\/consumer split/);
});

test('C2: producer and consumer must be two distinct executions', async () => {
  await assert.rejects(() => runTransfer({
    operation: 'pss', from: CHROMIUM_WEBCRYPTO, to: BOUNCY_CASTLE,
    produce: async () => ({ bytesHex: 'aa', execution: exec('SAME') }),
    consume: async () => exec('SAME'),
  }), /two distinct executions/);
});

test('C2: a producer that emitted nothing cannot begin a transfer', () => {
  assert.throws(() => makeTransferredArtifact('', CRYPTOPP, 'E'), TransferError);
});

test('C2: the transfer layer does not interpret the artifact', () => {
  const src = readFileSync(new URL('../../../../harness/orchestration/interop-transfer.ts', import.meta.url), 'utf8');
  for (const forbidden of ['parseAeadArtifact', 'importRsaSer', 'importEcSer', 'validate', 'src/contract']) {
    assert.ok(!src.includes(forbidden), `the plumbing must not do the consumer's contractual job ('${forbidden}')`);
  }
});

// =====================================================================
// Plan binding
// =====================================================================

test('C2: all 90 pairs are bound to fixture + ground truth, fail-closed', () => {
  const bindings = auditPlanBinding(plan, pool);
  assert.equal(bindings.length, 90);
  for (const b of bindings) {
    assert.equal(b.hasFixture, true);
    assert.equal(b.hasGroundTruth, true);
    assert.ok(b.relationsPlanned.length > 0, `${b.mutationId}: no relation planned`);
    assert.ok(b.rolesDispatchable.length > 0, `${b.mutationId}: no dispatchable role`);
  }
});

test('C2: the 26 non-eligible pairs are identified and must not begin an interop flow', () => {
  assert.equal(nonEligibleInteropPairs().length, 26);
});

// =====================================================================
// The recount
// =====================================================================

test('C2: the recount, with every overlap counted once', () => {
  // M3.7.1 updated these figures deliberately. C2 wrote them under the
  // pre-H13 definition of Required; H13 added StructuralComparable as a
  // fourth conjunct and recountPlan was not revisited, which is D13. The
  // structural fact C2 established -- that the causes OVERLAP and the sum is
  // not the union -- is unchanged and is what these assertions still protect.
  const r = recountPlan(plan);
  assert.equal(r.planned, 1641);
  assert.equal(r.required, 886);
  assert.equal(r.notRequiredDistinct, 755);

  assert.equal(r.notRequiredContractuallyNonEligible, 126);
  assert.equal(r.notRequiredStructurallyNonComparable, 582);
  assert.equal(r.notRequiredNotExecutable, 142);
  assert.equal(r.overlapNonEligibleAndNotExecutable, 32);
  assert.equal(r.overlapNonComparableAndNotExecutable, 63);
  assert.equal(r.overlapNonEligibleAndNonComparable, 0);

  // Inclusion-exclusion over three sets, never the sum.
  const union =
    r.notRequiredContractuallyNonEligible + r.notRequiredStructurallyNonComparable + r.notRequiredNotExecutable
    - r.overlapNonEligibleAndNotExecutable - r.overlapNonComparableAndNotExecutable
    - r.overlapNonEligibleAndNonComparable;
  assert.equal(union, r.notRequiredDistinct);
  assert.equal(r.required + r.notRequiredDistinct, r.planned);
  assert.notEqual(
    r.notRequiredContractuallyNonEligible + r.notRequiredStructurallyNonComparable + r.notRequiredNotExecutable,
    r.notRequiredDistinct,
    'the causes genuinely overlap; adding them would overstate the excluded population',
  );
});

test('C2: the eligibility cause is now a SUBSET of the 156 -- 126, with 30 absorbed', () => {
  const r = recountPlan(plan);
  // 26 non-eligible pairs x 6 directions = 156 planned R_interop scopes, as
  // before. What changed is attribution: 30 of them belong to classes that
  // M3.8.2 made structurally non-comparable as adapter-transform, and the
  // recount reports each observation under one cause.
  assert.equal(nonEligibleInteropPairs().length * 6, 156);
  assert.equal(r.notRequiredContractuallyNonEligible, 126);
  assert.equal(156 - r.notRequiredContractuallyNonEligible, 30);
});

