// Bloque C3 -- gate. Projection + wiring closure for M3.2.4b-3.6.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';

import {
  evaluateRelation, wiredRelation, WIRED_RELATIONS, WiringError,
} from '../../../../harness/phase-c/relation-wiring.js';
import {
  ProjectionError, projectByte, projectCap, projectErr, projectInterop, projectSer, projectVal, toChecksRequired,
} from '../../../../harness/phase-c/evaluator-projection.js';
import { runTransfer } from '../../../../harness/orchestration/interop-transfer.js';
import { recountPlan } from '../../../../harness/phase-c/plan-binding-audit.js';
import { assembleStructuralPlan } from '../../../../harness/phase-c/plan-assembly.js';
import { loadFrozenMaterialPool } from '../../../../harness/phase-c/material/load.js';
import { BOUNCY_CASTLE, CHROMIUM_WEBCRYPTO, CRYPTOPP } from '../../../../harness/schema/backend-identity.js';
import type { BackendIdentity } from '../../../../harness/schema/backend-identity.js';
import type { ExecutionEvidence } from '../../../../harness/evidence/execution-evidence.js';
import type { RelationId } from '../../../../harness/schema/registry-types.js';

const plan = assembleStructuralPlan(loadFrozenMaterialPool());

function ev(id: string, backend: BackendIdentity, bytes?: string, status: 'completed' | 'harness-error' = 'completed'): ExecutionEvidence {
  return {
    executionId: id, operation: 'gcm',
    context: { kind: 'mutation', phase: 'C', mutationId: 'M', stimulusInstanceId: 'default' },
    subject: { backend, direction: 'encrypt', path: 'sdk' },
    input: { kind: 'req' },
    ...(bytes === undefined ? {} : { output: { kind: 'out', bytes } }),
    outcome: { kind: 'ok' }, clauseIdsEvaluated: [], executionStatus: status,
    provenance: { timestampIso: '2026-09-07T00:00:00Z' },
  } as unknown as ExecutionEvidence;
}

// =====================================================================
// All six relations are wired, and really invoked
// =====================================================================

test('C3: all six relations have a projector AND an evaluator', () => {
  assert.deepEqual([...WIRED_RELATIONS].sort(), ['R_byte', 'R_cap', 'R_err', 'R_interop', 'R_ser', 'R_val']);
  for (const r of WIRED_RELATIONS) {
    const w = wiredRelation(r);
    assert.equal(typeof w.project, 'function');
    assert.equal(typeof w.evaluate, 'function');
  }
});

test('C3: an unknown relation is refused, never skipped', () => {
  assert.throws(() => wiredRelation('R_nope' as RelationId), WiringError);
});

test('C3: evaluateRelation really runs projector then evaluator for every relation', async () => {
  // Each call exercises the full last stretch and must return a genuine
  // ObservationState -- not a placeholder, and not undefined.
  const states = new Set<string>();

  states.add(evaluateRelation('R_byte', {
    left: ev('L', CHROMIUM_WEBCRYPTO, 'aabb'), right: ev('R', CRYPTOPP, 'aabb'), outputKind: 'raw-output',
  }));
  states.add(evaluateRelation('R_val', {
    expected: { kind: 'reject' }, execution: ev('V', CHROMIUM_WEBCRYPTO), observed: { kind: 'reject' },
  }));
  states.add(evaluateRelation('R_err', {
    execution: ev('E', CHROMIUM_WEBCRYPTO), rejectionOccurred: true,
    expectedErrorClass: 'invalid_key', observedErrorClass: 'invalid_key',
  }));
  states.add(evaluateRelation('R_ser', {
    basis: 'both', execution: ev('S', CHROMIUM_WEBCRYPTO), repOK: true, materialOK: true,
  }));
  states.add(evaluateRelation('R_cap', {
    declared: { kind: 'provider-support', state: 'supported' }, declarationExecution: ev('D', CHROMIUM_WEBCRYPTO),
    scoredExecution: ev('P', CHROMIUM_WEBCRYPTO), observed: { kind: 'provider-support', state: 'supported' },
  }));
  const transfer = await runTransfer({
    operation: 'gcm', from: CHROMIUM_WEBCRYPTO, to: CRYPTOPP,
    produce: async () => ({ bytesHex: 'ff00', execution: ev('P1', CHROMIUM_WEBCRYPTO, 'ff00') }),
    consume: async () => ev('C1', CRYPTOPP),
  });
  states.add(evaluateRelation('R_interop', {
    transfer, expectedOutcome: { kind: 'reject' },
    observedOutcome: { kind: 'rejection', value: null, errorClass: 'authentication_failure' },
  }));

  for (const s of states) {
    assert.ok(['conformant', 'divergent', 'n/a', 'not-executed', 'insufficient-evidence'].includes(s), s);
  }
  assert.ok(states.has('conformant'), 'at least one path reaches a real terminal verdict');
});

test('C3: no resolve() anywhere is a placeholder', () => {
  for (const f of ['relation-wiring.ts', 'evaluator-projection.ts']) {
    const src = readFileSync(new URL(`../../../../harness/phase-c/${f}`, import.meta.url), 'utf8');
    // Prose may DISCUSS placeholders; code may not BE one. Checked on
    // non-comment lines only.
    const code = src.split('\n').filter((l) => !l.trimStart().startsWith('//') && !l.trimStart().startsWith('*'));
    for (const bad of ['TODO', 'not implemented', 'placeholder', 'unimplemented']) {
      assert.ok(!code.some((l) => l.includes(bad)), `${f} contains '${bad}' in code`);
    }
  }
});

// =====================================================================
// The architectural rule: interpret evidence, never decide normative truth
// =====================================================================

test('C3: no projector imports src/contract to reinterpret ground truth', () => {
  for (const f of ['evaluator-projection.ts', 'relation-wiring.ts']) {
    const src = readFileSync(new URL(`../../../../harness/phase-c/${f}`, import.meta.url), 'utf8');
    const imports = src.split('\n').filter((l) => l.trimStart().startsWith('import'));
    for (const line of imports) {
      assert.ok(!line.includes('src/contract'), `${f} must not reach the contract during execution: ${line.trim()}`);
    }
    assert.ok(!src.includes('ground-truth/table'), `${f} must receive the expectation, not look it up`);
  }
});

test('C3: the expectation is a PARAMETER, so a run cannot decide what it should find', () => {
  // Same evidence, two different pre-registered expectations, two different
  // verdicts. If the projector derived the expectation, this could not happen.
  const base = { execution: ev('V', CHROMIUM_WEBCRYPTO), observed: { kind: 'reject' as const } };
  const agree = evaluateRelation('R_val', { ...base, expected: { kind: 'reject' } });
  const disagree = evaluateRelation('R_val', { ...base, expected: { kind: 'accept' } });
  assert.notEqual(agree, disagree);
});

// =====================================================================
// Per-relation invariants
// =====================================================================

test('C3/R_byte: cross-backend only -- a same-backend pair is refused (M3-H8)', () => {
  assert.throws(() => projectByte({
    left: ev('L', CRYPTOPP, 'aa'), right: ev('R', CRYPTOPP, 'aa'), outputKind: 'raw-output',
  }), ProjectionError);
  assert.throws(() => projectByte({
    left: ev('L', CRYPTOPP, 'aa'), right: ev('R', CRYPTOPP, 'aa'), outputKind: 'raw-output',
  }), /CROSS-BACKEND/);
  // And there is no PARAMETER through which a baseline could enter: the
  // projection's own signature admits only two executions and an output kind.
  const src = readFileSync(new URL('../../../../harness/phase-c/evaluator-projection.ts', import.meta.url), 'utf8');
  const sig = src.slice(src.indexOf('export function projectByte'), src.indexOf('): ByteEqualityEvaluationInput'));
  assert.ok(!sig.toLowerCase().includes('baseline'), 'no baseline parameter may reach the Phase C byte projection');
});

test('C3/R_interop: the projection consumes the real A->B transfer, not two executions', async () => {
  const transfer = await runTransfer({
    operation: 'pss', from: CHROMIUM_WEBCRYPTO, to: BOUNCY_CASTLE,
    produce: async () => ({ bytesHex: 'abcd', execution: ev('P', CHROMIUM_WEBCRYPTO, 'abcd') }),
    consume: async () => ev('C', BOUNCY_CASTLE),
  });
  const input = projectInterop({ transfer, expectedOutcome: { kind: 'verify', expected: true } });
  assert.equal(input.producerValid, true);
  assert.equal(input.sameBaselineOrStimulus, true, 'true because the consumer took the producer\'s own artifact');
  assert.equal(input.producerExecutionStatus, 'completed');
  assert.equal(input.consumerExecutionStatus, 'completed');
  // The signature admits no pair of independent executions.
  const src = readFileSync(new URL('../../../../harness/phase-c/evaluator-projection.ts', import.meta.url), 'utf8');
  assert.ok(src.includes('readonly transfer: TransferRecord'), 'R_interop projection takes a TransferRecord');
});

test('C3/R_interop: producerValid is the producer PROCESS, not artifact pristineness', async () => {
  const tampered = await runTransfer({
    operation: 'gcm', from: CHROMIUM_WEBCRYPTO, to: CRYPTOPP,
    produce: async () => ({ bytesHex: 'deadbeef', execution: ev('P', CHROMIUM_WEBCRYPTO, 'deadbeef') }),
    consume: async () => ev('C', CRYPTOPP),
  });
  // A tamper stimulus has a perfectly valid producer.
  assert.equal(projectInterop({ tampered: undefined, transfer: tampered, expectedOutcome: { kind: 'reject' } } as never).producerValid, true);
});

test('C3/R_ser: checksRequired governs WHICH checks, while missing runtime evidence remains insufficient-evidence', () => {
  assert.deepEqual(toChecksRequired('both'), { representationConformance: true, materialPreservation: true });
  assert.deepEqual(toChecksRequired('representation-conformance'), { representationConformance: true, materialPreservation: false });

  // A completed execution is structurally comparable at projection time.
  // If one of the checks required by the frozen basis is still missing, the
  // evaluator preserves that absence as insufficient-evidence; it is neither
  // promoted to divergence nor converted into structural non-comparability.
  const missing = projectSer({ basis: 'both', execution: ev('S', CHROMIUM_WEBCRYPTO), repOK: true });
  assert.equal(missing.comparable, true);
  assert.equal(evaluateRelation('R_ser', { basis: 'both', execution: ev('S', CHROMIUM_WEBCRYPTO), repOK: true }), 'insufficient-evidence');

  // A check the basis does NOT require may be absent without harm.
  const ok = projectSer({ basis: 'representation-conformance', execution: ev('S', CHROMIUM_WEBCRYPTO), repOK: true });
  assert.equal(ok.comparable, true);
});

test('C3/R_ser: a failed execution is non-comparable, never a divergence', () => {
  const s = projectSer({ basis: 'both', execution: ev('S', CHROMIUM_WEBCRYPTO, undefined, 'harness-error'), repOK: true, materialOK: true });
  assert.equal(s.comparable, false);
  assert.equal(evaluateRelation('R_ser', { basis: 'both', execution: ev('S', CHROMIUM_WEBCRYPTO, undefined, 'harness-error'), repOK: true, materialOK: true }), 'insufficient-evidence');
});

test('C3/R_cap: identical execution ids are refused ON THE PATH, not only in the evaluator', () => {
  const same = ev('SAME', CHROMIUM_WEBCRYPTO);
  assert.throws(() => projectCap({
    declared: { kind: 'provider-support', state: 'supported' },
    declarationExecution: same, scoredExecution: same,
  }), /DISJOINT/);
});

test('C3/R_err: a rejection that never happened is insufficient-evidence, not fail', () => {
  const state = evaluateRelation('R_err', {
    execution: ev('E', CHROMIUM_WEBCRYPTO), rejectionOccurred: false, expectedErrorClass: 'invalid_key',
  });
  assert.equal(state, 'insufficient-evidence');
  const input = projectErr({ execution: ev('E', CHROMIUM_WEBCRYPTO), rejectionOccurred: false });
  assert.equal(input.expectedErrorClass, undefined, 'absent means absent, never an empty string');
});

test('C3/R_val: a contractual reject is not an execution failure', () => {
  const input = projectVal({ expected: { kind: 'reject' }, execution: ev('V', CHROMIUM_WEBCRYPTO), observed: { kind: 'reject' } });
  assert.equal(input.executionStatus, 'completed');
  assert.equal(evaluateRelation('R_val', { expected: { kind: 'reject' }, execution: ev('V', CHROMIUM_WEBCRYPTO), observed: { kind: 'reject' } }), 'conformant');
});

test('C3: a malformed experiment PROPAGATES -- it is not filed as insufficient-evidence', () => {
  // A projector refusal reports a harness defect. Converting it into an
  // observation state would file a bug as a scientific result.
  assert.throws(() => evaluateRelation('R_byte', {
    left: ev('L', CRYPTOPP, 'aa'), right: ev('R', CRYPTOPP, 'aa'), outputKind: 'raw-output',
  }), ProjectionError);
});

// =====================================================================
// The plan still says what it said
// =====================================================================

test('C3: the recount is unchanged -- wiring adds no obligation and removes none', () => {
  const r = recountPlan(plan);
  assert.equal(r.planned, 1641);
  assert.equal(r.required, 886);    // M3-reopen-v5 normative Required
  assert.equal(r.notRequiredDistinct, 755);
  assert.equal(r.required + r.notRequiredDistinct, r.planned);
});
