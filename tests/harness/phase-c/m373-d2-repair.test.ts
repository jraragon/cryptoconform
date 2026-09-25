// M3.7-D2 -- the normative repair, and the C-T-swap provenance promotion.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';

import { assembleStructuralPlan } from '../../../harness/phase-c/plan-assembly.js';
import { loadFrozenMaterialPool } from '../../../harness/phase-c/material/load.js';
import {
  bindRequiredObligations, directedTransferObligations, nonInteropObligations,
} from '../../../harness/phase-c/execution-binding.js';
import { structuralComparability } from '../../../harness/phase-c/structural-comparability.js';
import {
  isArtifactBearing, PRODUCER_RECONSTRUCTION, producerExecutionPreservesStimulusIdentity,
} from '../../../harness/phase-c/producer-stimulus-identity.js';
import { CT_SWAP_PRODUCER_PLAINTEXT, ctSwapPlaintextBytes } from '../../../harness/phase-c/material/ct-swap-parameter.js';
import { recountPlan } from '../../../harness/phase-c/plan-binding-audit.js';

const pool = loadFrozenMaterialPool();
const plan = assembleStructuralPlan(pool);
const all = bindRequiredObligations(plan, pool);
const interop = directedTransferObligations(all);

test('D2: the repaired cardinality, derived from the predicate', () => {
  assert.equal(all.length, recountPlan(plan).required, 'binder and recount still agree');
  assert.equal(all.length, 886);
  assert.equal(interop.length, 216);
  assert.equal(nonInteropObligations(all).length, 670, 'non-interop is untouched by D2');
});

test('D2: the loss is exactly the PSS artifact-side population', () => {
  const byOp: Record<string, number> = {};
  for (const o of interop) byOp[o.operation] = (byOp[o.operation] ?? 0) + 1;
  assert.deepEqual(byOp, { gcm: 66, oaep: 18, pss: 18, 'rsa-ser': 66, 'ec-ser': 48 });
  // GCM and RSA-ser keep every obligation, including the 12 C-T-swap. EC-ser
  // loses 6 to M3.8.2's adapter-transform rule, not to D2.
  assert.equal(byOp['gcm'], 66);
  assert.equal(byOp['rsa-ser'], 66);
  assert.equal(byOp['ec-ser'], 48);
});

test('D2: the exclusion comes from the GENERAL property, not from a class list', () => {
  const src = readFileSync(new URL('../../../harness/phase-c/producer-stimulus-identity.ts', import.meta.url), 'utf8');
  const code = src.split('\n').filter((l) => !l.trimStart().startsWith('//') && !l.trimStart().startsWith('*'));
  for (const name of ['FALSE-REJECT', 'FALSE-ACCEPT', 'MESSAGE-NORMALIZATION', 'PSS-VERIF']) {
    assert.ok(!code.some((l) => l.includes(name)), `no class name may drive the exclusion ('${name}')`);
  }
  // The property is two independent conditions, and each is necessary.
  assert.equal(producerExecutionPreservesStimulusIdentity('pss', { message: 1, signature: 2 }), false);
  assert.equal(producerExecutionPreservesStimulusIdentity('pss', { key: 1, message: 2 }), true,
    'a PSS obligation whose stimulus IS a producer input keeps its comparability');
  assert.equal(producerExecutionPreservesStimulusIdentity('gcm', { aad: 1, artifact: 2 }), true,
    'artifact-bearing is not enough: GCM reproduces its A_0 deterministically');
  assert.equal(isArtifactBearing({ key: 1 }), false);
  assert.equal(isArtifactBearing({ alternateSignature: 1 }), true);
});

test('D2: it is not "PSS is probabilistic, exclude it"', () => {
  // PSS keeps 18 of its 38 after M3.8.2 also removed its adapter-transform classes obligations: only the artifact-side ones are lost.
  const pss = interop.filter((o) => o.operation === 'pss');
  assert.equal(pss.length, 18);
  assert.equal(PRODUCER_RECONSTRUCTION['pss'].kind, 'requires-randomized-execution');
  assert.ok(PRODUCER_RECONSTRUCTION['pss'].why.length > 80, 'the reason is recorded, not the verdict alone');
});

test('D2: the three PSS classes are non-comparable, each by the general premise', () => {
  for (const id of ['PSS-VERIFICATION-FALSE-ACCEPT', 'PSS-VERIFICATION-FALSE-REJECT', 'PSS-VERIFY-MESSAGE-NORMALIZATION']) {
    const v = structuralComparability(id, 'default', 'R_interop');
    assert.equal(v.value, 'structurally-non-comparable', id);
    assert.equal(v.cause, 'structurally-non-comparable');
    assert.ok(v.premise!.includes('M3.7-D2'), `${id}: the premise must name the defect it rests on`);
  }
  // And a PSS class whose stimulus is a producer input is untouched.
  assert.equal(structuralComparability('PSS-SALT-LENGTH-BOUNDARY', 'default', 'R_interop').value, 'comparable');
});

test('D2: every non-comparable R_interop verdict still names its own premise', () => {
  const v = structuralComparability('GCM-PROVIDER-CAPABILITY-MISMATCH', 'default', 'R_interop');
  assert.equal(v.cause, 'contractually-non-eligible', 'the specialised eligibility cause is preserved');
});

// =====================================================================
// C-T-swap provenance promotion
// =====================================================================

test('D2: the C-T-swap plaintext is the frozen generator\'s own literal', () => {
  // Nothing is invented: the promoted value is asserted against the frozen
  // script rather than trusted as a copy.
  const script = readFileSync(new URL('../../../scripts/generate-gcm-sdk-artifacts.ts', import.meta.url), 'utf8');
  assert.ok(script.includes(`'${CT_SWAP_PRODUCER_PLAINTEXT.utf8}'`),
    'the promoted parameter must equal the literal the frozen generator used');
  assert.equal(ctSwapPlaintextBytes().length, 16);
  assert.equal(CT_SWAP_PRODUCER_PLAINTEXT.bytes, 16);
});

test('D2: the promotion carries provenance and a rationale, not just a value', () => {
  const p = CT_SWAP_PRODUCER_PLAINTEXT.provenance;
  assert.equal(p.origin, 'promoted-from-frozen-generator');
  assert.deepEqual([...p.sourceMaterialIds], ['aes-phasec-primary-01', 'gcm-sdk-artifact-ctlen-01']);
  assert.ok(p.rationale.includes('|C| = |tag|'), 'the parameter must state why it is what it is');
});

test('D2: the promotion does NOT read the script at runtime, and generates nothing', () => {
  const src = readFileSync(new URL('../../../harness/phase-c/material/ct-swap-parameter.ts', import.meta.url), 'utf8');
  assert.ok(!src.includes('readFileSync'), 'the runtime must not read the generator');
  assert.ok(!src.includes('randomBytes') && !src.includes('generateKey'));
});

test('D2: the frozen corpus itself is untouched by the promotion', () => {
  // The parameter is promoted to an explicit Phase-C module, NOT injected into
  // frozen-material.json, whose hash the M2.4.2 audit pins.
  const corpus = readFileSync(new URL('../../../harness/phase-c/material/frozen-material.json', import.meta.url), 'utf8');
  assert.ok(!corpus.includes('PhaseC-CTSwap-16'), 'the frozen corpus must not be edited');
});
