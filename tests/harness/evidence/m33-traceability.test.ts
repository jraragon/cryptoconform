// Bloque D / M3.3 -- dataset, persistence and traceability gate.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';

import {
  allRegistryEntryHashes, registryEntryHash, resolveGamma0, verifyRegistryBinding,
  RegistryBindingError,
} from '../../../harness/evidence/registry-binding.js';
import { makeNonExecutionObservation } from '../../../harness/evidence/relation-observation.js';
import { toRelationValue } from '../../../harness/evidence/relation-spectrum.js';
import { assembleStructuralPlan } from '../../../harness/phase-c/plan-assembly.js';
import { loadFrozenMaterialPool } from '../../../harness/phase-c/material/load.js';
import { MUTATION_REGISTRY } from '../../../harness/registry/mutations.js';
import { CHROMIUM_WEBCRYPTO, CRYPTOPP } from '../../../harness/schema/backend-identity.js';
import {
  exportBundle, importBundle, reconstructScientificResult, type EvidenceBundle,
} from '../../../harness/aggregation/evidence-export.js';
import { makePhaseCScientificResult } from '../../../harness/evidence/phase-c-scientific-result.js';
import type { MutationInstanceResult } from '../../../harness/evidence/mutation-instance-result.js';
import type { RelationApplicability } from '../../../harness/schema/registry-types.js';

const plan = assembleStructuralPlan(loadFrozenMaterialPool());

// =====================================================================
// The registry binding: content, not a name
// =====================================================================

test('M3.3: every class has a registry entry hash, and all 79 are distinct', () => {
  const hashes = allRegistryEntryHashes();
  assert.equal(hashes.size, 79);
  assert.equal(new Set(hashes.values()).size, 79, 'a shared hash would let one class stand for another');
});

test('M3.3: the assembler binds every class -- gamma0Ref NAMES, the hash PROVES', () => {
  assert.equal(plan.classes.length, 79);
  for (const c of plan.classes) {
    assert.equal(c.gamma0Ref, `registry:${c.mutationId}`);
    assert.equal(c.registryEntryHash, registryEntryHash(c.mutationId),
      `${c.mutationId}: the plan's binding must be the entry's own content hash`);
  }
});

test('M3.3: the binding is over CONTENT -- a changed Gamma_0 is refused', () => {
  const entry = MUTATION_REGISTRY.find((e) => e.mutationId === 'GCM-AAD-IGNORED')!;
  const bound = registryEntryHash(entry.mutationId);
  assert.doesNotThrow(() => verifyRegistryBinding(entry.mutationId, bound));
  // A stale binding is refused rather than absorbed. This is the failure mode
  // `registry:<mutationId>` could not detect: a name survives a change of
  // content and goes on agreeing with whatever the registry now says.
  assert.throws(() => verifyRegistryBinding(entry.mutationId, 'f'.repeat(64)), RegistryBindingError);
  assert.throws(() => verifyRegistryBinding(entry.mutationId, 'f'.repeat(64)), /Refusing rather than absorbing/);
});

test('M3.3: a class that disappeared cannot be bound to nothing', () => {
  assert.throws(() => registryEntryHash('GONE'), /cannot be bound to nothing/);
});

test('M3.3: Gamma_0 is recoverable ONLY through the binding', () => {
  // The route M5 needs for sigma(c). It cannot return clauses without first
  // proving the registry still says what the result was bound to.
  const id = 'GCM-AUTHENTICATION-BYPASS';
  const g = resolveGamma0(id, registryEntryHash(id));
  assert.deepEqual([...g], ['gcm.authentication', 'gcm.validation']);
  assert.throws(() => resolveGamma0(id, 'a'.repeat(64)), RegistryBindingError);
});

test('M3.3: the bound payload is the causal ground truth, not the prediction', () => {
  // expectedSpectrum is a PREDICTION and stimulus descriptions are prose;
  // neither is what a frozen result must be held to. Changing a prediction
  // must not invalidate results, and changing Gamma_0 must.
  const src = readFileSync(new URL('../../../harness/evidence/registry-binding.ts', import.meta.url), 'utf8');
  const payload = src.slice(src.indexOf('export function registryEntryPayload'), src.indexOf('export function registryEntryHash'));
  assert.ok(payload.includes('gamma0'));
  assert.ok(payload.includes('mechanism'));
  assert.ok(!payload.includes('expectedSpectrum'), 'a prediction must not be able to invalidate a frozen result');
  assert.ok(!payload.includes('description'), 'prose must not either');
});

// =====================================================================
// The NonExecution bridge
// =====================================================================

test('M3.3: a planned non-execution now MATERIALISES as an observation', () => {
  // Designed since M3-H9.3a-3.1 and, until now, with no producer anywhere in
  // Phase C: the fact lived only in coverage.planned.
  const obs = makeNonExecutionObservation({
    relation: 'R_interop',
    scope: { kind: 'backend-pair', from: CHROMIUM_WEBCRYPTO, to: CRYPTOPP },
    context: { kind: 'mutation', phase: 'C', mutationId: 'M', stimulusInstanceId: 'default' },
    reason: 'backend-capability-absent',
    evaluatorId: 'R_interop',
  });
  assert.deepEqual(obs.status, { state: 'not-executed', reason: 'backend-capability-absent' });
  assert.ok(obs.basis.includes('backend-capability-absent'), 'the reason is visible in the evidence, not only in the plan');
});

test('M3.3: the bridge REUSES the frozen vocabulary, it does not re-decide it', () => {
  const frozen = ['stimulus-not-expressible', 'backend-capability-absent', 'direction-not-materializable'] as const;
  for (const reason of frozen) {
    const obs = makeNonExecutionObservation({
      relation: 'R_ser', scope: { kind: 'single-backend', backend: CRYPTOPP },
      context: { kind: 'mutation', phase: 'C', mutationId: 'M', stimulusInstanceId: 'default' },
      reason, evaluatorId: 'R_ser',
    });
    assert.deepEqual(obs.status, { state: 'not-executed', reason });
  }
});

test('M3.3: a non-execution observation still cannot cross into a spectrum cell', () => {
  // The bridge materialises the fact WITHOUT weakening the boundary that
  // keeps not-executed out of pass/fail/n-a.
  assert.equal(toRelationValue('not-executed'), undefined);
  assert.equal(toRelationValue('insufficient-evidence'), undefined);
});

// =====================================================================
// Reconstructibility from the frozen dataset
// =====================================================================

test('M3.3: bundle + frozen registry reconstruct Gamma_0 and therefore sigma', () => {
  const inst: MutationInstanceResult = {
    mutationId: 'GCM-AAD-IGNORED', stimulusInstanceId: 'default', operation: 'gcm',
    observations: [], coverage: { planned: [], reached: [], outstanding: [] }, complete: true,
  };
  const applicability: RelationApplicability =
    { R_byte: true, R_interop: true, R_ser: true, R_val: true, R_err: true, R_cap: true };
  const sr = makePhaseCScientificResult({
    mutationId: 'GCM-AAD-IGNORED', operation: 'gcm', gamma0Ref: 'registry:GCM-AAD-IGNORED',
    registryEntryHash: registryEntryHash('GCM-AAD-IGNORED'),
    applicability,
    observedSpectrum: { R_byte: 'pass', R_interop: 'pass', R_ser: 'pass', R_val: 'pass', R_err: 'pass', R_cap: 'pass' },
    nonScoreable: [], instanceResults: [inst],
    detectionSupport: { divergentInstances: 0, evaluatedInstances: 1 },
  });
  const bundle: EvidenceBundle = {
    bundleVersion: '2.0', executions: [], observations: [], instanceResults: [inst],
    mutationResults: [], scientificResults: [sr], omittedClasses: [],
  };

  // From the frozen dataset alone, plus the registry it is bound to.
  const back = importBundle(exportBundle(bundle));
  const { result } = reconstructScientificResult(back, 'GCM-AAD-IGNORED');
  assert.equal(result.registryEntryHash, registryEntryHash('GCM-AAD-IGNORED'));
  const gamma0 = resolveGamma0(result.mutationId, result.registryEntryHash!);
  assert.ok(gamma0.length > 0, 'sigma(c) is now computable from the dataset plus its bound registry');
});

test('M3.3: the binding survives the JSON round trip', () => {
  const h = registryEntryHash('PSS-KEY-ROLE-BYPASS');
  assert.equal(JSON.parse(JSON.stringify({ registryEntryHash: h })).registryEntryHash, h);
  assert.equal(h.length, 64);
});

test('M3.3: the field is optional, so pre-existing M2 objects stay valid', () => {
  const src = readFileSync(new URL('../../../harness/evidence/mutation-result.ts', import.meta.url), 'utf8');
  assert.ok(src.includes('readonly registryEntryHash?: string;'), 'additive, never required');
});
