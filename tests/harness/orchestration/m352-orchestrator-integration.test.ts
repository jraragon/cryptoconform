// Bloque D / M3.5.2 -- the full orchestrator integration gate.
//
//     runPhaseC(ExecutablePlan)  ->  FinalBundle  ->  reload  ->  reconstruction
//
// Deliberately NOT a rerun of the fourteen shapes: those are validated. What
// this proves is the other half of the distinction v0.8 §7.5 exists to keep:
//
//     All components work together  !=  PhaseCOrchestrator drives them together
//
// So the test hands a real assembled plan to runPhaseC and touches nothing
// afterwards. There is no manual execution, no inserted observation and no
// aggregator called by hand -- doing any of those would re-prove M3.5.1.

import { test, after } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, rmSync } from 'node:fs';

import { runPhaseC, type ExecutionPlan } from '../../../harness/orchestration/phase-c-orchestrator.js';
import { makeResolve } from '../../../harness/phase-c/resolve-glue.js';
import { resolveClaims } from '../../../harness/capability/capability-acquisition.js';
import { HKDF_CHROMIUM_ADAPTER, closeChromiumForTests } from '../../../harness/orchestration/hkdf-chromium-wiring.js';
import { HKDF_CRYPTOPP_ADAPTER } from '../../../harness/orchestration/hkdf-native-wiring.js';
import { resolveDispatch } from '../../../harness/orchestration/dispatch.js';
import { HKDF_INFO_TAMPER } from '../../../harness/mutations/hkdf.js';
import { assembleStructuralPlan } from '../../../harness/phase-c/plan-assembly.js';
import { loadFrozenMaterialPool } from '../../../harness/phase-c/material/load.js';
import { registryEntryHash, resolveGamma0 } from '../../../harness/evidence/registry-binding.js';
import {
  DRY_RUN_OUTPUT_DIR, makeDryRunBundle, persistDryRun, reloadDryRun,
} from '../../../harness/orchestration/dry-run.js';
import { reconstructScientificResult, assertBundleConsistency, type EvidenceBundle } from '../../../harness/aggregation/evidence-export.js';
import { CHROMIUM_WEBCRYPTO, CRYPTOPP } from '../../../harness/schema/backend-identity.js';
import type { HkdfRequest } from '../../../src/contract/hkdf.js';
import type { PlannedObservation } from '../../../harness/evidence/mutation-instance-result.js';

after(async () => {
  await closeChromiumForTests();
  rmSync(DRY_RUN_OUTPUT_DIR, { recursive: true, force: true });
});

const MUTATION_ID = 'HKDF-INFO-TAMPER';
const STIMULUS = 'default';
const baseFixture = (): HkdfRequest =>
  ({ ikm: new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8]), salt: undefined, info: new Uint8Array([9, 9, 9]), length: 32 });

const single = (backend: typeof CHROMIUM_WEBCRYPTO): PlannedObservation['scope'] =>
  ({ kind: 'single-backend', backend });
const manifestScope = { kind: 'manifest', backend: CHROMIUM_WEBCRYPTO, apiSurface: CHROMIUM_WEBCRYPTO.apiSurface } as PlannedObservation['scope'];
const crossSet: PlannedObservation['scope'] =
  { kind: 'cross-backend-set', backends: [CHROMIUM_WEBCRYPTO, CRYPTOPP] } as PlannedObservation['scope'];

/**
 * The plan handed to runPhaseC. Its structural facts -- applicability,
 * gamma0Ref, the registry binding -- come from the real assembler, so this is
 * not a plan invented for the test; only the entries an HKDF class can
 * actually execute here are selected.
 */
function executablePlan(): ExecutionPlan {
  const assembled = assembleStructuralPlan(loadFrozenMaterialPool());
  const cls = assembled.classes.find((c) => c.mutationId === MUTATION_ID);
  assert.ok(cls !== undefined, 'the class must come from the real assembler');

  // Dispatch is consulted, not bypassed: the adapters below are the ones the
  // frozen table resolves for (hkdf, backend, derive).
  assert.equal(resolveDispatch('hkdf', CHROMIUM_WEBCRYPTO, 'derive').symbol, 'HKDF_CHROMIUM_ADAPTER');
  assert.equal(resolveDispatch('hkdf', CRYPTOPP, 'derive').symbol, 'HKDF_CRYPTOPP_ADAPTER');

  const entries = [
    { relation: 'R_val' as const, scope: single(CHROMIUM_WEBCRYPTO) },
    { relation: 'R_err' as const, scope: single(CHROMIUM_WEBCRYPTO) },
    { relation: 'R_byte' as const, scope: crossSet },
    { relation: 'R_cap' as const, scope: manifestScope },
  ].map((e) => ({
    relation: e.relation,
    scope: e.scope,
    resolve: makeResolve<HkdfRequest, unknown>(e.relation, e.scope, {
      adapter: HKDF_CHROMIUM_ADAPTER as never,
      counterpart: HKDF_CRYPTOPP_ADAPTER as never,
      // R_cap's declared side comes from the frozen manifest since M3.9-B,
      // not from a second execution of the same adapter.
      capability: capabilityDepsFor(e.relation, HKDF_CHROMIUM_ADAPTER),
    }),
  }));

  return {
    classes: [{
      mutation: HKDF_INFO_TAMPER,
      operation: 'hkdf',
      gamma0Ref: cls.gamma0Ref,
      registryEntryHash: cls.registryEntryHash,
      applicability: { R_byte: true, R_interop: false, R_ser: false, R_val: true, R_err: true, R_cap: true },
      expectedSpectrum: cls.expectedSpectrum,
      stimulusInstances: [{
        stimulusInstanceId: STIMULUS,
        baseFixture: baseFixture(),
        executability: entries.map((e) => ({
          relation: e.relation, scope: e.scope, state: { kind: 'required' as const },
        })),
      }],
      entries,
    }],
  } as unknown as ExecutionPlan;
}


/**
 * R_cap's own deps. Since M3.9-B the declared side comes from the frozen
 * manifest and the scored side from a probe, so the resolver needs the claim
 * rather than a second execution of the same adapter.
 */
function capabilityDepsFor(relation: string, adapter: unknown) {
  if (relation !== 'R_cap') return undefined;
  const claim = resolveClaims('hkdf', CHROMIUM_WEBCRYPTO)[0]!;
  return {
    claim,
    declarationEvidenceIds: [`manifest:${claim.cell.basisKind}:${claim.capabilityId}`],
    probeAdapter: adapter as never,
    probeInput: baseFixture(),
  };
}

test('M3.5.2: runPhaseC drives the instrument end to end, with no manual step', async () => {
  const result = await runPhaseC(executablePlan());

  // Real executions happened, driven by the runner rather than by the test.
  assert.ok(result.executions.length >= 3, `expected real executions, got ${result.executions.length}`);
  for (const e of result.executions) {
    assert.equal(e.executionStatus, 'completed');
    // Baseline executions carry a baseline context; mutation ones name the class.
    if (e.context.kind === 'mutation') assert.equal(e.context.mutationId, MUTATION_ID);
  }

  // Every planned entry that CARRIES AN OBLIGATION produced an observation
  // through resolve(). R_err does not: M3-H13 makes it structurally
  // non-comparable for this class, so the runner never resolves it.
  assert.equal(result.observations.length, 3);
  assert.ok(!result.observations.some((o) => o.relation === 'R_err'));
  for (const o of result.observations) {
    assert.equal(o.basis, 'M3.5.2 orchestrator-driven resolution');
    assert.ok(o.participants.length > 0, 'an observation must name the executions it rests on');
  }

  // One instance result, complete, and one scientific result.
  assert.equal(result.instances.length, 1);
  assert.equal(result.instances[0]!.complete, true);
  assert.equal(result.scientificResults.length, 1);
  assert.equal(result.omittedClasses.length, 0);
});

test('M3.5.2: R_byte really used two backends, and really detected the mutation', async () => {
  const result = await runPhaseC(executablePlan());
  const rByte = result.observations.find((o) => o.relation === 'R_byte');
  assert.ok(rByte !== undefined);
  assert.equal(rByte!.participants.length, 2, 'a cross-provider comparison needs two executions');
  // The two executions are of DIFFERENT backends -- the mutation is the
  // common stimulus both received, not one side of the comparison (M3-H8).
  const parts = result.executions.filter((e) => rByte!.participants.includes(e.executionId));
  assert.equal(parts.length, 2);
  assert.notEqual(parts[0]!.subject.backend.family, parts[1]!.subject.backend.family);
  // Both real providers derive the same OKM from the same mutated input, so
  // the honest verdict is pass -- and it came from the evaluator, not the test.
  assert.equal(rByte!.status, 'pass');
});

test("M3.5.2: R_cap's declared side is NAMED, not executed a second time", async () => {
  // UPDATED at M3.8.2. The original asserted two distinct participants,
  // which was I5's old shape: two identities of one mechanism. Since M3.9-B
  // the declared side comes from the frozen manifest and is identified by
  // declarationBasisRef, so the observation carries ONE scored execution and
  // names its basis.
  const result = await runPhaseC(executablePlan());
  const rCap = result.observations.find((o) => o.relation === 'R_cap')!;
  assert.equal(rCap.participants.length, 1, 'one scored execution');
  assert.ok(rCap.declarationBasisRef !== undefined, 'and a named declaration basis');
  assert.ok(!rCap.participants.includes(rCap.declarationBasisRef!),
    "I5': the basis may never also be a participant");
  // The scored execution really happened and is in the bundle.
  assert.ok(result.executions.some((e) => e.executionId === rCap.participants[0]));
});

test('M3.5.2: the run reaches a persisted, reloaded, reconstructed bundle', async () => {
  const result = await runPhaseC(executablePlan());
  const bundle: EvidenceBundle = {
    bundleVersion: '2.0',
    executions: result.executions, observations: result.observations,
    instanceResults: result.instances, mutationResults: result.mutations,
    scientificResults: result.scientificResults, omittedClasses: result.omittedClasses,
  };
  assert.doesNotThrow(() => assertBundleConsistency(bundle));

  const path = persistDryRun(DRY_RUN_OUTPUT_DIR, 'm352-orchestrated', makeDryRunBundle(bundle));
  const back = reloadDryRun(path);
  assert.equal(back.runKind, 'dry-run', 'an orchestrated dry run is still a dry run');

  const { result: sr, instances } = reconstructScientificResult(back.bundle, MUTATION_ID);
  assert.equal(instances.length, 1);
  assert.equal(sr.requiredEvidenceComplete, true);
  // The registry binding survived the whole path, so Gamma_0 -- and therefore
  // sigma(c) -- is recoverable from what the runner produced.
  assert.equal(sr.registryEntryHash, registryEntryHash(MUTATION_ID));
  assert.ok(resolveGamma0(sr.mutationId, sr.registryEntryHash!).length > 0);
});

test('M3.5.2: resolve() is orchestration glue -- it decides no scientific policy', () => {
  // Checked on the source, since the property is what the code MAY NOT do.
  const src = readFileSync(new URL('../../../harness/phase-c/resolve-glue.ts', import.meta.url), 'utf8');
  const imports = src.split('\n').filter((l) => l.trimStart().startsWith('import'));
  for (const line of imports) {
    assert.ok(!line.includes('src/contract'), `no contract import may appear: ${line.trim()}`);
    assert.ok(!line.includes('interop-eligibility'), 'eligibility is pre-registered, never recomputed here');
    assert.ok(!line.includes('applicability'), 'Required is not recomputed here');
  }
  // The expectation is READ by key, and a missing row is a refusal rather
  // than a default.
  assert.ok(src.includes('resolveGroundTruth('));
  assert.ok(src.includes('no expected decision is pre-registered'));
  // And there is no mutationId branching, which M2.4.4's own restriction
  // forbids and the relation-based dispatch makes unnecessary.
  assert.ok(!/mutationId\s*===/.test(src));
});

test('M3.5.2: R_interop refuses to be assembled from one execution', () => {
  const resolve = makeResolve<HkdfRequest, unknown>('R_interop', single(CHROMIUM_WEBCRYPTO), {
    adapter: HKDF_CHROMIUM_ADAPTER as never,
  });
  // An interoperability claim needs a producer and a consumer; the glue
  // refuses rather than inventing one from a single run.
  assert.rejects(() => resolve({
    mutationId: MUTATION_ID, stimulusInstanceId: STIMULUS, baseFixture: baseFixture(),
    mutation: HKDF_INFO_TAMPER,
    getBaseline: async () => { throw new Error('unused'); },
    runMutation: async () => { throw new Error('unused'); },
    runDeclarationProbe: async () => { throw new Error('unused'); },
  } as never), /Refusing rather than assembling/);
});
