// M3.7.6 -- full pre-freeze validation.
//
// This gate DEVELOPS NOTHING. It tries to break, cumulatively, everything the
// reopening declared finished -- and it is pointed at the path M4 will
// actually take, not only at its components. That distinction is the entire
// reason M3 was reopened: at v0.9 every component was verified and the runner
// had never driven the instrument.
//
// It produces NO M4 dataset. What it produces carries no attestation, and a
// test proves the scored gate refuses it.

import { test, after } from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { readFileSync, rmSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

import { assembleStructuralPlan } from '../../harness/phase-c/plan-assembly.js';
import { loadFrozenMaterialPool } from '../../harness/phase-c/material/load.js';
import { bindRequiredObligations, directedTransferObligations, nonInteropObligations } from '../../harness/phase-c/execution-binding.js';
import { recountPlan } from '../../harness/phase-c/plan-binding-audit.js';
import { auditGroundTruth } from '../../harness/phase-c/ground-truth/resolve.js';
import { auditRegistry } from '../../harness/phase-c/interop-eligibility/resolve.js';
import { allRegistryEntryHashes, registryEntryHash, resolveGamma0 } from '../../harness/evidence/registry-binding.js';
import { blockOf, scoredOrder, assessCompletion, digestOf, SCORED_EXECUTION_POLICY_VERSION, type OrderableObligation } from '../../harness/orchestration/scored-execution-policy.js';
import { assertIsScoredArtifact, attestScoredRun, ScoredAttestationError } from '../../harness/orchestration/scored-attestation.js';
import { checkEnvironment, assertExecutionEnvironment } from '../../harness/orchestration/execution-protocol.js';
import { runPhaseC, type ExecutionPlan } from '../../harness/orchestration/phase-c-orchestrator.js';
import { makeResolve } from '../../harness/phase-c/resolve-glue.js';
import { resolveClaims } from '../../harness/capability/capability-acquisition.js';
import { HKDF_CHROMIUM_ADAPTER, closeChromiumForTests } from '../../harness/orchestration/hkdf-chromium-wiring.js';
import { HKDF_CRYPTOPP_ADAPTER } from '../../harness/orchestration/hkdf-native-wiring.js';
import { HKDF_INFO_TAMPER } from '../../harness/mutations/hkdf.js';
import { MUTATION_REGISTRY } from '../../harness/registry/mutations.js';
import { APPLICABILITY_MATRIX } from '../../harness/applicability/matrix.js';
import { getFixtureResolver } from '../../harness/phase-c/fixture-index.js';
import { assertBundleConsistency, exportBundle, importBundle, reconstructScientificResult, type EvidenceBundle } from '../../harness/aggregation/evidence-export.js';
import { DRY_RUN_OUTPUT_DIR, makeDryRunBundle, persistDryRun, reloadDryRun } from '../../harness/orchestration/dry-run.js';
import { CHROMIUM_WEBCRYPTO, CRYPTOPP } from '../../harness/schema/backend-identity.js';
import type { PlannedObservation } from '../../harness/evidence/mutation-instance-result.js';
import type { HkdfRequest } from '../../src/contract/hkdf.js';

const repoRoot = fileURLToPath(new URL('../../', import.meta.url));
const pool = loadFrozenMaterialPool();
const plan = assembleStructuralPlan(pool);
const all = bindRequiredObligations(plan, pool);

after(async () => {
  await closeChromiumForTests();
  rmSync(DRY_RUN_OUTPUT_DIR, { recursive: true, force: true });
});

// =====================================================================
// 1. Historical identities
// =====================================================================


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

test('M3.7.6: transported snapshot preserves the frozen evidence contracts', () => {
  // Historical Git-boundary checks belong to the external pre-freeze
  // procedure. The reproducible suite validates the transported snapshot.
  const spec = readFileSync(`${repoRoot}harness/evidence/relation-spectrum.ts`, 'utf8');
  assert.ok(spec.includes("export type RelationValue = 'pass' | 'fail' | 'n/a';"));
  assert.equal((spec.match(/readonly R_\w+: RelationValue;/g) ?? []).length, 6);
  const mr = readFileSync(`${repoRoot}harness/evidence/mutation-result.ts`, 'utf8');
  assert.ok(mr.includes('readonly observedSpectrum: RelationSpectrum;'));
  assert.ok(!mr.includes('nonScoreable'));
  // And the frozen corpus, whose hash audit:m2.4.2 pins.
  const corpus = readFileSync(`${repoRoot}harness/phase-c/material/frozen-material.json`, 'utf8');
  assert.ok(!corpus.includes('PhaseC-CTSwap-16'), 'D17 promoted the parameter WITHOUT editing the corpus');
});

// =====================================================================
// 2. One normative cardinality, from one predicate
// =====================================================================

test('M3.7.6: the cardinalities agree across every independent walk', () => {
  const rc = recountPlan(plan);
  assert.equal(rc.planned, 1641);
  assert.equal(rc.required, 886);
  assert.equal(all.length, rc.required, 'binder and recount consume one predicate -- the D13 repair');
  assert.equal(nonInteropObligations(all).length, 670);
  assert.equal(directedTransferObligations(all).length, 216);
  assert.equal(670 + 216, 886);
  assert.equal(rc.required + rc.notRequiredDistinct, rc.planned);
});

test('M3.7.6: the frozen populations are unchanged', () => {
  assert.equal(plan.classes.length, 79);
  assert.equal(auditGroundTruth().pairs, 90);
  const el = auditRegistry();
  assert.equal(el.totalPairs, 81);
  assert.deepEqual({ e: el.eligible, b: el.producerContractuallyBlocked, n: el.noOperationalInput }, { e: 55, b: 16, n: 10 });
  assert.equal(allRegistryEntryHashes().size, 79);
});

test('M3.7.6: R_interop by operation, after D2', () => {
  const byOp: Record<string, number> = {};
  for (const o of directedTransferObligations(all)) byOp[o.operation] = (byOp[o.operation] ?? 0) + 1;
  assert.deepEqual(byOp, { gcm: 66, oaep: 18, pss: 18, 'rsa-ser': 66, 'ec-ser': 48 });
});

// =====================================================================
// 3. D14 policy over the finished population
// =====================================================================

const orderable: OrderableObligation[] = all.map((o) => ({
  operation: o.operation, mutationId: o.mutationId, stimulusInstanceId: o.stimulusInstanceId,
  relation: o.relation, scopeKey: JSON.stringify(o.scope),
}));

test('M3.7.6: the D14 order is total over the 886 Required obligations and result-independent', () => {
  const ordered = scoredOrder(orderable);
  assert.equal(ordered.length, 886);
  const keys = ordered.map((o) => `${o.operation}|${o.mutationId}|${o.stimulusInstanceId}|${o.relation}|${o.scopeKey}`);
  assert.equal(new Set(keys).size, 886, 'total: no ties');
  const reversed = scoredOrder([...orderable].reverse()).map((o) => `${o.operation}|${o.mutationId}|${o.stimulusInstanceId}|${o.relation}|${o.scopeKey}`);
  assert.deepEqual(keys, reversed);
});

test('M3.7.6: no D14 block splits a class, over all 73 Required-bearing classes', () => {
  const blocks = new Map<string, Set<string>>();
  for (const o of all) {
    const s = blocks.get(o.mutationId) ?? new Set<string>();
    s.add(blockOf(o.operation));
    blocks.set(o.mutationId, s);
  }
  assert.equal(blocks.size, 73);
  for (const [id, b] of blocks) assert.equal(b.size, 1, `${id} spans ${b.size} blocks`);
});

test('M3.7.6: the completion gate demands exactly the 886 Required obligations', () => {
  const keys = all.map((o) => `${o.mutationId}|${o.stimulusInstanceId}|${o.relation}|${JSON.stringify(o.scope)}`);
  assert.equal(assessCompletion(keys, keys).complete, true);
  assert.equal(assessCompletion(keys, keys.slice(1)).complete, false);
  assert.equal(assessCompletion(keys, [...keys, 'extra']).complete, false);
});

// =====================================================================
// 4. Environment and compiled artifact
// =====================================================================

test('M3.7.6: the environment gate passes where the suite runs', () => {
  const checks = checkEnvironment({
    nativeBuildDir: `${repoRoot}harness/orchestration/native-build`,
    chromiumVersion: CHROMIUM_WEBCRYPTO.apiVersion,
  });
  assert.deepEqual(checks.filter((c) => !c.satisfied).map((c) => c.id), []);
  assert.doesNotThrow(() => assertExecutionEnvironment(checks));
});

test('M3.7.6: the COMPILED artifact reports the repaired figures', () => {
  const out = execFileSync('node', ['-e', `
    import('./dist/harness/phase-c/plan-assembly.js').then(async (pa) => {
      const ml = await import('./dist/harness/phase-c/material/load.js');
      const pb = await import('./dist/harness/phase-c/plan-binding-audit.js');
      const p = pa.assembleStructuralPlan(ml.loadFrozenMaterialPool());
      const r = pb.recountPlan(p);
      console.log(JSON.stringify({ classes: p.classes.length, planned: r.planned, required: r.required }));
    });
  `], { cwd: repoRoot, encoding: 'utf8' }).trim();
  assert.deepEqual(JSON.parse(out.split('\n').pop()!), { classes: 79, planned: 1641, required: 886 });
});

// =====================================================================
// 5. THE REAL PATH -- runPhaseC over a complete D14 block
// =====================================================================

const HKDF_CLASS = 'HKDF-INFO-TAMPER';
const baseFixture = (): HkdfRequest =>
  ({ ikm: new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8]), salt: undefined, info: new Uint8Array([9, 9, 9]), length: 32 });

function realPlan(): ExecutionPlan {
  const cls = plan.classes.find((c) => c.mutationId === HKDF_CLASS)!;
  const si = cls.stimulusInstances[0]!;
  // Entries come from the STRUCTURAL plan, not from the bound obligations.
  // Planned != Required: R_err is applicable to HKDF and therefore PLANNED,
  // while M3.7-D2 makes it non-comparable for this class and so not an
  // obligation. Building the plan from the required set alone would PRUNE it,
  // which is exactly what H10 and D13 forbade -- and the aggregator refuses,
  // correctly, when an applicable relation has no planned scope.
  const entries = si.executability.map((x) => ({
    relation: x.relation,
    scope: x.scope,
    resolve: makeResolve<HkdfRequest, unknown>(x.relation, x.scope, {
      adapter: HKDF_CHROMIUM_ADAPTER as never, counterpart: HKDF_CRYPTOPP_ADAPTER as never,
      capability: capabilityDepsFor(x.relation, HKDF_CHROMIUM_ADAPTER),
    }),
  }));
  return {
    classes: [{
      mutation: HKDF_INFO_TAMPER, operation: 'hkdf',
      gamma0Ref: cls.gamma0Ref, registryEntryHash: cls.registryEntryHash,
      applicability: APPLICABILITY_MATRIX['hkdf'],
      expectedSpectrum: cls.expectedSpectrum,
      stimulusInstances: [{
        stimulusInstanceId: si.stimulusInstanceId,
        baseFixture: baseFixture(),
        executability: si.executability.map((x) => ({ relation: x.relation, scope: x.scope, state: x.state })),
      }],
      entries,
    }],
  } as unknown as ExecutionPlan;
}

test('M3.7.6: the driven plan is the STRUCTURAL one -- Planned != Required', () => {
  const p = realPlan();
  const cls = (p.classes as unknown as { stimulusInstances: { executability: { relation: string }[] }[] }[])[0]!;
  const planned = new Set(cls.stimulusInstances[0]!.executability.map((x) => x.relation));
  const required = new Set(all.filter((o) => o.mutationId === HKDF_CLASS).map((o) => o.relation));
  assert.ok(planned.has('R_err'), 'R_err is applicable and therefore planned');
  assert.ok(!required.has('R_err'), 'and non-comparable, so not an obligation (M3.7-D2)');
  assert.ok(planned.size > required.size, 'the plan is not pruned to the obligations');
});

test('M3.7.6: runPhaseC drives the real path end to end, under the frozen policy', async () => {
  const result = await runPhaseC(realPlan());
  assert.ok(result.executions.length > 0, 'real executions happened');
  for (const e of result.executions) assert.equal(e.executionStatus, 'completed');
  assert.equal(result.instances.length, 1);
  assert.equal(result.scientificResults.length, 1);
  assert.equal(result.omittedClasses.length, 0);
  // Every observation rests on executions the bundle actually contains.
  const ids = new Set(result.executions.map((e) => e.executionId));
  for (const o of result.observations) {
    assert.ok(o.participants.length > 0);
    for (const p of o.participants) assert.ok(ids.has(p), `observation references unregistered execution ${p}`);
  }
});

test('M3.7.6: the real path reaches a persisted, reloaded, reconstructed bundle', async () => {
  const result = await runPhaseC(realPlan());
  const bundle: EvidenceBundle = {
    bundleVersion: '2.0', executions: result.executions, observations: result.observations,
    instanceResults: result.instances, mutationResults: result.mutations,
    scientificResults: result.scientificResults, omittedClasses: result.omittedClasses,
  };
  assert.doesNotThrow(() => assertBundleConsistency(bundle));
  const back = importBundle(exportBundle(bundle));
  const { result: sr } = reconstructScientificResult(back, HKDF_CLASS);
  assert.equal(sr.registryEntryHash, registryEntryHash(HKDF_CLASS));
  assert.ok(resolveGamma0(sr.mutationId, sr.registryEntryHash!).length > 0, 'sigma(c) recoverable from the dataset');
});

// =====================================================================
// 6. D15 -- and the proof this gate produced no M4 data
// =====================================================================

test('M3.7.6: what this gate produced is NOT scored, and the gate says so', async () => {
  const result = await runPhaseC(realPlan());
  const bundle: EvidenceBundle = {
    bundleVersion: '2.0', executions: result.executions, observations: result.observations,
    instanceResults: result.instances, mutationResults: result.mutations,
    scientificResults: result.scientificResults, omittedClasses: result.omittedClasses,
  };
  const serialized = exportBundle(bundle);
  // No attestation was issued for it, so the scored gate refuses it.
  assert.throws(() => assertIsScoredArtifact({ bundle }, serialized), ScoredAttestationError);
  assert.throws(() => assertIsScoredArtifact({ bundle }, serialized), /Absence is not a claim/);
});

test('M3.7.6: dry-run and scored remain separable in both directions', () => {
  const dry = makeDryRunBundle({
    bundleVersion: '2.0', executions: [], observations: [], instanceResults: [],
    mutationResults: [], scientificResults: [], omittedClasses: [],
  });
  const path = persistDryRun(DRY_RUN_OUTPUT_DIR, 'm376', dry);
  assert.equal(reloadDryRun(path).runKind, 'dry-run');
  assert.throws(() => assertIsScoredArtifact(dry, 'x'), /DRY RUN artifact/);
  // And a positive attestation still verifies over sentinel content.
  const sentinel = '{"sentinel":"M3.7.6 validation -- NOT M4 evidence"}';
  const att = attestScoredRun({
    identity: {
      runId: 'run-m376-sentinel', policyVersion: SCORED_EXECUTION_POLICY_VERSION,
      instrumentCommit: '065ae8f', plannedObligations: 1641, requiredObligations: 1192,
      environmentDigest: digestOf('env'),
    },
    serializedContent: sentinel,
  });
  assert.doesNotThrow(() => assertIsScoredArtifact({ attestation: att }, sentinel));
});

// =====================================================================
// 7. Provenance of the repairs themselves
// =====================================================================

test('M3.7.6: the reopening record covers every defect it repaired', () => {
  const doc = readFileSync(`${repoRoot}M3.7-REOPENING.md`, 'utf8');
  for (const d of ['D11', 'D12', 'D13', 'D14', 'D15', 'D16', 'D17']) {
    assert.ok(doc.includes(d), `the reopening record must name ${d}`);
  }
  assert.ok(doc.includes('9de63f4'), 'and the freeze it reopened');
});

test('M3.7.6: every class still resolves a fixture and a ground-truth row', () => {
  let pairs = 0;
  for (const e of MUTATION_REGISTRY) {
    for (const si of e.stimulusInstances) {
      getFixtureResolver(e.mutationId, si.stimulusInstanceId)(e.mutationId, si.stimulusInstanceId, pool);
      pairs += 1;
    }
  }
  assert.equal(pairs, 90);
  assert.equal(CRYPTOPP.family, 'cryptopp');
});
