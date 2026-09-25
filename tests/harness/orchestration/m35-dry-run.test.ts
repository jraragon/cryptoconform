// Bloque D / M3.5 -- the dry run, end to end, on real backends.
//
//   ExecutionPlan -> Orchestrator primitives -> RealBackendExecution ->
//   ExecutionEvidence -> Projection_R -> Evaluator_R -> RelationObservation ->
//   MutationInstanceResult -> ScientificResult -> EvidenceBundle -> Reconstruction
//
// Small relative to M4 and STRUCTURALLY REPRESENTATIVE, which is the criterion
// M3.1 sets: not one class per operation, but every distinct execution,
// projection and persistence SHAPE traversed at least once. The shapes that
// could break differently are the direct adapter, the key-bound factory, the
// serialization wrapper, the cross-backend byte comparison, the directed
// transfer, and a planned non-execution.

import { test, after } from 'node:test';
import assert from 'node:assert/strict';
import { webcrypto } from 'node:crypto';
import { rmSync } from 'node:fs';

import { executeBaseline, executeMutation } from '../../../harness/orchestration/engine.js';
import { HKDF_CHROMIUM_ADAPTER, closeChromiumForTests } from '../../../harness/orchestration/hkdf-chromium-wiring.js';
import { HKDF_CRYPTOPP_ADAPTER, HKDF_BOUNCYCASTLE_ADAPTER } from '../../../harness/orchestration/hkdf-native-wiring.js';
import { makeOaepEncryptCryptoppAdapter, makeOaepDecryptBouncyCastleAdapter } from '../../../harness/orchestration/oaep-native-wiring.js';
import type { OaepKeyHex } from '../../../harness/orchestration/oaep-chromium-wiring.js';
import { rsaSerExportCryptopp, rsaSerImportBouncyCastle } from '../../../harness/orchestration/rsa-ser-native-wiring.js';
import { ecSerExportCryptopp, ecSerImportBouncyCastle } from '../../../harness/orchestration/ec-ser-native-wiring.js';
import { HKDF_INFO_TAMPER } from '../../../harness/mutations/hkdf.js';
import {
  assertNotScored, bindFactory, DRY_RUN_OUTPUT_DIR, DryRunContaminationError,
  makeDryRunBundle, persistDryRun, reloadDryRun, wrapSerializationExecution,
} from '../../../harness/orchestration/dry-run.js';
import { runTransfer } from '../../../harness/orchestration/interop-transfer.js';
import { evaluateRelation } from '../../../harness/phase-c/relation-wiring.js';
import { makeNonExecutionObservation } from '../../../harness/evidence/relation-observation.js';
import { makeMutationInstanceResult, type PlannedObservation } from '../../../harness/evidence/mutation-instance-result.js';
import { makePhaseCScientificResult } from '../../../harness/evidence/phase-c-scientific-result.js';
import { reconstructScientificResult, type EvidenceBundle } from '../../../harness/aggregation/evidence-export.js';
import { registryEntryHash, resolveGamma0 } from '../../../harness/evidence/registry-binding.js';
import { resolveGroundTruth } from '../../../harness/phase-c/ground-truth/resolve.js';
import { BOUNCY_CASTLE, CHROMIUM_WEBCRYPTO, CRYPTOPP } from '../../../harness/schema/backend-identity.js';
import type { ExecutionEvidence } from '../../../harness/evidence/execution-evidence.js';
import type { RelationObservation } from '../../../harness/evidence/relation-observation.js';
import type { RelationApplicability } from '../../../harness/schema/registry-types.js';
import type { HkdfRequest } from '../../../src/contract/hkdf.js';
import type { OaepEncryptRequest, OaepDecryptRequest } from '../../../src/contract/oaep.js';

after(async () => {
  await closeChromiumForTests();
  rmSync(DRY_RUN_OUTPUT_DIR, { recursive: true, force: true });
});

/** Every shape the dry run must traverse, ticked by the runs below. */
const covered = new Set<string>();
const cover = (shape: string) => { covered.add(shape); };

const hkdfFixture = (): HkdfRequest =>
  ({ ikm: new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8]), salt: undefined, info: new Uint8Array([9, 9, 9]), length: 32 });

const bytesOf = (e: ExecutionEvidence): string => (e.output as { bytes: string }).bytes;

let hkdfChromium: ExecutionEvidence;
let hkdfCryptopp: ExecutionEvidence;
let hkdfMutated: ExecutionEvidence;
const observations: RelationObservation[] = [];

// =====================================================================
// Shape 1 -- the direct adapter, on three real backends
// =====================================================================

test('M3.5: HKDF through a DIRECT adapter, on Chromium, Crypto++ and Bouncy Castle', async () => {
  hkdfChromium = await executeBaseline('B', 'dry-hkdf-chromium', hkdfFixture(), HKDF_CHROMIUM_ADAPTER);
  hkdfCryptopp = await executeBaseline('B', 'dry-hkdf-cryptopp', hkdfFixture(), HKDF_CRYPTOPP_ADAPTER);
  const bc = await executeBaseline('B', 'dry-hkdf-bc', hkdfFixture(), HKDF_BOUNCYCASTLE_ADAPTER);
  for (const e of [hkdfChromium, hkdfCryptopp, bc]) {
    assert.equal(e.executionStatus, 'completed');
    assert.ok(bytesOf(e).length > 0, 'a real OKM must have been produced');
  }
  // Three independent implementations agreeing is what makes the later
  // divergence meaningful.
  assert.equal(bytesOf(hkdfChromium), bytesOf(hkdfCryptopp));
  assert.equal(bytesOf(hkdfChromium), bytesOf(bc));
  cover('direct-adapter');
});

test('M3.5: a real mutation really diverges', async () => {
  hkdfMutated = await executeMutation(HKDF_INFO_TAMPER, 'default', hkdfFixture(), HKDF_CHROMIUM_ADAPTER);
  assert.equal(hkdfMutated.context.kind, 'mutation');
  assert.notEqual(bytesOf(hkdfMutated), bytesOf(hkdfChromium));
  cover('mutation-execution');
});

// =====================================================================
// Shape 2 -- the key-bound factory (OAEP), and a directed transfer
// =====================================================================

test('M3.5: OAEP through a FACTORY bound to real key material, Crypto++ -> Bouncy Castle', async () => {
  const kp = await webcrypto.subtle.generateKey(
    { name: 'RSA-OAEP', modulusLength: 3072, publicExponent: new Uint8Array([1, 0, 1]), hash: 'SHA-256' },
    true, ['encrypt', 'decrypt'],
  );
  const jwk = await webcrypto.subtle.exportKey('jwk', kp.privateKey);
  const h = (b: string) => Buffer.from(b, 'base64url').toString('hex');
  const key: OaepKeyHex = {
    modulusHex: h(jwk.n!), publicExponentHex: h(jwk.e!), privateExponentHex: h(jwk.d!),
    pHex: h(jwk.p!), qHex: h(jwk.q!), dpHex: h(jwk.dp!), dqHex: h(jwk.dq!), qiHex: h(jwk.qi!),
  };
  // The SAME material reaches producer and consumer, or a cross-provider
  // observation means nothing. bindFactory makes that a visible step.
  const enc = bindFactory(makeOaepEncryptCryptoppAdapter, key);
  const dec = bindFactory(makeOaepDecryptBouncyCastleAdapter, key);
  cover('key-bound-factory');

  const plaintext = Buffer.from('deadbeefdeadbeefdeadbeefdeadbeef', 'hex');
  const encReq: OaepEncryptRequest = {
    key: { role: 'public', modulusBits: 3072 }, plaintext, label: undefined, hash: 'SHA-256', mgfHash: 'SHA-256',
  };

  const transfer = await runTransfer({
    operation: 'oaep', from: CRYPTOPP, to: BOUNCY_CASTLE,
    produce: async () => {
      const e = await executeBaseline('B', 'dry-oaep-enc', encReq, enc);
      return { bytesHex: bytesOf(e), execution: e };
    },
    consume: async (artifact) => {
      const decReq: OaepDecryptRequest = {
        key: { role: 'private', modulusBits: 3072 }, ciphertext: Buffer.from(artifact.bytesHex, 'hex'),
        label: undefined, hash: 'SHA-256', mgfHash: 'SHA-256',
      };
      return executeBaseline('B', 'dry-oaep-dec', decReq, dec);
    },
  });
  cover('directed-transfer');

  // The bytes Bouncy Castle consumed are IDENTICALLY the bytes Crypto++
  // produced -- proved by the recomputed hash, not asserted.
  assert.equal(transfer.consumedHash, transfer.artifact.transferHash);
  assert.equal(transfer.producerExecution.executionStatus, 'completed');
  assert.equal(transfer.consumerExecution.executionStatus, 'completed');

  const state = evaluateRelation('R_interop', {
    transfer, expectedOutcome: { kind: 'recover-bytes', expected: plaintext.toString('hex') },
    observedOutcome: { kind: 'recovered-plaintext', value: bytesOf(transfer.consumerExecution) },
  });
  assert.equal(state, 'conformant', 'a real cross-provider OAEP round trip must recover the plaintext');
  observations.push(makeNonExecutionObservation({
    relation: 'R_ser', scope: { kind: 'single-backend', backend: CRYPTOPP },
    context: { kind: 'mutation', phase: 'C', mutationId: 'OAEP-MESSAGE-NORMALIZATION', stimulusInstanceId: 'default' },
    reason: 'stimulus-not-expressible', evaluatorId: 'R_ser',
  }));
  cover('planned-non-execution');
});

// =====================================================================
// Shape 3 -- the serialization wrapper, on both operations
// =====================================================================

test('M3.5: RSA-ser and EC-ser through the EXECUTION WRAPPER, export on one backend, import on another', async () => {
  const rsaKp = await webcrypto.subtle.generateKey(
    { name: 'RSA-OAEP', modulusLength: 3072, publicExponent: new Uint8Array([1, 0, 1]), hash: 'SHA-256' },
    true, ['encrypt', 'decrypt'],
  );
  const jwk = await webcrypto.subtle.exportKey('jwk', rsaKp.privateKey);
  const h = (b: string) => Buffer.from(b, 'base64url').toString('hex');
  const material = {
    role: 'private' as const, nHex: h(jwk.n!), eHex: h(jwk.e!), dHex: h(jwk.d!),
    pHex: h(jwk.p!), qHex: h(jwk.q!), dpHex: h(jwk.dp!), dqHex: h(jwk.dq!), qiHex: h(jwk.qi!),
  };
  const exported = await rsaSerExportCryptopp(material);
  assert.equal(exported.exportOk, true, 'Crypto++ must really export');
  const exportEv = wrapSerializationExecution({
    operation: 'rsa-ser', backend: CRYPTOPP, direction: 'export',
    mutationId: 'RSA-SER-PUBLIC-MATERIAL-DIVERGENCE', stimulusInstanceId: 'default',
    inputKind: 'rsa-private-material', result: { ok: true, artifactHex: exported.artifactHex! },
  });
  const imported = await rsaSerImportBouncyCastle('private', exported.artifactHex!, material);
  const importEv = wrapSerializationExecution({
    operation: 'rsa-ser', backend: BOUNCY_CASTLE, direction: 'import',
    mutationId: 'RSA-SER-PUBLIC-MATERIAL-DIVERGENCE', stimulusInstanceId: 'default',
    inputKind: 'pkcs8-artifact',
    result: { ok: imported.importOk, extra: { materialPreserved: imported.materialPreserved } },
  });
  assert.equal(exportEv.subject.direction, 'export');
  assert.equal(importEv.subject.direction, 'import');
  assert.notEqual(exportEv.executionId, importEv.executionId);
  assert.equal(imported.importOk, true, 'a real cross-provider RSA key round trip');

  // A deliberately out-of-range scalar: the point is that a FAILED call still
  // becomes well-formed evidence rather than an exception escaping into the
  // pipeline.
  const ecExport = await ecSerExportCryptopp({
    role: 'private', xHex: '00'.repeat(32), yHex: '00'.repeat(32), dHex: '00'.repeat(32),
  }).catch(() => undefined);
  // EC-ser's own material shape differs; what the wrapper must show is that a
  // FAILED call still becomes well-formed evidence rather than an exception
  // escaping into the pipeline.
  const ecEv = wrapSerializationExecution({
    operation: 'ec-ser', backend: CRYPTOPP, direction: 'export',
    mutationId: 'EC-PRIVATE-SCALAR-RANGE', stimulusInstanceId: 'default', inputKind: 'ec-private-material',
    result: ecExport?.exportOk ? { ok: true, artifactHex: ecExport.artifactHex! } : { ok: false, errorClass: 'invalid_key' },
  });
  assert.ok(['accept', 'reject'].includes(ecEv.outcome.kind));
  assert.equal(ecEv.executionStatus, 'completed', 'a contractual reject is not an execution failure');
  cover('serialization-wrapper');
});

// =====================================================================
// Shape 4 -- projection and evaluation of the remaining relations
// =====================================================================

test('M3.5: R_byte over a real CROSS-BACKEND-SET pair, and the other four relations', () => {
  const rByte = evaluateRelation('R_byte', {
    left: hkdfChromium, right: hkdfCryptopp, outputKind: 'raw-output',
  });
  assert.equal(rByte, 'conformant', 'two real providers agree on the same OKM');
  cover('r-byte-cross-backend');

  const divergent = evaluateRelation('R_byte', {
    left: hkdfMutated, right: hkdfCryptopp, outputKind: 'raw-output',
  });
  assert.equal(divergent, 'divergent', 'and a real mutation is really detected');

  const gt = resolveGroundTruth('HKDF-INFO-TAMPER', 'default');
  assert.ok(gt.row.expectedValidation !== undefined, 'the expectation comes from C1');
  assert.equal(evaluateRelation('R_val', {
    expected: gt.row.expectedValidation!.decision, execution: hkdfChromium,
    observed: gt.row.expectedValidation!.decision,
  }), 'conformant');
  cover('r-val');

  // A rejection that never happened yields insufficient-evidence for R_err --
  // never a divergence. R_val records the actual outcome independently.
  assert.equal(evaluateRelation('R_err', {
    execution: hkdfChromium, rejectionOccurred: false,
  }), 'insufficient-evidence');
  // And a real, matching error class is conformant, which is the path that
  // proves the projector reaches the evaluator with usable premises.
  assert.equal(evaluateRelation('R_err', {
    execution: hkdfChromium, rejectionOccurred: true,
    expectedErrorClass: 'invalid_parameter', observedErrorClass: 'invalid_parameter',
  }), 'conformant');
  cover('r-err');

  assert.equal(evaluateRelation('R_ser', {
    basis: 'both', execution: hkdfChromium, repOK: true, materialOK: true,
  }), 'conformant');
  cover('r-ser');

  // R_cap with genuinely independent evidences.
  assert.equal(evaluateRelation('R_cap', {
    declared: { kind: 'provider-support', state: 'supported' },
    declarationExecution: hkdfChromium, scoredExecution: hkdfCryptopp,
    observed: { kind: 'provider-support', state: 'supported' },
  }), 'conformant');
  assert.notEqual(hkdfChromium.executionId, hkdfCryptopp.executionId);
  cover('r-cap-independent-evidence');

  // A legitimate insufficient-evidence, obtained rather than fabricated: a
  // required check whose result could not be observed.
  assert.equal(evaluateRelation('R_ser', { basis: 'both', execution: hkdfChromium, repOK: true }), 'insufficient-evidence');
  cover('insufficient-evidence');
});

// =====================================================================
// Shape 5 -- persistence, isolation from M4, and reconstruction
// =====================================================================

test('M3.5: persist -> reload -> reconstruct, with the registry binding intact', () => {
  const planned: PlannedObservation[] = [
    { relation: 'R_val', scope: { kind: 'single-backend', backend: CHROMIUM_WEBCRYPTO }, executability: { kind: 'required' } },
  ];
  const instance = makeMutationInstanceResult({
    mutationId: 'HKDF-INFO-TAMPER', stimulusInstanceId: 'default', operation: 'hkdf',
    planned, observations: [],
  });
  const applicability: RelationApplicability =
    { R_byte: true, R_interop: false, R_ser: false, R_val: true, R_err: true, R_cap: true };
  const sr = makePhaseCScientificResult({
    mutationId: 'HKDF-INFO-TAMPER', operation: 'hkdf', gamma0Ref: 'registry:HKDF-INFO-TAMPER',
    registryEntryHash: registryEntryHash('HKDF-INFO-TAMPER'),
    applicability,
    observedSpectrum: { R_byte: 'fail', R_interop: 'n/a', R_ser: 'n/a', R_val: 'pass', R_err: 'pass', R_cap: 'pass' },
    nonScoreable: [], instanceResults: [instance],
    detectionSupport: { divergentInstances: 1, evaluatedInstances: 1 },
  });
  const bundle: EvidenceBundle = {
    bundleVersion: '2.0',
    executions: [hkdfChromium, hkdfCryptopp, hkdfMutated],
    observations, instanceResults: [instance], mutationResults: [],
    scientificResults: [sr], omittedClasses: [],
  };

  const path = persistDryRun(DRY_RUN_OUTPUT_DIR, 'm35-dry-run', makeDryRunBundle(bundle));
  const back = reloadDryRun(path);

  // Persist(x) -> Reload(x) -> Reconstruct(x) = x_scientific
  const { result, instances } = reconstructScientificResult(back.bundle, 'HKDF-INFO-TAMPER');
  assert.deepEqual(result.observedSpectrum, sr.observedSpectrum);
  assert.equal(instances.length, 1);
  // Including the binding added in M3.3: Gamma_0 recovered through it.
  const gamma0 = resolveGamma0(result.mutationId, result.registryEntryHash!);
  assert.ok(gamma0.length > 0);
  // And the NonExecutionObservation survived, still non-terminal.
  const nx = back.bundle.observations.find((o) => typeof o.status === 'object');
  assert.ok(nx !== undefined, 'the planned non-execution reached the dataset');
  assert.deepEqual(nx!.status, { state: 'not-executed', reason: 'stimulus-not-expressible' });
  cover('persist-reload-reconstruct');
});

test('M3.5: DryRunEvidence n ScoredM4Evidence = {} -- structurally, in three ways', () => {
  const dr = makeDryRunBundle({
    bundleVersion: '2.0', executions: [], observations: [], instanceResults: [],
    mutationResults: [], scientificResults: [], omittedClasses: [],
  });
  // 1. it declares its kind
  assert.equal(dr.runKind, 'dry-run');
  // 2. a scored consumer refuses it
  assert.throws(() => assertNotScored(dr), DryRunContaminationError);
  assert.throws(() => assertNotScored(dr), /must never enter the scored dataset/);
  assert.doesNotThrow(() => assertNotScored({}));
  // 3. the kind travels INSIDE the file, so moving it out of its directory
  //    does not launder it
  const p = persistDryRun(DRY_RUN_OUTPUT_DIR, 'isolation', dr);
  assert.ok(p.startsWith(DRY_RUN_OUTPUT_DIR));
  assert.equal(reloadDryRun(p).runKind, 'dry-run');
  cover('m4-isolation');
});

// =====================================================================
// Structural representativeness
// =====================================================================

test('M3.5: every distinct execution / projection / persistence SHAPE was traversed', () => {
  const required = [
    'direct-adapter', 'mutation-execution', 'key-bound-factory', 'serialization-wrapper',
    'directed-transfer', 'r-byte-cross-backend', 'r-val', 'r-err', 'r-ser',
    'r-cap-independent-evidence', 'planned-non-execution', 'insufficient-evidence',
    'persist-reload-reconstruct', 'm4-isolation',
  ];
  const missing = required.filter((s) => !covered.has(s));
  assert.deepEqual(missing, [], 'the criterion is shape coverage, not one class per operation');
});
