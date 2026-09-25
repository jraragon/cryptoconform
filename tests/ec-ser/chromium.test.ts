import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { ecSerContractImport, ecSerContractExport } from '../../src/adapters/chromium/ec-ser.js';
import { encodePkcs8, exportEcSer, type EcPrivateMaterial, type EcPublicMaterial } from '../../src/contract/ec-ser.js';
import { encodeSequence, encodeInteger, encodeOctetString, encodeExplicitTag, encodeSecp256r1Oid, encodeEcPublicKeyOid, encodeBitStringWholeBytes } from '../../src/contract/der.js';
import { encodeUncompressedPoint, P256_N } from '../../src/contract/p256.js';

// @ts-expect-error -- plain .mjs harness, deliberately outside the TS build (see the harness file's own header comment for why)
import { ChromiumEcHarness } from '../../scripts/chromium-ec-ser-harness.mjs';

// Traceability: exercises ec-ser.* clauses against the CHROMIUM realization
// specifically (pinned build confirmed below), not node:crypto's webcrypto.
// Every test in this file is explicitly one of two kinds, never blended:
//   - CONTRACT PATH: ecSerContractImport() -- our own Accept_C, Chromium
//     untouched for rejections.
//   - NATIVE PROBE: harness.nativeImport()/nativeImportThenExport() --
//     Chromium's own subtle.importKey/exportKey directly, no Accept_C.
// Discrepancies between the two are RECORDED AS EVIDENCE, not failures,
// whenever the contract's rejection is deliberate (per D-059's [1]-absence
// exclusion from D_common).

let harness: InstanceType<typeof ChromiumEcHarness>;
let realizationId: string;
let fixture: { dHex: string; xHex: string; yHex: string; nativeSpkiHex: string; nativePkcs8Hex: string };
let fixture2: { dHex: string; xHex: string; yHex: string; nativeSpkiHex: string; nativePkcs8Hex: string };

before(async () => {
  harness = new ChromiumEcHarness();
  await harness.start();
  const version = await harness.version();
  realizationId = `chromium:${version} (Playwright-pinned build; see sec:environment)`;
  fixture = await harness.generateKeyPair();
  fixture2 = await harness.generateKeyPair();
});

after(async () => {
  await harness.stop();
});

function hexToBig(h: string): bigint {
  return BigInt('0x' + h);
}

// --- 0. Pinned realization confirmed ---

test('Chromium realization is the exact pinned build (151.0.7922.34), not node:crypto', async () => {
  const version = await harness.version();
  assert.equal(version, '151.0.7922.34');
});

// --- 1. C_portable -> Accept, both roles (contract path) ---

test('CONTRACT PATH: a genuinely portable canonical artifact (our own export) is accepted', () => {
  const d = hexToBig(fixture.dHex);
  const q = { x: hexToBig(fixture.xHex), y: hexToBig(fixture.yHex) };
  const material: EcPrivateMaterial = { role: 'private', d, q };
  const canonical = exportEcSer(material);
  const result = ecSerContractImport(canonical, 'private', realizationId);
  assert.equal(result.outcome.kind, 'accept');
  if (result.outcome.kind === 'accept') assert.equal(result.outcome.normalized, false);
});

// --- 2. [0] absent -> Accept(N(A)) on contract path; native Chromium ALSO accepts (both recorded, kept separate) ---

test('[0] ABSENT: contract path accepts with normalized=true; NATIVE Chromium (real export) also accepts -- both recorded, deliberately kept separate', async () => {
  // Chromium's OWN genuine native PKCS8 export already lacks [0] (confirmed this session) -- use it directly as the [0]-absent stimulus.
  const contractResult = ecSerContractImport(hexToUint8(fixture.nativePkcs8Hex), 'private', realizationId);
  assert.equal(contractResult.outcome.kind, 'accept');
  if (contractResult.outcome.kind === 'accept') assert.equal(contractResult.outcome.normalized, true);

  const nativeResult = await harness.nativeImport({ format: 'pkcs8', hex: fixture.nativePkcs8Hex }, 'private');
  assert.equal(nativeResult.accepted, true);
});

// --- 3. [1] absent -> Reject on contract path (E_representation), even though Chromium native ACCEPTS -- the central Accept_C != NativeAccept_p demonstration ---

test('[1] ABSENT: contract path REJECTS (invalid_parameter, ec-ser.private.asn1) even though NATIVE Chromium ACCEPTS it (auto-derives Q) -- Accept_C != NativeAccept_p by design, confirmed on both paths in one test', async () => {
  const artifactNoPub = buildPrivateArtifact(hexToBig(fixture.dHex), null);

  const contractResult = ecSerContractImport(artifactNoPub, 'private', realizationId);
  assert.equal(contractResult.outcome.kind, 'reject');
  if (contractResult.outcome.kind === 'reject') {
    assert.equal(contractResult.outcome.errorClass, 'invalid_parameter');
    assert.deepEqual(contractResult.clauseIds, ['ec-ser.private.asn1']);
  }

  const nativeResult = await harness.nativeImport({ format: 'pkcs8', hex: Buffer.from(artifactNoPub).toString('hex') }, 'private');
  assert.equal(nativeResult.accepted, true, 'expected Chromium to natively accept [1]-absent (confirmed post-freeze deviation)');
});

// --- 4. d=0, d>=n -> Reject(E_key) ---

test('d=0 is rejected as invalid_key (V_scalar), contract path', () => {
  const q = { x: hexToBig(fixture.xHex), y: hexToBig(fixture.yHex) };
  const artifact = buildPrivateArtifact(0n, q);
  const result = ecSerContractImport(artifact, 'private', realizationId);
  assert.equal(result.outcome.kind, 'reject');
  if (result.outcome.kind === 'reject') {
    assert.equal(result.outcome.errorClass, 'invalid_key');
    assert.deepEqual(result.clauseIds, ['ec-ser.private.scalar']);
  }
});

test('d>=n is rejected as invalid_key (V_scalar), contract path', () => {
  const q = { x: hexToBig(fixture.xHex), y: hexToBig(fixture.yHex) };
  const artifact = buildPrivateArtifact(P256_N, q);
  const result = ecSerContractImport(artifact, 'private', realizationId);
  assert.equal(result.outcome.kind, 'reject');
  if (result.outcome.kind === 'reject') assert.equal(result.outcome.errorClass, 'invalid_key');
});

// --- 5. Q not on curve -> Reject(E_membership) ---

test('Q not on the curve is rejected as invalid_membership (V_curve), contract path -- NOT invalid_key', () => {
  const d = hexToBig(fixture.dHex);
  const offCurve = { x: hexToBig(fixture.xHex), y: 12345n }; // essentially never on-curve for a real x with an arbitrary small y
  const artifact = buildPrivateArtifact(d, offCurve);
  const result = ecSerContractImport(artifact, 'private', realizationId);
  assert.equal(result.outcome.kind, 'reject');
  if (result.outcome.kind === 'reject') {
    assert.equal(result.outcome.errorClass, 'invalid_membership');
    assert.deepEqual(result.clauseIds, ['ec-ser.curveMembership']);
  }
});

// --- 6. Q on curve but Q != dG -> Reject(E_key), via the CANONICAL ISOLATING STIMULUS (two independent valid pairs, never arbitrary corruption) ---

test('ISOLATING STIMULUS (d1, Q2=d2*G), d1!=d2, both individually valid: Q supplied != dG is rejected as invalid_key (pairConsistency), contract path -- never invalid_membership, since Q2 IS genuinely on-curve', () => {
  const d1 = hexToBig(fixture.dHex);
  const q2 = { x: hexToBig(fixture2.xHex), y: hexToBig(fixture2.yHex) }; // genuinely on-curve (fixture2's own real public point)
  const artifact = buildPrivateArtifact(d1, q2);
  const result = ecSerContractImport(artifact, 'private', realizationId);
  assert.equal(result.outcome.kind, 'reject');
  if (result.outcome.kind === 'reject') {
    assert.equal(result.outcome.errorClass, 'invalid_key');
    assert.deepEqual(result.clauseIds, ['ec-ser.pairConsistency']);
  }
});

// --- 7. NATIVE PROBE: the same isolating stimulus against Chromium directly (the post-freeze deviation finding, formalized as a permanent regression test) ---

test('NATIVE PROBE, post-freeze deviation (Experimental Evidence Base sec:9-deviations): Chromium 151.0.7922.34 REJECTS the same isolating stimulus (d1,Q2) with DataError -- V_pair empirically enforced for this pinned realization, sanity-checked against the matched genuine (d2,Q2) control', async () => {
  const d1Hex = fixture.dHex.padStart(64, '0');
  const d2Hex = fixture2.dHex.padStart(64, '0');

  // Sanity/positive control: (d2, Q2), the GENUINE matching pair, encoded through the identical hand-built DER path -- must be accepted, or the artifact construction itself is suspect, not Chromium's math.
  const genuineArtifact = buildPrivateArtifactHexParts(d2Hex, fixture2.xHex, fixture2.yHex);
  const controlResult = await harness.nativeImport({ format: 'pkcs8', hex: genuineArtifact }, 'private');
  assert.equal(controlResult.accepted, true, 'sanity control (d2,Q2) must be accepted -- confirms the hand-built DER path itself is valid');

  // The isolating stimulus itself: (d1, Q2), d1 != d2, Q2 genuinely on-curve.
  const mismatchArtifact = buildPrivateArtifactHexParts(d1Hex, fixture2.xHex, fixture2.yHex);
  const stimulusResult = await harness.nativeImport({ format: 'pkcs8', hex: mismatchArtifact }, 'private');
  assert.equal(stimulusResult.accepted, false, 'expected Chromium to natively reject (d1,Q2) with d1!=d2 -- V_pair empirically enforced');
  assert.equal(stimulusResult.errorName, 'DataError');
});

// --- 8. R_ser evidence: NativeExport_Chromium(K)=A -> Accept_C(A)=Accept(N(A)) -> Export_C(N(A))=A_canonical ---

test('R_ser: Chromium native export (lacking [0]) -> Accept_C normalizes -> our canonical export matches OUR OWN direct canonical export of the same material (serialization equivalence, not native-artifact identity)', () => {
  const d = hexToBig(fixture.dHex);
  const q = { x: hexToBig(fixture.xHex), y: hexToBig(fixture.yHex) };
  const directCanonical = exportEcSer({ role: 'private', d, q });

  const contractResult = ecSerContractImport(hexToUint8(fixture.nativePkcs8Hex), 'private', realizationId);
  assert.equal(contractResult.outcome.kind, 'accept');
  if (contractResult.outcome.kind !== 'accept' || !contractResult.material) throw new Error('unreachable');
  const exportRecord = ecSerContractExport(contractResult.material, realizationId);
  const normalizedCanonical = hexToUint8(exportRecord.outcome.artifactHex);

  assert.deepEqual(Buffer.from(normalizedCanonical), Buffer.from(directCanonical));
});

// --- Helpers ---

function hexToUint8(hex: string): Uint8Array {
  return Uint8Array.from(Buffer.from(hex, 'hex'));
}

function buildPrivateArtifact(d: bigint, q: { x: bigint; y: bigint } | null): Uint8Array {
  let dHex = d.toString(16);
  if (dHex.length % 2 !== 0) dHex = '0' + dHex;
  const dBytes = Uint8Array.from(Buffer.from(dHex.padStart(64, '0'), 'hex'));
  const fields = [encodeInteger(1n), encodeOctetString(dBytes)];
  if (q !== null) {
    fields.push(encodeExplicitTag(1, encodeBitStringWholeBytes(encodeUncompressedPoint(q))));
  }
  const inner = encodeSequence(fields);
  const algId = encodeSequence([encodeEcPublicKeyOid(), encodeSecp256r1Oid()]);
  return encodeSequence([encodeInteger(0n), algId, encodeOctetString(inner)]);
}

function buildPrivateArtifactHexParts(dHex: string, xHex: string, yHex: string): string {
  const d = hexToBig(dHex);
  const q = { x: hexToBig(xHex), y: hexToBig(yHex) };
  return Buffer.from(buildPrivateArtifact(d, q)).toString('hex');
}
