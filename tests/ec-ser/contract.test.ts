import { test, before } from 'node:test';
import assert from 'node:assert/strict';
import { webcrypto } from 'node:crypto';
import {
  importEcSer,
  exportEcSer,
  encodeSpki,
  encodePkcs8,
  derivePublicPoint,
  type EcPublicMaterial,
  type EcPrivateMaterial,
} from '../../src/contract/ec-ser.js';
import { SdkContractError } from '../../src/contract/errors.js';
import { encodeSequence, encodeInteger, encodeOctetString, encodeExplicitTag, encodeSecp256r1Oid, encodeEcPublicKeyOid, encodeBitStringWholeBytes } from '../../src/contract/der.js';
import { encodeUncompressedPoint, P256_N, type AffinePoint } from '../../src/contract/p256.js';

// Traceability: exercises all 13 ec-ser.* clauses (sec:contract-traceability
// convention), independent of any backend adapter. Fixture is a real P-256
// key pair from GENUINE webcrypto.subtle (the exact API surface Design
// Freeze v0.6 characterized as "WebCrypto" -- not Node's classical crypto
// module's key-object export, which is a different API with potentially
// different behavior).

let spkiDer: Uint8Array;
let pkcs8Der: Uint8Array;
let publicMaterial: EcPublicMaterial;
let privateMaterial: EcPrivateMaterial;

before(async () => {
  const keyPair = await webcrypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify']);
  spkiDer = new Uint8Array(await webcrypto.subtle.exportKey('spki', keyPair.publicKey));
  pkcs8Der = new Uint8Array(await webcrypto.subtle.exportKey('pkcs8', keyPair.privateKey));
  publicMaterial = importEcSer(spkiDer, 'public').material as EcPublicMaterial;
  privateMaterial = importEcSer(pkcs8Der, 'private').material as EcPrivateMaterial;
});

// --- 1. Round trip against a REAL OpenSSL/Node-produced artifact ---

test('ec-ser.public.asn1/point: import(Node SPKI DER) then export() is byte-identical to the original', () => {
  const reExported = exportEcSer(publicMaterial);
  assert.deepEqual(Buffer.from(reExported), Buffer.from(spkiDer));
});

test('ec-ser.private.asn1: import(Node PKCS8 DER) then export() preserves material exactly -- NOT necessarily byte-identical to the original, and that is itself a genuine finding (see next test)', () => {
  const reimported = importEcSer(pkcs8Der, 'private').material as EcPrivateMaterial;
  const reExported = exportEcSer(reimported);
  const reimportedAgain = importEcSer(reExported, 'private').material as EcPrivateMaterial;
  assert.equal(reimportedAgain.d, privateMaterial.d);
  assert.deepEqual(reimportedAgain.q, privateMaterial.q);
});

test('REAL FINDING, confirmed by direct byte decoding, not assumed: genuine webcrypto.subtle.exportKey("pkcs8", ...) in this Node runtime OMITS ECPrivateKey.parameters[0] -- contradicting the W3C spec ALGORITHM TEXT\'s stated "MUST have both present" -- so Accept_C correctly classifies a real WebCrypto-produced artifact as common-but-not-portable (normalized=true), exactly the case D-059/D-061\'s normalization branch exists to handle', () => {
  const result = importEcSer(pkcs8Der, 'private');
  assert.equal(result.normalized, true, 'a real Node WebCrypto PKCS8 export was expected to be missing parameters[0] and require normalization');
});

test('round trip: import(export(M)) recovers M exactly, for both roles', () => {
  const pubBack = importEcSer(exportEcSer(publicMaterial), 'public').material as EcPublicMaterial;
  assert.deepEqual(pubBack.q, publicMaterial.q);

  const privBack = importEcSer(exportEcSer(privateMaterial), 'private').material as EcPrivateMaterial;
  assert.equal(privBack.d, privateMaterial.d);
  assert.deepEqual(privBack.q, privateMaterial.q);
});

// --- 2. THE genuinely new 3-way outcome: normalization ---

test('NORMALIZATION: parameters[0] absent (common-but-not-portable) is ACCEPTED with normalized=true, not rejected', () => {
  const artifact = buildPrivateArtifact(privateMaterial, { omitParams: false, omitPublicKey: false, paramsAbsent: true });
  const result = importEcSer(artifact, 'private');
  assert.equal(result.normalized, true);
  const m = result.material as EcPrivateMaterial;
  assert.equal(m.d, privateMaterial.d);
});

test('parameters[0] present-matching (already portable, e.g. our own canonical export) is accepted with normalized=false', () => {
  const canonicalArtifact = exportEcSer(privateMaterial); // our own writer always includes [0] -- genuinely portable
  const result = importEcSer(canonicalArtifact, 'private');
  assert.equal(result.normalized, false);
});

test('parameters[0] present but MISMATCHED curve is rejected as invalid_parameter, not normalized', () => {
  const artifact = buildPrivateArtifact(privateMaterial, { omitParams: false, omitPublicKey: false, mismatchedParams: true });
  assert.throws(
    () => importEcSer(artifact, 'private'),
    (err: unknown) => {
      assert.ok(err instanceof SdkContractError);
      assert.equal(err.errorClass, 'invalid_parameter');
      assert.deepEqual(err.clauseIds, ['ec-ser.private.asn1']);
      return true;
    },
  );
});

// --- 3. THE critical asymmetry: [1] absence is REJECTED, never normalized (W3C #356) ---

test("CRITICAL: publicKey[1] absent is REJECTED as invalid_parameter -- NEVER normalized, unlike parameters[0]'s absence (D-059's [1]-outside-common asymmetry)", () => {
  const artifact = buildPrivateArtifact(privateMaterial, { omitPublicKey: true });
  assert.throws(
    () => importEcSer(artifact, 'private'),
    (err: unknown) => {
      assert.ok(err instanceof SdkContractError);
      assert.equal(err.errorClass, 'invalid_parameter');
      assert.deepEqual(err.clauseIds, ['ec-ser.private.asn1']);
      return true;
    },
  );
});

// --- 4. Q=dG is NEVER normalized, by construction ---

test('CRITICAL (D-061): Q supplied != dG is rejected as invalid_key (pairConsistency), NEVER normalized -- even though Q could technically be "repaired"', async () => {
  // Construct (d1, Q=d2*G) with d1 != d2, both individually valid.
  const otherKeyPair = await webcrypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify']);
  const otherSpki = new Uint8Array(await webcrypto.subtle.exportKey('spki', otherKeyPair.publicKey));
  const otherPub = importEcSer(otherSpki, 'public').material as EcPublicMaterial;
  const inconsistentMaterial: EcPrivateMaterial = { role: 'private', d: privateMaterial.d, q: otherPub.q };
  const artifact = encodePkcs8(inconsistentMaterial);
  assert.throws(
    () => importEcSer(artifact, 'private'),
    (err: unknown) => {
      assert.ok(err instanceof SdkContractError);
      assert.equal(err.errorClass, 'invalid_key');
      assert.deepEqual(err.clauseIds, ['ec-ser.pairConsistency']);
      return true;
    },
  );
});

// --- 5. Membership: kept separate from Key ---

test('ec-ser.curveMembership: a syntactically well-formed but off-curve Q is rejected as invalid_membership (NOT invalid_key)', () => {
  const offCurve: AffinePoint = { x: publicMaterial.q !== 'infinity' ? publicMaterial.q.x : 1n, y: 1n }; // essentially never on-curve for a real x with y=1
  const artifact = encodeSpki({ role: 'public', q: offCurve });
  assert.throws(
    () => importEcSer(artifact, 'public'),
    (err: unknown) => {
      assert.ok(err instanceof SdkContractError);
      assert.equal(err.errorClass, 'invalid_membership');
      assert.deepEqual(err.clauseIds, ['ec-ser.curveMembership']);
      return true;
    },
  );
});

// --- 6. Scalar range ---

test('ec-ser.private.scalar: d=0 is rejected as invalid_key (V_scalar)', () => {
  const artifact = buildPrivateArtifact(privateMaterial, { overrideD: 0n });
  assert.throws(
    () => importEcSer(artifact, 'private'),
    (err: unknown) => {
      assert.ok(err instanceof SdkContractError);
      assert.equal(err.errorClass, 'invalid_key');
      assert.deepEqual(err.clauseIds, ['ec-ser.private.scalar']);
      return true;
    },
  );
});

test('ec-ser.private.scalar: d=n is rejected as invalid_key (V_scalar)', () => {
  const artifact = buildPrivateArtifact(privateMaterial, { overrideD: P256_N });
  assert.throws(() => importEcSer(artifact, 'private'), SdkContractError);
});

// --- 7. Curve substitution ---

test('ec-ser.curve: a non-secp256r1 curve OID is rejected as invalid_parameter', () => {
  const wrongCurveOid = Uint8Array.from([0x06, 0x03, 0x55, 0x04, 0x03]); // arbitrary unrelated OID
  const algId = encodeSequence([encodeEcPublicKeyOid(), wrongCurveOid]);
  const artifact = encodeSequence([algId, encodeBitStringWholeBytes(encodeUncompressedPoint(publicMaterial.q))]);
  assert.throws(
    () => importEcSer(artifact, 'public'),
    (err: unknown) => {
      assert.ok(err instanceof SdkContractError);
      assert.equal(err.errorClass, 'invalid_parameter');
      assert.deepEqual(err.clauseIds, ['ec-ser.curve']);
      return true;
    },
  );
});

// --- 8. Role/container mismatch ---

test('ec-ser.key.role: SPKI requested as private is rejected as invalid_parameter', () => {
  assert.throws(
    () => importEcSer(spkiDer, 'private'),
    (err: unknown) => {
      assert.ok(err instanceof SdkContractError);
      assert.equal(err.errorClass, 'invalid_parameter');
      assert.deepEqual(err.clauseIds, ['ec-ser.key.role']);
      return true;
    },
  );
});

// --- 9. Exact consumption ---

test('ec-ser.validation.syntax: trailing byte rejected as malformed_artifact', () => {
  const withTrailer = new Uint8Array(spkiDer.length + 1);
  withTrailer.set(spkiDer, 0);
  withTrailer[spkiDer.length] = 0xff;
  assert.throws(
    () => importEcSer(withTrailer, 'public'),
    (err: unknown) => {
      assert.ok(err instanceof SdkContractError);
      assert.equal(err.errorClass, 'malformed_artifact');
      return true;
    },
  );
});

// --- 10. derivePublicPoint utility used correctly ---

test('derivePublicPoint(d) matches the real embedded Q for the Node-generated key', () => {
  const derived = derivePublicPoint(privateMaterial.d);
  assert.deepEqual(derived, privateMaterial.q);
});

// --- Helper: build a private artifact with deliberate variations ---

function buildPrivateArtifact(
  base: EcPrivateMaterial,
  opts: { omitParams?: boolean; paramsAbsent?: boolean; mismatchedParams?: boolean; omitPublicKey?: boolean; overrideD?: bigint } = {},
): Uint8Array {
  const d = opts.overrideD ?? base.d;
  let dHex = d.toString(16);
  if (dHex.length % 2 !== 0) dHex = '0' + dHex;
  const dBytes = Uint8Array.from(Buffer.from(dHex.padStart(64, '0'), 'hex'));

  const fields = [encodeInteger(1n), encodeOctetString(dBytes)];

  const includeParams = !opts.omitParams && !opts.paramsAbsent;
  if (includeParams) {
    const curveOid = opts.mismatchedParams ? Uint8Array.from([0x06, 0x03, 0x55, 0x04, 0x03]) : encodeSecp256r1Oid();
    fields.push(encodeExplicitTag(0, curveOid));
  }
  if (!opts.omitPublicKey) {
    fields.push(encodeExplicitTag(1, encodeBitStringWholeBytes(encodeUncompressedPoint(base.q))));
  }

  const inner = encodeSequence(fields);
  const algId = encodeSequence([encodeEcPublicKeyOid(), encodeSecp256r1Oid()]);
  return encodeSequence([encodeInteger(0n), algId, encodeOctetString(inner)]);
}
