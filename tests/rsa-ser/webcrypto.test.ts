import { test, before } from 'node:test';
import assert from 'node:assert/strict';
import { generateKeyPairSync } from 'node:crypto';
import { rsaSerWebCryptoImport, rsaSerWebCryptoExport } from '../../src/adapters/webcrypto/rsa-ser.js';
import { encodeSpki, encodePrivateKeyInfo, type RsaPublicMaterial, type RsaPrivateMaterial } from '../../src/contract/rsa-ser.js';
import { encodeSequence, encodeInteger, encodeBitStringWholeBytes, encodeRsaEncryptionOid } from '../../src/contract/der.js';

// Traceability: exercises rsa-ser.* clauses against the WebCrypto
// realization, for both import and export directions. RSA-3072 key pair
// generated once via Node's own (OpenSSL-backed) crypto, shared as fixture.

let spkiDer: Uint8Array;
let pkcs8Der: Uint8Array;

before(() => {
  const { publicKey, privateKey } = generateKeyPairSync('rsa', { modulusLength: 3072, publicExponent: 0x10001 });
  spkiDer = new Uint8Array(publicKey.export({ type: 'spki', format: 'der' }));
  pkcs8Der = new Uint8Array(privateKey.export({ type: 'pkcs8', format: 'der' }));
});

test('import: rejects with the full 4-class model; export: accept is the only outcome exercised (unsupported not modeled in M1)', async () => {
  const importResult = await rsaSerWebCryptoImport(spkiDer, 'private'); // role-container mismatch
  assert.equal(importResult.record.outcome.kind, 'reject');
  if (importResult.record.outcome.kind === 'reject') {
    assert.equal(importResult.record.outcome.errorClass, 'invalid_parameter');
  }

  const importedPub = await rsaSerWebCryptoImport(spkiDer, 'public');
  assert.equal(importedPub.record.outcome.kind, 'accept');
  const exportResult = await rsaSerWebCryptoExport(importedPub.material!);
  assert.equal(exportResult.record.outcome.kind, 'accept');
});

// Proof that Accept_C is NOT delegated to subtle.importKey: WebCrypto's own
// import path does NOT check RSA mathematical consistency at all (Design
// Freeze v0.6, sec:rsa-ser-webcrypto, confirmed normatively) -- so a
// mathematically-inconsistent-but-structurally-valid private key would be
// silently ACCEPTED by a naive subtle.importKey-only implementation. Our
// adapter must still reject it.
test('Accept_C independence: a private key with a corrupted CRT relation (WebCrypto itself would accept this natively) is still rejected as invalid_key', async () => {
  const realImport = await rsaSerWebCryptoImport(pkcs8Der, 'private');
  const real = realImport.material as RsaPrivateMaterial;
  const badMaterial: RsaPrivateMaterial = { ...real, dP: real.dP + 2n };
  const badArtifact = encodePrivateKeyInfo(badMaterial);

  const result = await rsaSerWebCryptoImport(badArtifact, 'private');
  assert.equal(result.record.outcome.kind, 'reject');
  if (result.record.outcome.kind === 'reject') {
    assert.equal(result.record.outcome.errorClass, 'invalid_key');
  }
  assert.deepEqual(result.record.clauseIds, ['rsa-ser.private-relations']);
});

test('parameters=NULL and parameters=absent both import successfully and re-export to the byte-identical canonical artifact -- evidence of genuine canonicalization, not blind round-trip', async () => {
  const nullVariant = spkiDer;

  const importedNull = await rsaSerWebCryptoImport(nullVariant, 'public');
  assert.equal(importedNull.record.outcome.kind, 'accept');
  const material = importedNull.material as RsaPublicMaterial;

  const inner = encodeSequence([encodeInteger(material.n), encodeInteger(material.e)]);
  const algIdAbsent = encodeSequence([encodeRsaEncryptionOid()]);
  const absentVariant = encodeSequence([algIdAbsent, encodeBitStringWholeBytes(inner)]);

  const importedAbsent = await rsaSerWebCryptoImport(absentVariant, 'public');
  assert.equal(importedAbsent.record.outcome.kind, 'accept');

  const exportFromNull = await rsaSerWebCryptoExport(importedNull.material!);
  const exportFromAbsent = await rsaSerWebCryptoExport(importedAbsent.material!);

  assert.deepEqual(Buffer.from(exportFromNull.sdkArtifact), Buffer.from(exportFromAbsent.sdkArtifact));
  assert.deepEqual(Buffer.from(exportFromNull.sdkArtifact), Buffer.from(nullVariant));
});

test('public-validity: a syntactically valid (n,e) passes the cheap necessary conditions even though n=p*q cannot be confirmed from (n,e) alone', async () => {
  const artifact = encodeSpki({ role: 'public', n: 15n, e: 3n });
  const result = await rsaSerWebCryptoImport(artifact, 'public');
  assert.equal(result.record.outcome.kind, 'accept');
});

test('private math validity requires the FULL V_domain and V_rel conjunction (asymmetric with public)', async () => {
  const result = await rsaSerWebCryptoImport(pkcs8Der, 'private');
  assert.equal(result.record.outcome.kind, 'accept');
  assert.ok(result.record.clauseIds.includes('rsa-ser.private-domain'));
  assert.ok(result.record.clauseIds.includes('rsa-ser.private-relations'));
});

test('R_ser: import -> export preserves RSA key material exactly (public)', async () => {
  const imported = await rsaSerWebCryptoImport(spkiDer, 'public');
  const exported = await rsaSerWebCryptoExport(imported.material!);
  const reImported = await rsaSerWebCryptoImport(exported.sdkArtifact, 'public');
  const original = imported.material as RsaPublicMaterial;
  const roundTripped = reImported.material as RsaPublicMaterial;
  assert.equal(roundTripped.n, original.n);
  assert.equal(roundTripped.e, original.e);
});

test('R_ser: import -> export preserves RSA key material exactly (private)', async () => {
  const imported = await rsaSerWebCryptoImport(pkcs8Der, 'private');
  const exported = await rsaSerWebCryptoExport(imported.material!);
  const reImported = await rsaSerWebCryptoImport(exported.sdkArtifact, 'private');
  const original = imported.material as RsaPrivateMaterial;
  const roundTripped = reImported.material as RsaPrivateMaterial;
  assert.equal(roundTripped.n, original.n);
  assert.equal(roundTripped.d, original.d);
  assert.equal(roundTripped.p, original.p);
  assert.equal(roundTripped.q, original.q);
});

test('R_byte (WebCrypto/Node specifically, NOT yet a general applicability claim): SDK canonical SPKI export is byte-identical to WebCrypto native SPKI export, for the same material', async () => {
  const imported = await rsaSerWebCryptoImport(spkiDer, 'public');
  const exported = await rsaSerWebCryptoExport(imported.material!);
  assert.deepEqual(Buffer.from(exported.sdkArtifact), Buffer.from(exported.webCryptoArtifact));
  // Byte-identity WITH WEBCRYPTO ONLY -- NOT a claim that R_byte applies to
  // RSA-ser in general. That requires the same comparison to also hold for
  // Crypto++ and Bouncy Castle, not yet built.
});

test('R_byte (WebCrypto/Node specifically): SDK canonical PKCS8 export is byte-identical to WebCrypto native PKCS8 export, for the same material', async () => {
  const imported = await rsaSerWebCryptoImport(pkcs8Der, 'private');
  const exported = await rsaSerWebCryptoExport(imported.material!);
  assert.deepEqual(Buffer.from(exported.sdkArtifact), Buffer.from(exported.webCryptoArtifact));
});

test('SPKI/PKCS8 direct comparison against the original Node-generated fixture bytes', async () => {
  const importedPub = await rsaSerWebCryptoImport(spkiDer, 'public');
  const exportedPub = await rsaSerWebCryptoExport(importedPub.material!);
  assert.deepEqual(Buffer.from(exportedPub.sdkArtifact), Buffer.from(spkiDer));

  const importedPriv = await rsaSerWebCryptoImport(pkcs8Der, 'private');
  const exportedPriv = await rsaSerWebCryptoExport(importedPriv.material!);
  assert.deepEqual(Buffer.from(exportedPriv.sdkArtifact), Buffer.from(pkcs8Der));
});

test('rsa-ser.exact-consumption: trailing byte rejected through the actual adapter call path, before WebCrypto is ever invoked', async () => {
  const withTrailer = new Uint8Array(spkiDer.length + 1);
  withTrailer.set(spkiDer, 0);
  withTrailer[spkiDer.length] = 0xaa;
  const result = await rsaSerWebCryptoImport(withTrailer, 'public');
  assert.equal(result.record.outcome.kind, 'reject');
  if (result.record.outcome.kind === 'reject') {
    assert.equal(result.record.outcome.errorClass, 'malformed_artifact');
  }
  assert.equal(result.nativeCryptoKey, undefined); // confirms WebCrypto's import path was never reached
});
