import { test, before } from 'node:test';
import assert from 'node:assert/strict';
import { generateKeyPairSync } from 'node:crypto';
import {
  importRsaSer,
  exportRsaSer,
  encodeSpki,
  encodePrivateKeyInfo,
  type RsaPublicMaterial,
  type RsaPrivateMaterial,
} from '../../src/contract/rsa-ser.js';
import { SdkContractError } from '../../src/contract/errors.js';
import { encodeSequence, encodeInteger, encodeBitStringWholeBytes, encodeOctetString, encodeNull, encodeRsaEncryptionOid } from '../../src/contract/der.js';

// Traceability: exercises all 13 rsa-ser.* clauses (sec:contract-traceability
// convention), independent of any backend adapter. RSA-3072 key pair
// generated once via Node's built-in (OpenSSL-backed) crypto module, used
// both as a real-world DER fixture AND to empirically settle Design Freeze
// v0.6's own explicitly-undecided question: "if all three backends' DER
// export of the same key is byte-identical, R_byte could apply to
// serialization for the first time in this design."

let spkiDer: Uint8Array;
let pkcs8Der: Uint8Array;
let publicMaterial: RsaPublicMaterial;
let privateMaterial: RsaPrivateMaterial;

before(() => {
  const { publicKey, privateKey } = generateKeyPairSync('rsa', { modulusLength: 3072, publicExponent: 0x10001 });
  spkiDer = new Uint8Array(publicKey.export({ type: 'spki', format: 'der' }));
  pkcs8Der = new Uint8Array(privateKey.export({ type: 'pkcs8', format: 'der' }));
  publicMaterial = importRsaSer(spkiDer, 'public') as RsaPublicMaterial;
  privateMaterial = importRsaSer(pkcs8Der, 'private') as RsaPrivateMaterial;
});

test('rsa-ser.public-material: import(Node SPKI DER) then export() is byte-identical to the original -- empirical R_byte-for-serialization evidence', () => {
  const reExported = exportRsaSer(publicMaterial);
  assert.deepEqual(Buffer.from(reExported), Buffer.from(spkiDer));
});

test('rsa-ser.private-material: import(Node PKCS8 DER) then export() is byte-identical to the original', () => {
  const reExported = exportRsaSer(privateMaterial);
  assert.deepEqual(Buffer.from(reExported), Buffer.from(pkcs8Der));
});

test('round trip: import(export(M)) recovers M exactly, for both roles', () => {
  const pubBytes = exportRsaSer(publicMaterial);
  const pubBack = importRsaSer(pubBytes, 'public') as RsaPublicMaterial;
  assert.equal(pubBack.n, publicMaterial.n);
  assert.equal(pubBack.e, publicMaterial.e);

  const privBytes = exportRsaSer(privateMaterial);
  const privBack = importRsaSer(privBytes, 'private') as RsaPrivateMaterial;
  assert.equal(privBack.n, privateMaterial.n);
  assert.equal(privBack.d, privateMaterial.d);
  assert.equal(privBack.p, privateMaterial.p);
  assert.equal(privBack.q, privateMaterial.q);
});

test('rsa-ser.exact-consumption: a trailing byte after otherwise-valid DER is rejected as malformed_artifact', () => {
  const withTrailer = new Uint8Array(spkiDer.length + 1);
  withTrailer.set(spkiDer, 0);
  withTrailer[spkiDer.length] = 0xff;
  assert.throws(
    () => importRsaSer(withTrailer, 'public'),
    (err: unknown) => {
      assert.ok(err instanceof SdkContractError);
      assert.equal(err.errorClass, 'malformed_artifact');
      assert.deepEqual(err.clauseIds, ['rsa-ser.exact-consumption']);
      return true;
    },
  );
});

test('rsa-ser.der-syntax: non-DER garbage bytes are rejected as malformed_artifact', () => {
  const garbage = new Uint8Array([0xff, 0x00, 0x01, 0x02]);
  assert.throws(
    () => importRsaSer(garbage, 'public'),
    (err: unknown) => {
      assert.ok(err instanceof SdkContractError);
      assert.equal(err.errorClass, 'malformed_artifact');
      assert.deepEqual(err.clauseIds, ['rsa-ser.der-syntax']);
      return true;
    },
  );
});

test('rsa-ser.container: a valid DER SEQUENCE of unrelated content is rejected as malformed_artifact', () => {
  const notAContainer = encodeSequence([encodeInteger(1n), encodeInteger(2n), encodeInteger(3n), encodeInteger(4n)]);
  assert.throws(
    () => importRsaSer(notAContainer, 'public'),
    (err: unknown) => {
      assert.ok(err instanceof SdkContractError);
      assert.equal(err.errorClass, 'malformed_artifact');
      assert.deepEqual(err.clauseIds, ['rsa-ser.container']);
      return true;
    },
  );
});

test('rsa-ser.role-container: a well-formed PrivateKeyInfo requested with role=public is rejected as invalid_parameter (not malformed ASN.1)', () => {
  assert.throws(
    () => importRsaSer(pkcs8Der, 'public'),
    (err: unknown) => {
      assert.ok(err instanceof SdkContractError);
      assert.equal(err.errorClass, 'invalid_parameter');
      assert.deepEqual(err.clauseIds, ['rsa-ser.role-container']);
      return true;
    },
  );
});

test('rsa-ser.role-container: a well-formed SPKI requested with role=private is rejected as invalid_parameter', () => {
  assert.throws(
    () => importRsaSer(spkiDer, 'private'),
    (err: unknown) => {
      assert.ok(err instanceof SdkContractError);
      assert.equal(err.errorClass, 'invalid_parameter');
      assert.deepEqual(err.clauseIds, ['rsa-ser.role-container']);
      return true;
    },
  );
});

test('rsa-ser.algorithm-id: an AlgorithmIdentifier with a non-rsaEncryption OID is rejected as invalid_parameter', () => {
  const wrongOid = encodeSequence([Uint8Array.from([0x06, 0x03, 0x55, 0x04, 0x03]), encodeNull()]);
  const inner = encodeSequence([encodeInteger(publicMaterial.n), encodeInteger(publicMaterial.e)]);
  const artifact = encodeSequence([wrongOid, encodeBitStringWholeBytes(inner)]);
  assert.throws(
    () => importRsaSer(artifact, 'public'),
    (err: unknown) => {
      assert.ok(err instanceof SdkContractError);
      assert.equal(err.errorClass, 'invalid_parameter');
      assert.deepEqual(err.clauseIds, ['rsa-ser.algorithm-id']);
      return true;
    },
  );
});

test('rsa-ser.algorithm-params: AlgorithmIdentifier.parameters present but not NULL (e.g. an INTEGER) is rejected as invalid_parameter', () => {
  const badAlgId = encodeSequence([encodeRsaEncryptionOid(), encodeInteger(5n)]);
  const inner = encodeSequence([encodeInteger(publicMaterial.n), encodeInteger(publicMaterial.e)]);
  const artifact = encodeSequence([badAlgId, encodeBitStringWholeBytes(inner)]);
  assert.throws(
    () => importRsaSer(artifact, 'public'),
    (err: unknown) => {
      assert.ok(err instanceof SdkContractError);
      assert.equal(err.errorClass, 'invalid_parameter');
      assert.deepEqual(err.clauseIds, ['rsa-ser.algorithm-params']);
      return true;
    },
  );
});

test('rsa-ser.algorithm-params: absent parameters (1-child AlgorithmIdentifier) is accepted, same as explicit NULL', () => {
  const algIdAbsentParams = encodeSequence([encodeRsaEncryptionOid()]);
  const inner = encodeSequence([encodeInteger(publicMaterial.n), encodeInteger(publicMaterial.e)]);
  const artifact = encodeSequence([algIdAbsentParams, encodeBitStringWholeBytes(inner)]);
  assert.doesNotThrow(() => importRsaSer(artifact, 'public'));
});

function buildPublicArtifact(n: bigint, e: bigint): Uint8Array {
  return encodeSpki({ role: 'public', n, e });
}

test('rsa-ser.public-validity: even n is rejected as invalid_key', () => {
  assert.throws(
    () => importRsaSer(buildPublicArtifact(16n, 3n), 'public'),
    (err: unknown) => {
      assert.ok(err instanceof SdkContractError);
      assert.equal(err.errorClass, 'invalid_key');
      assert.deepEqual(err.clauseIds, ['rsa-ser.public-validity']);
      return true;
    },
  );
});

test('rsa-ser.public-validity: even e is rejected as invalid_key', () => {
  assert.throws(
    () => importRsaSer(buildPublicArtifact(15n, 4n), 'public'),
    (err: unknown) => {
      assert.ok(err instanceof SdkContractError);
      assert.equal(err.errorClass, 'invalid_key');
      return true;
    },
  );
});

test('rsa-ser.public-validity: n<15 is rejected as invalid_key', () => {
  assert.throws(() => importRsaSer(buildPublicArtifact(9n, 3n), 'public'), SdkContractError);
});

test('rsa-ser.public-validity: e out of [3,n-1] range is rejected as invalid_key', () => {
  assert.throws(() => importRsaSer(buildPublicArtifact(15n, 15n), 'public'), SdkContractError);
});

function buildPrivateArtifact(overrides: Partial<Omit<RsaPrivateMaterial, 'role'>>): Uint8Array {
  const base: RsaPrivateMaterial = { ...privateMaterial, ...overrides };
  return encodePrivateKeyInfo(base);
}

test('rsa-ser.private-relations: n != p*q is rejected as invalid_key (exact RFC 8017 relational check, not shorthand)', () => {
  const artifact = buildPrivateArtifact({ n: privateMaterial.n + 2n });
  assert.throws(
    () => importRsaSer(artifact, 'private'),
    (err: unknown) => {
      assert.ok(err instanceof SdkContractError);
      assert.equal(err.errorClass, 'invalid_key');
      assert.deepEqual(err.clauseIds, ['rsa-ser.private-relations']);
      return true;
    },
  );
});

test('rsa-ser.private-relations: corrupted dP (e*dP != 1 mod (p-1)) is rejected as invalid_key', () => {
  const artifact = buildPrivateArtifact({ dP: privateMaterial.dP + 2n });
  assert.throws(
    () => importRsaSer(artifact, 'private'),
    (err: unknown) => {
      assert.ok(err instanceof SdkContractError);
      assert.equal(err.errorClass, 'invalid_key');
      assert.deepEqual(err.clauseIds, ['rsa-ser.private-relations']);
      return true;
    },
  );
});

test('rsa-ser.private-domain: p == q is rejected as invalid_key', () => {
  const artifact = buildPrivateArtifact({ q: privateMaterial.p });
  assert.throws(
    () => importRsaSer(artifact, 'private'),
    (err: unknown) => {
      assert.ok(err instanceof SdkContractError);
      assert.equal(err.errorClass, 'invalid_key');
      return true;
    },
  );
});

test('valid private material passes both private-domain and private-relations (the real Node-generated key)', () => {
  assert.doesNotThrow(() => importRsaSer(pkcs8Der, 'private'));
});

test('rsa-ser.container: a 10-field (multi-prime-shaped) RSAPrivateKey is rejected as malformed_artifact -- multi-prime is outside the portable profile (D-053)', () => {
  const multiPrimeInner = encodeSequence([
    encodeInteger(1n),
    encodeInteger(privateMaterial.n),
    encodeInteger(privateMaterial.e),
    encodeInteger(privateMaterial.d),
    encodeInteger(privateMaterial.p),
    encodeInteger(privateMaterial.q),
    encodeInteger(privateMaterial.dP),
    encodeInteger(privateMaterial.dQ),
    encodeInteger(privateMaterial.qInv),
    encodeSequence([]),
  ]);
  const algId = encodeSequence([encodeRsaEncryptionOid(), encodeNull()]);
  const artifact = encodeSequence([encodeInteger(0n), algId, encodeOctetString(multiPrimeInner)]);
  assert.throws(
    () => importRsaSer(artifact, 'private'),
    (err: unknown) => {
      assert.ok(err instanceof SdkContractError);
      assert.equal(err.errorClass, 'malformed_artifact');
      assert.deepEqual(err.clauseIds, ['rsa-ser.container']);
      return true;
    },
  );
});
