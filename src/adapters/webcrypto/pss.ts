import { webcrypto } from 'node:crypto';
import { validatePssSignRequest, validatePssVerifyRequest, MODULUS_BITS, PSS_HASH, SALT_LEN_BYTES, type PssKeyRef } from '../../contract/pss.js';
import { SdkContractError } from '../../contract/errors.js';
import { toHex, type PssSignEvidenceRecord, type PssVerifyEvidenceRecord } from '../../evidence/record.js';

/**
 * WebCrypto realization identity string. Same pattern as the HKDF/GCM/OAEP
 * WebCrypto adapters -- process.version is the reproducibility anchor,
 * exact pinned Node LTS build to be substituted at real repo init
 * (Experimental Evidence Base sec:environment).
 */
function realizationId(): string {
  return `node:${process.version} webcrypto RSA-PSS (OpenSSL-backed, not Chromium/BoringSSL -- see sec:environment)`;
}

function nowIso(): string {
  return new Date().toISOString();
}

/**
 * Generates an RSA-3072/SHA-256 PSS key pair via WebCrypto -- the shared
 * fixture used across this adapter's baseline tests.
 */
export async function generatePssKeyPair(): Promise<CryptoKeyPair> {
  return webcrypto.subtle.generateKey(
    { name: 'RSA-PSS', modulusLength: MODULUS_BITS, publicExponent: new Uint8Array([1, 0, 1]), hash: PSS_HASH },
    true,
    ['sign', 'verify'],
  );
}

/**
 * Derives the backend-agnostic PssKeyRef and hash DIRECTLY from the actual
 * CryptoKey, exactly like OAEP's keyRefAndHash -- never from a separately-
 * suppliable request field. Same rationale as OAEP: WebCrypto structurally
 * couples PSS's hash to the CryptoKey's own algorithm.hash attribute; a
 * request could otherwise "claim" SHA-256 while the key material actually
 * carries a different digest, and subtle.sign/verify would silently honor
 * the key's real hash regardless.
 */
function keyRefAndHash(key: CryptoKey): { keyRef: PssKeyRef; hash: string } {
  const algo = key.algorithm as RsaHashedKeyAlgorithm;
  const role: PssKeyRef['role'] = key.type === 'public' ? 'public' : 'private';
  return {
    keyRef: { role, modulusBits: algo.modulusLength },
    hash: algo.hash.name,
  };
}

export interface PssWebCryptoSignInput {
  readonly key: CryptoKey;
  readonly message: Uint8Array;
}

export interface PssWebCryptoVerifyInput {
  readonly key: CryptoKey;
  readonly message: Uint8Array;
  readonly signature: Uint8Array; // NOT length-checked by this adapter before the backend call -- see D-046
}

/**
 * I_p = API_p . Adapter_p for (RSA-PSS sign, WebCrypto). Accept_C (key role
 * + portable parameters, hash/mgfHash derived from the key itself,
 * saltLength EXPLICITLY fixed to SALT_LEN_BYTES rather than omitted from
 * the RsaPssParams call) runs entirely before subtle.sign is touched.
 */
export async function pssWebCryptoSign(input: PssWebCryptoSignInput): Promise<PssSignEvidenceRecord> {
  const { keyRef, hash } = keyRefAndHash(input.key);
  const evidenceInput = {
    keyRole: keyRef.role,
    modulusBits: keyRef.modulusBits,
    messageHex: toHex(input.message),
    hash,
    mgfHash: hash, // WebCrypto structurally couples them -- see keyRefAndHash's comment
    saltLengthBytes: SALT_LEN_BYTES,
  };

  try {
    validatePssSignRequest({
      key: keyRef,
      message: input.message,
      hash,
      mgfHash: hash,
      saltLengthBytes: SALT_LEN_BYTES,
    }); // Accept_C

    // saltLength is passed EXPLICITLY here, not omitted and left to
    // whatever WebCrypto's own default might be -- the portable profile's
    // value (32 = hLen) is a deliberate contractual choice, not an
    // unexamined default (same discipline already applied to GCM's
    // DEFAULT_CHANNEL and MAC_AT_END explicitness in the Crypto++ adapter).
    const signatureBuffer = await webcrypto.subtle.sign(
      { name: 'RSA-PSS', saltLength: SALT_LEN_BYTES },
      input.key,
      input.message as BufferSource,
    );
    const signature = new Uint8Array(signatureBuffer);

    return {
      operation: 'RSA-PSS',
      direction: 'sign',
      backend: { name: 'webcrypto', realization: realizationId() },
      clauseIds: [
        'pss.key',
        'pss.modulus',
        'pss.message',
        'pss.hash',
        'pss.mgfCoupling',
        'pss.saltLength',
        'pss.signature',
        'pss.signatureLength',
      ],
      mutationId: null,
      input: evidenceInput,
      outcome: { kind: 'accept', signatureHex: toHex(signature) },
      timestampIso: nowIso(),
    };
  } catch (err) {
    if (err instanceof SdkContractError) {
      return {
        operation: 'RSA-PSS',
        direction: 'sign',
        backend: { name: 'webcrypto', realization: realizationId() },
        clauseIds: err.clauseIds,
        mutationId: null,
        input: evidenceInput,
        outcome: { kind: 'reject', errorClass: err.errorClass, detail: err.message },
        timestampIso: nowIso(),
      };
    }
    throw err; // an unexpected native failure is NOT normalized away -- same rule as HKDF/GCM/OAEP
  }
}

/**
 * I_p = API_p . Adapter_p for (RSA-PSS verify, WebCrypto). Accept_C covers
 * ONLY key role and portable parameters -- deliberately NOT signature
 * length (D-046). Once Accept_C passes, subtle.verify's raw boolean result
 * IS the outcome -- `false` is copied through verbatim as `verified(valid:
 * false)`, never caught, inspected, or reclassified as any SDK error.
 * The only case that can still produce a `reject` outcome after Accept_C
 * passes is an actual thrown exception from subtle.verify itself (e.g. a
 * genuinely malformed CryptoKey/algorithm mismatch) -- which, per this
 * session's explicit requirement, must be classified according to the
 * frozen model rather than silently absorbed into `valid: false`. In
 * practice, per the frozen design's own finding, WebCrypto's verify() is
 * confirmed boolean-only for the ordinary invalid-signature case, so this
 * path is not expected to fire under Accept_C-cleared inputs -- but it is
 * not suppressed if it does.
 */
export async function pssWebCryptoVerify(input: PssWebCryptoVerifyInput): Promise<PssVerifyEvidenceRecord> {
  const { keyRef, hash } = keyRefAndHash(input.key);
  const evidenceInput = {
    keyRole: keyRef.role,
    modulusBits: keyRef.modulusBits,
    messageHex: toHex(input.message),
    signatureHex: toHex(input.signature),
    hash,
    mgfHash: hash,
    saltLengthBytes: SALT_LEN_BYTES,
  };

  try {
    validatePssVerifyRequest({
      key: keyRef,
      message: input.message,
      signature: input.signature, // Accept_C deliberately does NOT check this length -- D-046
      hash,
      mgfHash: hash,
      saltLengthBytes: SALT_LEN_BYTES,
    }); // Accept_C

    // subtle.verify's own raw boolean result IS the outcome. NOT wrapped
    // in a try/catch that maps failure to any SDK error -- a `false`
    // return (including for |signature|!=384, corrupted, truncated,
    // lengthened, or wrong-key cases) is copied through verbatim as a
    // correctly-functioning verification result, per D-046/D-047.
    const valid = await webcrypto.subtle.verify(
      { name: 'RSA-PSS', saltLength: SALT_LEN_BYTES },
      input.key,
      input.signature as BufferSource,
      input.message as BufferSource,
    );

    return {
      operation: 'RSA-PSS',
      direction: 'verify',
      backend: { name: 'webcrypto', realization: realizationId() },
      clauseIds: ['pss.key', 'pss.modulus', 'pss.hash', 'pss.mgfCoupling', 'pss.saltLength', 'pss.verification'],
      mutationId: null,
      input: evidenceInput,
      outcome: { kind: 'verified', valid },
      timestampIso: nowIso(),
    };
  } catch (err) {
    if (err instanceof SdkContractError) {
      return {
        operation: 'RSA-PSS',
        direction: 'verify',
        backend: { name: 'webcrypto', realization: realizationId() },
        clauseIds: err.clauseIds,
        mutationId: null,
        input: evidenceInput,
        outcome: { kind: 'reject', errorClass: err.errorClass, detail: err.message },
        timestampIso: nowIso(),
      };
    }
    // A genuine, unexpected native exception from subtle.verify itself
    // (not the ordinary false-verdict case, which never throws) -- per
    // the frozen classification order, this would need attribution to the
    // frozen model rather than silent absorption. Not expected under
    // Accept_C-cleared inputs (the frozen design confirms WebCrypto's
    // verify() is boolean-only here), so this is deliberately re-thrown
    // as an unexpected finding rather than guessed at.
    throw err;
  }
}
