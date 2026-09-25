import { webcrypto } from 'node:crypto';
import {
  validateOaepEncryptRequest,
  validateOaepDecryptRequest,
  MODULUS_BITS,
  OAEP_HASH,
  type OaepKeyRef,
} from '../../contract/oaep.js';
import { SdkContractError } from '../../contract/errors.js';
import { toHex, type OaepEncryptEvidenceRecord, type OaepDecryptEvidenceRecord } from '../../evidence/record.js';

/**
 * WebCrypto realization identity string. Same pattern as the HKDF/GCM
 * WebCrypto adapters -- process.version is the reproducibility anchor,
 * exact pinned Node LTS build to be substituted at real repo init
 * (Experimental_Evidence_Base sec:environment).
 */
function realizationId(): string {
  return `node:${process.version} webcrypto RSA-OAEP (OpenSSL-backed, not Chromium/BoringSSL -- see sec:environment)`;
}

function nowIso(): string {
  return new Date().toISOString();
}

/**
 * Generates an RSA-3072/SHA-256 OAEP key pair via WebCrypto -- the shared
 * fixture used across this adapter's baseline tests. Not itself part of
 * Accept_C; a plain convenience so tests don't each hand-roll key generation.
 */
export async function generateOaepKeyPair(): Promise<CryptoKeyPair> {
  return webcrypto.subtle.generateKey(
    { name: 'RSA-OAEP', modulusLength: MODULUS_BITS, publicExponent: new Uint8Array([1, 0, 1]), hash: OAEP_HASH },
    true,
    ['encrypt', 'decrypt'],
  );
}

/**
 * Derives the backend-agnostic OaepKeyRef from an actual WebCrypto CryptoKey.
 *
 * CRITICAL: hash and mgfHash are read
 * DIRECTLY from key.algorithm.hash.name, never accepted as a separate,
 * independently-suppliable request field. WebCrypto structurally couples
 * OAEP's hash to the CryptoKey itself (v0.6, sec:oaep: "the operation is
 * performed with... the hash function specified by the
 * RsaHashedKeyAlgorithm/hash attribute of the CryptoKey's internal slot...
 * no independent MGF1-hash parameter exists"). If this adapter instead let
 * a caller-declared hash flow into Accept_C independently of the key's own
 * material hash, a request could nominally "claim" SHA-256 while the actual
 * CryptoKey was generated with a different hash entirely, and subtle.encrypt
 * would silently honor the key's real hash regardless -- an adapter-induced
 * divergence between what Accept_C validated and what was actually computed.
 */
function keyRefAndHash(key: CryptoKey): { keyRef: OaepKeyRef; hash: string } {
  const algo = key.algorithm as RsaHashedKeyAlgorithm;
  const role: OaepKeyRef['role'] = key.type === 'public' ? 'public' : 'private';
  return {
    keyRef: { role, modulusBits: algo.modulusLength },
    hash: algo.hash.name,
  };
}

export interface OaepWebCryptoEncryptInput {
  readonly key: CryptoKey;
  readonly plaintext: Uint8Array;
  readonly label: Uint8Array | undefined; // undefined = absent; contractually === empty (D-030)
}

export interface OaepWebCryptoDecryptInput {
  readonly key: CryptoKey;
  readonly ciphertext: Uint8Array; // NOT length-checked by this adapter before the backend call -- see D-034
  readonly label: Uint8Array | undefined;
}

/**
 * I_p = API_p . Adapter_p for (RSA-OAEP encrypt, WebCrypto). Enforces v0.6's
 * frozen steps 2 (key role) and 3 (portable parameters), with hash/mgfHash
 * derived from the CryptoKey itself (see keyRefAndHash). Step 4 does not
 * apply to encrypt.
 */
export async function oaepWebCryptoEncrypt(input: OaepWebCryptoEncryptInput): Promise<OaepEncryptEvidenceRecord> {
  const { keyRef, hash } = keyRefAndHash(input.key);
  const evidenceInput = {
    keyRole: keyRef.role,
    modulusBits: keyRef.modulusBits,
    plaintextHex: toHex(input.plaintext),
    labelHex: input.label === undefined ? null : toHex(input.label),
    hash,
    mgfHash: hash, // WebCrypto structurally couples them -- see keyRefAndHash's comment
  };

  try {
    validateOaepEncryptRequest({
      key: keyRef,
      plaintext: input.plaintext,
      label: input.label,
      hash,
      mgfHash: hash,
    }); // Accept_C: steps 2+3, SDK-level, not delegated to the backend

    const params: RsaOaepParams = { name: 'RSA-OAEP' };
    if (input.label !== undefined) {
      // Explicit empty vs. omitted are both exercised as genuinely distinct
      // calls into the real WebCrypto API (same pattern already used for
      // gcm.aad) -- oaep.label's absent===empty equivalence is confirmed by
      // the test suite calling both shapes, not assumed here.
      params.label = input.label as BufferSource;
    }

    const cipherBuffer = await webcrypto.subtle.encrypt(params, input.key, input.plaintext);
    const ciphertext = new Uint8Array(cipherBuffer);

    return {
      operation: 'RSA-OAEP',
      direction: 'encrypt',
      backend: { name: 'webcrypto', realization: realizationId() },
      clauseIds: [
        'oaep.key',
        'oaep.modulus',
        'oaep.message',
        'oaep.ciphertext',
        'oaep.ciphertextLength',
        'oaep.hash',
        'oaep.mgfCoupling',
        'oaep.label',
      ],
      mutationId: null,
      input: evidenceInput,
      outcome: { kind: 'accept', ciphertextHex: toHex(ciphertext) },
      timestampIso: nowIso(),
    };
  } catch (err) {
    if (err instanceof SdkContractError) {
      return {
        operation: 'RSA-OAEP',
        direction: 'encrypt',
        backend: { name: 'webcrypto', realization: realizationId() },
        clauseIds: err.clauseIds,
        mutationId: null,
        input: evidenceInput,
        outcome: { kind: 'reject', errorClass: err.errorClass, detail: err.message },
        timestampIso: nowIso(),
      };
    }
    throw err; // an unexpected native failure is NOT normalized away -- same rule as HKDF/GCM
  }
}

/**
 * I_p = API_p . Adapter_p for (RSA-OAEP decrypt, WebCrypto). Enforces v0.6's
 * frozen steps 2 (key role) and 3 (portable parameters, EXCLUDING ciphertext
 * length -- see validateOaepDecryptRequest's header comment and this file's
 * RED-COMMENT-equivalent below). Step 4 (RSAES-OAEP-DECRYPT collapse) is
 * enforced by catching the actual subtle.decrypt call WITHOUT inspecting
 * the caught error's name, type, or message -- any failure reaching that
 * point, after steps 2-3 have already passed, is normalized to
 * decryption_error unconditionally.
 */
export async function oaepWebCryptoDecrypt(input: OaepWebCryptoDecryptInput): Promise<OaepDecryptEvidenceRecord> {
  const { keyRef, hash } = keyRefAndHash(input.key);
  const evidenceInput = {
    keyRole: keyRef.role,
    modulusBits: keyRef.modulusBits,
    ciphertextHex: toHex(input.ciphertext),
    labelHex: input.label === undefined ? null : toHex(input.label),
    hash,
    mgfHash: hash,
  };

  try {
    validateOaepDecryptRequest({
      key: keyRef,
      ciphertext: input.ciphertext, // Accept_C deliberately does NOT check this length -- D-034
      label: input.label,
      hash,
      mgfHash: hash,
    }); // steps 2+3

    const params: RsaOaepParams = { name: 'RSA-OAEP' };
    if (input.label !== undefined) {
      params.label = input.label as BufferSource;
    }

    let plaintextBuffer: ArrayBuffer;
    try {
      // Step 4. A wrong-length ciphertext (or any other RSAES-OAEP-DECRYPT
      // failure) reaches THIS call unmodified -- Accept_C above never
      // rejected it. Whatever WebCrypto throws here is caught blindly,
      // exactly like the GCM adapter's authentication_failure catch, but
      // for a different, RFC-mandated reason (Bleichenbacher/Manger
      // anti-oracle collapse, not a GCM-style design choice).
      plaintextBuffer = await webcrypto.subtle.decrypt(params, input.key, input.ciphertext);
    } catch {
      return {
        operation: 'RSA-OAEP',
        direction: 'decrypt',
        backend: { name: 'webcrypto', realization: realizationId() },
        clauseIds: ['oaep.error'],
        mutationId: null,
        input: evidenceInput,
        outcome: {
          kind: 'reject',
          errorClass: 'decryption_error',
          detail:
            'RSAES-OAEP-DECRYPT failed (ciphertext length, lHash, padding, or RSA-representative-range cause -- collapsed per RFC 8017 Sec.7.1.2 anti-oracle requirement, D-027)',
        },
        timestampIso: nowIso(),
      };
    }

    return {
      operation: 'RSA-OAEP',
      direction: 'decrypt',
      backend: { name: 'webcrypto', realization: realizationId() },
      clauseIds: ['oaep.key', 'oaep.modulus', 'oaep.hash', 'oaep.mgfCoupling', 'oaep.label'],
      mutationId: null,
      input: evidenceInput,
      outcome: { kind: 'accept', plaintextHex: toHex(new Uint8Array(plaintextBuffer)) },
      timestampIso: nowIso(),
    };
  } catch (err) {
    if (err instanceof SdkContractError) {
      return {
        operation: 'RSA-OAEP',
        direction: 'decrypt',
        backend: { name: 'webcrypto', realization: realizationId() },
        clauseIds: err.clauseIds,
        mutationId: null,
        input: evidenceInput,
        outcome: { kind: 'reject', errorClass: err.errorClass, detail: err.message },
        timestampIso: nowIso(),
      };
    }
    throw err;
  }
}
