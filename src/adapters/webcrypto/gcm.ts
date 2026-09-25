import { webcrypto } from 'node:crypto';
import {
  validateGcmEncryptRequest,
  validateGcmDecryptKey,
  validateGcmDecryptAad,
  parseAeadArtifact,
  buildAeadArtifact,
  TAG_LEN_BYTES,
  TAG_LEN_BITS,
  type GcmEncryptRequest,
  type GcmDecryptRequest,
} from '../../contract/gcm.js';
import { SdkContractError } from '../../contract/errors.js';
import { toHex, type GcmEncryptEvidenceRecord, type GcmDecryptEvidenceRecord } from '../../evidence/record.js';

/**
 * WebCrypto realization identity string. MUST be updated to the exact pinned
 * Node LTS version once fixed at repo init (Experimental_Evidence_Base v0.3,
 * sec:environment) -- process.version alone is recorded here as the
 * reproducibility anchor for this evidence record. Same pattern as the HKDF
 * WebCrypto adapter.
 */
function realizationId(): string {
  return `node:${process.version} webcrypto (OpenSSL-backed, not Chromium/BoringSSL -- see sec:environment)`;
}

function nowIso(): string {
  return new Date().toISOString();
}

/**
 * I_p = API_p . Adapter_p (v0.6). This function IS Adapter_p for
 * (AES-GCM encrypt, WebCrypto). Enforces v0.6's frozen classification order:
 *   step 1 (capability/portable boundary: gcm.key, gcm.iv, gcm.tagLength) +
 *   step 3 (remaining parameters: gcm.plaintext, gcm.aad) -- both via
 *   validateGcmEncryptRequest, BEFORE webcrypto.subtle is ever touched.
 * Step 2 (artifact structure) does not apply to encrypt. Step 4
 * (authentication_failure) cannot occur here by construction -- encrypt
 * with contractually valid inputs does not authenticate anything; it only
 * produces C and T.
 *
 * Per v0.6: WebCrypto's own output is normatively C||T (confirmed against
 * the W3C spec text; see v0.6 sec:aesgcm). This adapter does NOT assume or
 * depend on any internal GCM layout beyond that single documented fact --
 * it slices the trailing TAG_LEN_BYTES off the returned buffer to get T,
 * treats the rest as C, and constructs the portable version||IV||C||T
 * artifact itself. No other assumption about WebCrypto's internals is made.
 */
export async function gcmWebCryptoEncrypt(req: GcmEncryptRequest): Promise<GcmEncryptEvidenceRecord> {
  const input = {
    keyHex: req.key instanceof Uint8Array ? toHex(req.key) : '',
    plaintextHex: req.plaintext instanceof Uint8Array ? toHex(req.plaintext) : '',
    aadHex: req.aad === undefined ? null : toHex(req.aad),
    ivHex: req.iv instanceof Uint8Array ? toHex(req.iv) : '',
    tagLengthBits: req.tagLengthBits,
  };

  try {
    validateGcmEncryptRequest(req); // Accept_C: steps 1+3, SDK-level, not delegated to the backend

    const key = await webcrypto.subtle.importKey('raw', req.key, 'AES-GCM', false, ['encrypt']);

    const algo: AesGcmParams = { name: 'AES-GCM', iv: req.iv as BufferSource, tagLength: req.tagLengthBits };
    if (req.aad !== undefined) {
      // Explicit empty vs. omitted are both exercised as genuinely distinct
      // calls into the real WebCrypto API (not pre-decided as equivalent by
      // this adapter) -- gcm.aad's absent===empty equivalence is a contract
      // fact to be CONFIRMED by the test suite calling both shapes, not
      // assumed here.
      algo.additionalData = req.aad as BufferSource;
    }

    const cipherBuffer = await webcrypto.subtle.encrypt(algo, key, req.plaintext);
    const cAndT = new Uint8Array(cipherBuffer);
    const ciphertext = cAndT.slice(0, cAndT.length - TAG_LEN_BYTES);
    const tag = cAndT.slice(cAndT.length - TAG_LEN_BYTES);
    const artifact = buildAeadArtifact(req.iv, ciphertext, tag);

    return {
      operation: 'AES-256-GCM',
      direction: 'encrypt',
      backend: { name: 'webcrypto', realization: realizationId() },
      clauseIds: ['gcm.key', 'gcm.plaintext', 'gcm.aad', 'gcm.iv', 'gcm.tagLength', 'gcm.ciphertext', 'gcm.artifact'],
      mutationId: null,
      input,
      outcome: { kind: 'accept', artifactHex: toHex(artifact) },
      timestampIso: nowIso(),
    };
  } catch (err) {
    if (err instanceof SdkContractError) {
      return {
        operation: 'AES-256-GCM',
        direction: 'encrypt',
        backend: { name: 'webcrypto', realization: realizationId() },
        clauseIds: err.clauseIds,
        mutationId: null,
        input,
        outcome: { kind: 'reject', errorClass: err.errorClass, detail: err.message },
        timestampIso: nowIso(),
      };
    }
    throw err; // an unexpected native failure is NOT normalized away -- v0.6's "no catch-all provider error" rule
  }
}

/**
 * I_p = API_p . Adapter_p (v0.6) for (AES-GCM decrypt, WebCrypto). Enforces
 * v0.6's frozen classification order EXACTLY, as four separate, sequential
 * steps -- not merged, since a single combined validation call would risk
 * misordering step 2 relative to steps 1 and 3:
 *   1. validateGcmDecryptKey  -> gcm.key,        invalid_parameter
 *   2. parseAeadArtifact      -> gcm.artifact,   malformed_artifact
 *   3. validateGcmDecryptAad  -> gcm.aad,        invalid_parameter
 *   4. subtle.decrypt itself  -> gcm.authentication, authentication_failure
 *      (ONLY reachable after 1-3 have excluded every structural/parametric
 *      cause -- per the explicit rule for this adapter: any OperationError
 *      surfacing here is normalized to authentication_failure WITHOUT ever
 *      inspecting its message/type to infer which of IV/AAD/C/T was wrong.
 *      That opacity is exactly what gcm.authentication requires: an
 *      attacker/tester must not be able to distinguish tag-tamper from
 *      AAD-tamper from ciphertext-tamper from the observable error alone.)
 */
export async function gcmWebCryptoDecrypt(req: GcmDecryptRequest): Promise<GcmDecryptEvidenceRecord> {
  const input = {
    keyHex: req.key instanceof Uint8Array ? toHex(req.key) : '',
    artifactHex: req.artifact instanceof Uint8Array ? toHex(req.artifact) : '',
    aadHex: req.aad === undefined ? null : toHex(req.aad),
  };

  try {
    validateGcmDecryptKey(req); // step 1
    const parts = parseAeadArtifact(req.artifact); // step 2
    validateGcmDecryptAad(req); // step 3

    const key = await webcrypto.subtle.importKey('raw', req.key, 'AES-GCM', false, ['decrypt']);
    const cipherAndTag = new Uint8Array(parts.ciphertext.length + parts.tag.length);
    cipherAndTag.set(parts.ciphertext, 0);
    cipherAndTag.set(parts.tag, parts.ciphertext.length);

    const algo: AesGcmParams = { name: 'AES-GCM', iv: parts.iv as BufferSource, tagLength: TAG_LEN_BITS };
    if (req.aad !== undefined) {
      algo.additionalData = req.aad as BufferSource;
    }

    let plaintextBuffer: ArrayBuffer;
    try {
      plaintextBuffer = await webcrypto.subtle.decrypt(algo, key, cipherAndTag); // step 4
    } catch {
      // Deliberately NOT inspecting the caught error's message/type -- see
      // this function's header comment. Any failure reaching here, after
      // steps 1-3 already passed, is normalized to authentication_failure.
      return {
        operation: 'AES-256-GCM',
        direction: 'decrypt',
        backend: { name: 'webcrypto', realization: realizationId() },
        clauseIds: ['gcm.authentication'],
        mutationId: null,
        input,
        outcome: {
          kind: 'reject',
          errorClass: 'authentication_failure',
          detail: 'GCM authentication failed (tag verification rejected the ciphertext/tag/AAD/IV combination)',
        },
        timestampIso: nowIso(),
      };
    }

    return {
      operation: 'AES-256-GCM',
      direction: 'decrypt',
      backend: { name: 'webcrypto', realization: realizationId() },
      clauseIds: ['gcm.key', 'gcm.aad', 'gcm.artifact', 'gcm.authentication'],
      mutationId: null,
      input,
      outcome: { kind: 'accept', plaintextHex: toHex(new Uint8Array(plaintextBuffer)) },
      timestampIso: nowIso(),
    };
  } catch (err) {
    if (err instanceof SdkContractError) {
      return {
        operation: 'AES-256-GCM',
        direction: 'decrypt',
        backend: { name: 'webcrypto', realization: realizationId() },
        clauseIds: err.clauseIds,
        mutationId: null,
        input,
        outcome: { kind: 'reject', errorClass: err.errorClass, detail: err.message },
        timestampIso: nowIso(),
      };
    }
    throw err; // an unexpected native failure is NOT normalized away
  }
}
