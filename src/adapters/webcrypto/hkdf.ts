import { webcrypto } from 'node:crypto';
import { validateHkdfRequest, type HkdfRequest } from '../../contract/hkdf.js';
import { SdkContractError } from '../../contract/errors.js';
import { toHex, type HkdfEvidenceRecord } from '../../evidence/record.js';

/**
 * WebCrypto realization identity string. MUST be updated to the exact pinned
 * Node LTS version once fixed at repo init (Experimental_Evidence_Base v0.1,
 * sec:environment) -- process.version alone is recorded here as the
 * reproducibility anchor for this evidence record.
 */
function realizationId(): string {
  return `node:${process.version} webcrypto (OpenSSL-backed, not Chromium/BoringSSL -- see sec:environment)`;
}

/**
 * I_p = API_p . Adapter_p (v0.6). This function IS Adapter_p for
 * (HKDF, WebCrypto): it enforces Accept_C (validateHkdfRequest) itself,
 * since v0.6 does not establish that WebCrypto's native subtle.deriveBits
 * enforces the portable L bound -- the adapter cannot assume it does.
 */
export async function hkdfWebCrypto(req: HkdfRequest): Promise<HkdfEvidenceRecord> {
  const input = {
    ikmHex: toHex(req.ikm),
    saltHex: req.salt === undefined ? null : toHex(req.salt),
    infoHex: toHex(req.info),
    length: req.length,
  };

  try {
    validateHkdfRequest(req); // Accept_C -- SDK-level, not delegated to the backend

    const key = await webcrypto.subtle.importKey('raw', req.ikm, 'HKDF', false, ['deriveBits']);

    // RFC 5869: absent salt = HashLen zero octets. Under HMAC's own zero-padding
    // of short keys, an empty-byte salt and a HashLen-zero-byte salt produce an
    // identical padded HMAC key, so an empty ArrayBuffer is the correct mapping
    // for "absent" here, not an approximation.
    const salt = req.salt ?? new Uint8Array(0);

    const okmBuffer = await webcrypto.subtle.deriveBits(
      { name: 'HKDF', hash: 'SHA-256', salt, info: req.info },
      key,
      req.length * 8,
    );

    return {
      operation: 'HKDF-SHA-256',
      backend: { name: 'webcrypto', realization: realizationId() },
      clauseIds: ['hkdf.ikm', 'hkdf.salt', 'hkdf.info', 'hkdf.hash', 'hkdf.length', 'hkdf.output'],
      mutationId: null,
      input,
      outcome: { kind: 'accept', okmHex: toHex(new Uint8Array(okmBuffer)) },
      timestampIso: new Date().toISOString(),
    };
  } catch (err) {
    if (err instanceof SdkContractError) {
      return {
        operation: 'HKDF-SHA-256',
        backend: { name: 'webcrypto', realization: realizationId() },
        clauseIds: err.clauseIds,
        mutationId: null,
        input,
        outcome: { kind: 'reject', errorClass: err.errorClass, detail: err.message },
        timestampIso: new Date().toISOString(),
      };
    }
    throw err; // an unexpected native failure is NOT normalized away -- v0.6's "no catch-all provider error" rule
  }
}
