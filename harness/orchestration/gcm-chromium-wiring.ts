// M2.5.2 -- GCM x real Chromium (Playwright), encrypt and decrypt.
// Reuses M1's real validateGcmEncryptRequest/validateGcmDecryptKey/
// validateGcmDecryptAad/buildAeadArtifact/parseAeadArtifact (pure JS
// contract logic, no WebCrypto dependency -- runs identically in Node).
// Only the actual crypto.subtle call executes inside the real browser,
// for the same reason established in hkdf-chromium-wiring.ts:
// gcmWebCryptoEncrypt/Decrypt (src/adapters/webcrypto/gcm.ts) import
// node:crypto and cannot run in a page.evaluate() context.

import {
  validateGcmEncryptRequest, validateGcmDecryptKey, validateGcmDecryptAad,
  buildAeadArtifact, parseAeadArtifact, TAG_LEN_BYTES,
  type GcmEncryptRequest, type GcmDecryptRequest,
} from '../../src/contract/gcm.js';
import { SdkContractError } from '../../src/contract/errors.js';
import { toHex, type GcmEncryptEvidenceRecord, type GcmDecryptEvidenceRecord } from '../../src/evidence/record.js';
import { CHROMIUM_WEBCRYPTO } from '../schema/backend-identity.js';
import type { ExecutionAdapter } from './engine.js';
import { getSharedChromiumPage } from './chromium-page.js';

function realization(): string {
  return `chromium ${CHROMIUM_WEBCRYPTO.apiVersion} (${CHROMIUM_WEBCRYPTO.sourcePin})`;
}

// Args interpolated directly via JSON.stringify, per the established
// finding (M2.5.1): the string form of page.evaluate does not apply a
// separate arg parameter, and compiling a function reference through this
// codebase's own tsx pipeline can inject an orphaned esbuild __name()
// helper call.
function buildEncryptScript(keyHex: string, plaintextHex: string, aadHex: string | null, ivHex: string, tagLengthBits: number): string {
  const argsJson = JSON.stringify({ keyHex, plaintextHex, aadHex, ivHex, tagLengthBits });
  return `
    (async () => {
      const args = ${argsJson};
      const hexToBytes = (hex) => {
        const out = new Uint8Array(new ArrayBuffer(hex.length / 2));
        for (let i = 0; i < out.length; i++) out[i] = parseInt(hex.substr(i * 2, 2), 16);
        return out;
      };
      const key = await crypto.subtle.importKey('raw', hexToBytes(args.keyHex), { name: 'AES-GCM' }, false, ['encrypt']);
      const algo = { name: 'AES-GCM', iv: hexToBytes(args.ivHex), tagLength: args.tagLengthBits };
      if (args.aadHex !== null) algo.additionalData = hexToBytes(args.aadHex);
      const ctBuffer = await crypto.subtle.encrypt(algo, key, hexToBytes(args.plaintextHex));
      const ctBytes = new Uint8Array(ctBuffer);
      return Array.from(ctBytes).map((b) => b.toString(16).padStart(2, '0')).join('');
    })()
  `;
}

function buildDecryptScript(keyHex: string, ctWithTagHex: string, aadHex: string | null, ivHex: string, tagLengthBits: number): string {
  const argsJson = JSON.stringify({ keyHex, ctWithTagHex, aadHex, ivHex, tagLengthBits });
  return `
    (async () => {
      const args = ${argsJson};
      const hexToBytes = (hex) => {
        const out = new Uint8Array(new ArrayBuffer(hex.length / 2));
        for (let i = 0; i < out.length; i++) out[i] = parseInt(hex.substr(i * 2, 2), 16);
        return out;
      };
      try {
        const key = await crypto.subtle.importKey('raw', hexToBytes(args.keyHex), { name: 'AES-GCM' }, false, ['decrypt']);
        const algo = { name: 'AES-GCM', iv: hexToBytes(args.ivHex), tagLength: args.tagLengthBits };
        if (args.aadHex !== null) algo.additionalData = hexToBytes(args.aadHex);
        const ptBuffer = await crypto.subtle.decrypt(algo, key, hexToBytes(args.ctWithTagHex));
        const ptBytes = new Uint8Array(ptBuffer);
        return { ok: true, plaintextHex: Array.from(ptBytes).map((b) => b.toString(16).padStart(2, '0')).join('') };
      } catch (e) {
        return { ok: false, message: String(e && e.message ? e.message : e) };
      }
    })()
  `;
}

export const GCM_ENCRYPT_CHROMIUM_ADAPTER: ExecutionAdapter<GcmEncryptRequest, GcmEncryptEvidenceRecord> = {
  operation: 'gcm',
  backend: CHROMIUM_WEBCRYPTO,
  execute: async (fixture) => {
    const input = {
      keyHex: toHex(fixture.key), plaintextHex: toHex(fixture.plaintext),
      aadHex: fixture.aad === undefined ? null : toHex(fixture.aad),
      ivHex: toHex(fixture.iv), tagLengthBits: fixture.tagLengthBits,
    };
    try {
      validateGcmEncryptRequest(fixture); // Accept_C -- real M1 contract function, unmodified
      const page = await getSharedChromiumPage();
      const ctWithTagHex: string = await page.evaluate(buildEncryptScript(input.keyHex, input.plaintextHex, input.aadHex, input.ivHex, input.tagLengthBits));
      const ctWithTag = Buffer.from(ctWithTagHex, 'hex');
      const ciphertext = ctWithTag.subarray(0, ctWithTag.length - TAG_LEN_BYTES);
      const tag = ctWithTag.subarray(ctWithTag.length - TAG_LEN_BYTES);
      const artifact = buildAeadArtifact(new Uint8Array(fixture.iv), new Uint8Array(ciphertext), new Uint8Array(tag));
      return {
        operation: 'AES-256-GCM', direction: 'encrypt',
        backend: { name: 'webcrypto', realization: realization() },
        clauseIds: ['gcm.key', 'gcm.plaintext', 'gcm.aad', 'gcm.iv', 'gcm.tagLength', 'gcm.ciphertext', 'gcm.artifact'],
        mutationId: null, input,
        outcome: { kind: 'accept', artifactHex: toHex(artifact) },
        timestampIso: new Date().toISOString(),
      };
    } catch (err) {
      if (err instanceof SdkContractError) {
        return {
          operation: 'AES-256-GCM', direction: 'encrypt',
          backend: { name: 'webcrypto', realization: realization() },
          clauseIds: err.clauseIds, mutationId: null, input,
          outcome: { kind: 'reject', errorClass: err.errorClass, detail: err.message },
          timestampIso: new Date().toISOString(),
        };
      }
      throw err;
    }
  },
  toEvidenceFields: (_fixture, record) => ({
    subject: { backend: CHROMIUM_WEBCRYPTO, direction: 'encrypt', path: 'sdk' },
    input: { kind: 'gcm-encrypt-request', value: record.input },
    output: record.outcome.kind === 'accept' ? { kind: 'gcm-artifact', bytes: record.outcome.artifactHex } : undefined,
    outcome: record.outcome.kind === 'accept' ? { kind: 'accept' } : { kind: 'reject', detail: `${record.outcome.errorClass}: ${record.outcome.detail}` },
    clauseIdsEvaluated: record.clauseIds,
    executionStatus: 'completed',
    nativeObservation: undefined,
  }),
};

export const GCM_DECRYPT_CHROMIUM_ADAPTER: ExecutionAdapter<GcmDecryptRequest, GcmDecryptEvidenceRecord> = {
  operation: 'gcm',
  backend: CHROMIUM_WEBCRYPTO,
  execute: async (fixture) => {
    const input = { keyHex: toHex(fixture.key), artifactHex: toHex(fixture.artifact), aadHex: fixture.aad === undefined ? null : toHex(fixture.aad) };
    try {
      validateGcmDecryptKey(fixture); // Accept_C step 1
      const parts = parseAeadArtifact(fixture.artifact); // Accept_C step 2 -- real M1 parser
      validateGcmDecryptAad(fixture); // Accept_C step 3
      const ctWithTagHex = toHex(parts.ciphertext) + toHex(parts.tag);
      const page = await getSharedChromiumPage();
      const result: { ok: boolean; plaintextHex?: string; message?: string } = await page.evaluate(
        buildDecryptScript(input.keyHex, ctWithTagHex, input.aadHex, toHex(parts.iv), TAG_LEN_BYTES * 8),
      );
      if (!result.ok) {
        return {
          operation: 'AES-256-GCM', direction: 'decrypt',
          backend: { name: 'webcrypto', realization: realization() },
          clauseIds: ['gcm.authentication'], mutationId: null, input,
          outcome: { kind: 'reject', errorClass: 'authentication_failure', detail: result.message ?? 'decrypt failed' },
          timestampIso: new Date().toISOString(),
        };
      }
      return {
        operation: 'AES-256-GCM', direction: 'decrypt',
        backend: { name: 'webcrypto', realization: realization() },
        clauseIds: ['gcm.key', 'gcm.aad', 'gcm.artifact', 'gcm.authentication'],
        mutationId: null, input,
        outcome: { kind: 'accept', plaintextHex: result.plaintextHex! },
        timestampIso: new Date().toISOString(),
      };
    } catch (err) {
      if (err instanceof SdkContractError) {
        return {
          operation: 'AES-256-GCM', direction: 'decrypt',
          backend: { name: 'webcrypto', realization: realization() },
          clauseIds: err.clauseIds, mutationId: null, input,
          outcome: { kind: 'reject', errorClass: err.errorClass, detail: err.message },
          timestampIso: new Date().toISOString(),
        };
      }
      throw err;
    }
  },
  toEvidenceFields: (_fixture, record) => ({
    subject: { backend: CHROMIUM_WEBCRYPTO, direction: 'decrypt', path: 'sdk' },
    input: { kind: 'gcm-decrypt-request', value: record.input },
    output: record.outcome.kind === 'accept' ? { kind: 'gcm-plaintext', bytes: record.outcome.plaintextHex } : undefined,
    outcome: record.outcome.kind === 'accept' ? { kind: 'accept' } : { kind: 'reject', detail: `${record.outcome.errorClass}: ${record.outcome.detail}` },
    clauseIdsEvaluated: record.clauseIds,
    executionStatus: 'completed',
    nativeObservation: undefined,
  }),
};
