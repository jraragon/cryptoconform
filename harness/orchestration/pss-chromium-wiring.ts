// M2.5.2 -- PSS x real Chromium (Playwright), sign and verify.
// Reuses M1's real validatePssSignRequest/validatePssVerifyRequest (pure JS
// contract logic). Only the actual crypto.subtle call executes inside the
// real browser -- pssWebCrypto* (src/adapters/webcrypto/pss.ts) is
// Node-bound and cannot run in a page.evaluate() context, same reasoning
// as HKDF/GCM/OAEP. Reuses OAEP's own full-CRT-parameter JWK requirement
// (M2.5.2 finding): Chromium's crypto.subtle.importKey('jwk', ...) for an
// RSA private key strictly needs p/q/dp/dq/qi, not just n/e/d.

import { validatePssSignRequest, validatePssVerifyRequest, type PssSignRequest, type PssVerifyRequest } from '../../src/contract/pss.js';
import { SdkContractError } from '../../src/contract/errors.js';
import { toHex, type PssSignEvidenceRecord, type PssVerifyEvidenceRecord } from '../../src/evidence/record.js';
import { CHROMIUM_WEBCRYPTO } from '../schema/backend-identity.js';
import type { ExecutionAdapter } from './engine.js';
import { getSharedChromiumPage } from './chromium-page.js';
import type { OaepKeyHex as PssKeyHex } from './oaep-chromium-wiring.js'; // identical shape (n,e,d,p,q,dp,dq,qi hex)

function realization(): string {
  return `chromium ${CHROMIUM_WEBCRYPTO.apiVersion} (${CHROMIUM_WEBCRYPTO.sourcePin})`;
}
function hexToBase64Url(hex: string): string {
  return Buffer.from(hex, 'hex').toString('base64url');
}
function publicJwk(key: PssKeyHex): object {
  return { kty: 'RSA', n: hexToBase64Url(key.modulusHex), e: hexToBase64Url(key.publicExponentHex), ext: true };
}
function privateJwk(key: PssKeyHex): object {
  return {
    ...publicJwk(key),
    d: hexToBase64Url(key.privateExponentHex ?? ''),
    p: hexToBase64Url(key.pHex ?? ''), q: hexToBase64Url(key.qHex ?? ''),
    dp: hexToBase64Url(key.dpHex ?? ''), dq: hexToBase64Url(key.dqHex ?? ''),
    qi: hexToBase64Url(key.qiHex ?? ''),
  };
}

function buildSignScript(jwk: object, messageHex: string, saltLengthBytes: number): string {
  const argsJson = JSON.stringify({ jwk, messageHex, saltLengthBytes });
  return `
    (async () => {
      const args = ${argsJson};
      const hexToBytes = (hex) => {
        const out = new Uint8Array(new ArrayBuffer(hex.length / 2));
        for (let i = 0; i < out.length; i++) out[i] = parseInt(hex.substr(i * 2, 2), 16);
        return out;
      };
      const key = await crypto.subtle.importKey('jwk', args.jwk, { name: 'RSA-PSS', hash: 'SHA-256' }, false, ['sign']);
      const sigBuffer = await crypto.subtle.sign({ name: 'RSA-PSS', saltLength: args.saltLengthBytes }, key, hexToBytes(args.messageHex));
      return Array.from(new Uint8Array(sigBuffer)).map((b) => b.toString(16).padStart(2, '0')).join('');
    })()
  `;
}
function buildVerifyScript(jwk: object, messageHex: string, signatureHex: string, saltLengthBytes: number): string {
  const argsJson = JSON.stringify({ jwk, messageHex, signatureHex, saltLengthBytes });
  return `
    (async () => {
      const args = ${argsJson};
      const hexToBytes = (hex) => {
        const out = new Uint8Array(new ArrayBuffer(hex.length / 2));
        for (let i = 0; i < out.length; i++) out[i] = parseInt(hex.substr(i * 2, 2), 16);
        return out;
      };
      const key = await crypto.subtle.importKey('jwk', args.jwk, { name: 'RSA-PSS', hash: 'SHA-256' }, false, ['verify']);
      const valid = await crypto.subtle.verify({ name: 'RSA-PSS', saltLength: args.saltLengthBytes }, key, hexToBytes(args.signatureHex), hexToBytes(args.messageHex));
      return valid;
    })()
  `;
}

export function makePssSignChromiumAdapter(key: PssKeyHex): ExecutionAdapter<PssSignRequest, PssSignEvidenceRecord> {
  return {
    operation: 'pss',
    backend: CHROMIUM_WEBCRYPTO,
    execute: async (fixture) => {
      const input = { keyRole: fixture.key.role, modulusBits: fixture.key.modulusBits, messageHex: toHex(fixture.message), hash: fixture.hash, mgfHash: fixture.mgfHash, saltLengthBytes: fixture.saltLengthBytes };
      try {
        validatePssSignRequest(fixture); // Accept_C -- real M1 contract function, unmodified
        const page = await getSharedChromiumPage();
        const signatureHex: string = await page.evaluate(buildSignScript(privateJwk(key), input.messageHex, fixture.saltLengthBytes));
        return {
          operation: 'RSA-PSS', direction: 'sign',
          backend: { name: 'webcrypto', realization: realization() },
          clauseIds: ['pss.key', 'pss.modulus', 'pss.hash', 'pss.mgfCoupling', 'pss.saltLength', 'pss.message'],
          mutationId: null, input,
          outcome: { kind: 'accept', signatureHex },
          timestampIso: new Date().toISOString(),
        };
      } catch (err) {
        if (err instanceof SdkContractError) {
          return {
            operation: 'RSA-PSS', direction: 'sign',
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
      subject: { backend: CHROMIUM_WEBCRYPTO, direction: 'sign', path: 'sdk' },
      input: { kind: 'pss-sign-request', value: record.input },
      output: record.outcome.kind === 'accept' ? { kind: 'pss-signature', bytes: record.outcome.signatureHex } : undefined,
      outcome: record.outcome.kind === 'accept' ? { kind: 'accept' } : { kind: 'reject', detail: `${record.outcome.errorClass}: ${record.outcome.detail}` },
      clauseIdsEvaluated: record.clauseIds,
      executionStatus: 'completed',
      nativeObservation: undefined,
    }),
  };
}

export function makePssVerifyChromiumAdapter(key: PssKeyHex): ExecutionAdapter<PssVerifyRequest, PssVerifyEvidenceRecord> {
  return {
    operation: 'pss',
    backend: CHROMIUM_WEBCRYPTO,
    execute: async (fixture) => {
      const input = { keyRole: fixture.key.role, modulusBits: fixture.key.modulusBits, messageHex: toHex(fixture.message), signatureHex: toHex(fixture.signature), hash: fixture.hash, mgfHash: fixture.mgfHash, saltLengthBytes: fixture.saltLengthBytes };
      try {
        validatePssVerifyRequest(fixture); // Accept_C -- real M1 contract function, unmodified (deliberately no signature-length check, D-046)
        const page = await getSharedChromiumPage();
        const valid: boolean = await page.evaluate(buildVerifyScript(publicJwk(key), input.messageHex, input.signatureHex, fixture.saltLengthBytes));
        return {
          operation: 'RSA-PSS', direction: 'verify',
          backend: { name: 'webcrypto', realization: realization() },
          clauseIds: ['pss.key', 'pss.modulus', 'pss.hash', 'pss.mgfCoupling', 'pss.saltLength'],
          mutationId: null, input,
          outcome: { kind: 'verified', valid },
          timestampIso: new Date().toISOString(),
        };
      } catch (err) {
        if (err instanceof SdkContractError) {
          return {
            operation: 'RSA-PSS', direction: 'verify',
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
      subject: { backend: CHROMIUM_WEBCRYPTO, direction: 'verify', path: 'sdk' },
      input: { kind: 'pss-verify-request', value: record.input },
      output: record.outcome.kind === 'verified' ? { kind: 'pss-verified', bytes: String(record.outcome.valid) } : undefined,
      outcome: record.outcome.kind === 'verified' ? { kind: 'accept' } : { kind: 'reject', detail: `${record.outcome.errorClass}: ${record.outcome.detail}` },
      clauseIdsEvaluated: record.clauseIds,
      executionStatus: 'completed',
      nativeObservation: undefined,
    }),
  };
}
