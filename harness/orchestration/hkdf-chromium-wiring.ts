// M2.5.1 -- HKDF x real Chromium (Playwright), the first genuine
// resolution of M2.4.7's own Node/Chromium finding. Reuses M1's real
// validateHkdfRequest (Accept_C) unmodified; the crypto.subtle call itself
// runs inside an actual Chromium page, since hkdfWebCrypto (Node-bound)
// cannot execute in a browser context -- see M2.5.1-CONTRACT.md.

import { validateHkdfRequest, type HkdfRequest } from '../../src/contract/hkdf.js';
import { SdkContractError } from '../../src/contract/errors.js';
import { toHex, type HkdfEvidenceRecord } from '../../src/evidence/record.js';
import { CHROMIUM_WEBCRYPTO } from '../schema/backend-identity.js';
import type { ExecutionAdapter } from './engine.js';
import { getSharedChromiumPage, closeSharedChromium } from './chromium-page.js';
import type { Page } from 'playwright';

export const closeChromiumForTests = closeSharedChromium;

// Runs INSIDE the real Chromium page via page.evaluate -- this is
// Chromium's own native WebCrypto, not Node's. Deliberately mirrors
// hkdfWebCrypto's own call shape (RFC 5869 absent-salt handling included)
// without being able to literally invoke that Node-bound function here.
// Passed as a raw JS string with arguments interpolated directly (via
// JSON.stringify), not using page.evaluate's separate `arg` parameter --
// confirmed empirically that the string form of page.evaluate does NOT
// invoke the resulting function with a passed arg the way the function
// form does (arg is silently ignored). Also sidesteps a real, confirmed
// esbuild/tsx artifact: compiling a function reference through this
// codebase's own TypeScript pipeline for page.evaluate can inject a call
// to an esbuild-internal __name() helper for stack-trace naming, which
// Playwright's function-serialization path does not carry into the
// browser, producing 'ReferenceError: __name is not defined'. A plain,
// self-contained string is never run through that compilation step at
// all, avoiding the artifact at its source.
function buildChromiumHkdfScript(ikmHex: string, saltHex: string | null, infoHex: string, length: number): string {
  const argsJson = JSON.stringify({ ikmHex, saltHex, infoHex, length });
  return `
    (async () => {
      const args = ${argsJson};
      const hexToBytes = (hex) => {
        const out = new Uint8Array(new ArrayBuffer(hex.length / 2));
        for (let i = 0; i < out.length; i++) out[i] = parseInt(hex.substr(i * 2, 2), 16);
        return out;
      };
      const ikm = hexToBytes(args.ikmHex);
      const info = hexToBytes(args.infoHex);
      const salt = args.saltHex === null ? new Uint8Array(0) : hexToBytes(args.saltHex);
      const key = await crypto.subtle.importKey('raw', ikm, 'HKDF', false, ['deriveBits']);
      const okmBuffer = await crypto.subtle.deriveBits({ name: 'HKDF', hash: 'SHA-256', salt, info }, key, args.length * 8);
      const okmBytes = new Uint8Array(okmBuffer);
      return Array.from(okmBytes).map((b) => b.toString(16).padStart(2, '0')).join('');
    })()
  `;
}

async function deriveInChromium(page: Page, ikmHex: string, saltHex: string | null, infoHex: string, length: number): Promise<string> {
  return page.evaluate(buildChromiumHkdfScript(ikmHex, saltHex, infoHex, length));
}

export const HKDF_CHROMIUM_ADAPTER: ExecutionAdapter<HkdfRequest, HkdfEvidenceRecord> = {
  operation: 'hkdf',
  backend: CHROMIUM_WEBCRYPTO,
  execute: async (fixture) => {
    const input = {
      ikmHex: toHex(fixture.ikm),
      saltHex: fixture.salt === undefined ? null : toHex(fixture.salt),
      infoHex: toHex(fixture.info),
      length: fixture.length,
    };
    try {
      validateHkdfRequest(fixture); // Accept_C -- the real M1 contract function, unmodified
      const page = await getSharedChromiumPage();
      const okmHex = await deriveInChromium(page, input.ikmHex, input.saltHex, input.infoHex, fixture.length);
      return {
        operation: 'HKDF-SHA-256',
        backend: { name: 'webcrypto', realization: `chromium ${CHROMIUM_WEBCRYPTO.apiVersion} (${CHROMIUM_WEBCRYPTO.sourcePin})` },
        clauseIds: ['hkdf.ikm', 'hkdf.salt', 'hkdf.info', 'hkdf.hash', 'hkdf.length', 'hkdf.output'],
        mutationId: null,
        input,
        outcome: { kind: 'accept', okmHex },
        timestampIso: new Date().toISOString(),
      };
    } catch (err) {
      if (err instanceof SdkContractError) {
        return {
          operation: 'HKDF-SHA-256',
          backend: { name: 'webcrypto', realization: `chromium ${CHROMIUM_WEBCRYPTO.apiVersion} (${CHROMIUM_WEBCRYPTO.sourcePin})` },
          clauseIds: err.clauseIds,
          mutationId: null,
          input,
          outcome: { kind: 'reject', errorClass: err.errorClass, detail: err.message },
          timestampIso: new Date().toISOString(),
        };
      }
      throw err;
    }
  },
  toEvidenceFields: (_fixture, record) => ({
    subject: { backend: CHROMIUM_WEBCRYPTO, direction: 'derive', path: 'sdk' },
    input: { kind: 'hkdf-request', value: record.input },
    output: record.outcome.kind === 'accept' ? { kind: 'hkdf-okm', bytes: record.outcome.okmHex } : undefined,
    outcome: record.outcome.kind === 'accept'
      ? { kind: 'accept' }
      : { kind: 'reject', detail: `${record.outcome.errorClass}: ${record.outcome.detail}` },
    clauseIdsEvaluated: record.clauseIds,
    executionStatus: 'completed',
    nativeObservation: undefined,
  }),
};
