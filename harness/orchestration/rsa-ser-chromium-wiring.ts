// M2.5.2 -- RSA-ser x real Chromium (Playwright).
//
// Genuinely different scope from HKDF/GCM/OAEP/PSS: RSA-ser's own portable
// canonical encoder (exportRsaSer/importRsaSer, src/contract/rsa-ser.ts) is
// pure JS/DER logic with NO WebCrypto dependency at all -- it is not
// "backend-specific" in the way crypto.subtle.* calls are, so there is no
// "Chromium's own version" of that specific function to invoke. What IS
// genuinely backend-specific, and what M1's own WebCrypto adapter itself
// tests (see src/adapters/webcrypto/rsa-ser.ts's own header comment), is
// WebCrypto's NATIVE spki/pkcs8 export/import round trip via a JWK-built
// CryptoKey -- this is Chromium's own real native serialization behavior,
// kept conceptually distinct from R_ser's own canonical-encoder question.

import { CHROMIUM_WEBCRYPTO } from '../schema/backend-identity.js';
import { getSharedChromiumPage } from './chromium-page.js';

export interface RsaKeyHexMaterial {
  readonly role: 'public' | 'private';
  readonly nHex: string;
  readonly eHex: string;
  readonly dHex?: string;
  readonly pHex?: string;
  readonly qHex?: string;
  readonly dpHex?: string;
  readonly dqHex?: string;
  readonly qiHex?: string;
}

function hexToBase64Url(hex: string): string {
  return Buffer.from(hex, 'hex').toString('base64url');
}

function toJwk(material: RsaKeyHexMaterial): object {
  if (material.role === 'public') {
    return { kty: 'RSA', n: hexToBase64Url(material.nHex), e: hexToBase64Url(material.eHex), ext: true };
  }
  return {
    kty: 'RSA', n: hexToBase64Url(material.nHex), e: hexToBase64Url(material.eHex),
    d: hexToBase64Url(material.dHex ?? ''), p: hexToBase64Url(material.pHex ?? ''), q: hexToBase64Url(material.qHex ?? ''),
    dp: hexToBase64Url(material.dpHex ?? ''), dq: hexToBase64Url(material.dqHex ?? ''), qi: hexToBase64Url(material.qiHex ?? ''),
    ext: true,
  };
}

function buildRoundtripScript(jwk: object, role: 'public' | 'private'): string {
  const argsJson = JSON.stringify({ jwk, role });
  return `
    (async () => {
      const args = ${argsJson};
      try {
        const usage = args.role === 'public' ? 'encrypt' : 'decrypt';
        const key = await crypto.subtle.importKey('jwk', args.jwk, { name: 'RSA-OAEP', hash: 'SHA-256' }, true, [usage]);
        const exportFormat = args.role === 'public' ? 'spki' : 'pkcs8';
        const artifactBuffer = await crypto.subtle.exportKey(exportFormat, key);
        const artifactHex = Array.from(new Uint8Array(artifactBuffer)).map((b) => b.toString(16).padStart(2, '0')).join('');
        // Native round trip: re-import the artifact we just exported.
        const reimportedKey = await crypto.subtle.importKey(exportFormat, artifactBuffer, { name: 'RSA-OAEP', hash: 'SHA-256' }, true, [usage]);
        const reimportedJwk = await crypto.subtle.exportKey('jwk', reimportedKey);
        return { ok: true, artifactHex, materialPreserved: reimportedJwk.n === args.jwk.n && reimportedJwk.e === args.jwk.e };
      } catch (e) {
        return { ok: false, message: String(e && e.message ? e.message : e) };
      }
    })()
  `;
}

export interface RsaSerRoundtripResult {
  readonly backend: typeof CHROMIUM_WEBCRYPTO;
  readonly exportOk: boolean;
  readonly artifactHex?: string;
  readonly importOk?: boolean;
  readonly materialPreserved?: boolean;
  readonly errorMessage?: string;
}

// Deliberately NOT an ExecutionAdapter<TFixture,TNativeRecord> like the
// other operations -- RSA-ser's own Phase A question (Export_p(K)->A_p,
// Import_p(A_p)->K'_p, K'_p===K) is a single combined round-trip check,
// mirrored identically across all three backends' own wiring functions
// for this operation specifically.
export async function rsaSerRoundtripChromium(material: RsaKeyHexMaterial): Promise<RsaSerRoundtripResult> {
  const page = await getSharedChromiumPage();
  const result: { ok: boolean; artifactHex?: string; materialPreserved?: boolean; message?: string } =
    await page.evaluate(buildRoundtripScript(toJwk(material), material.role));
  if (!result.ok) {
    return { backend: CHROMIUM_WEBCRYPTO, exportOk: false, errorMessage: result.message };
  }
  return { backend: CHROMIUM_WEBCRYPTO, exportOk: true, artifactHex: result.artifactHex, importOk: true, materialPreserved: result.materialPreserved };
}

// ---------------------------------------------------------------------
// M2.5.3.4 -- separate export/import, for cross-provider Phase B. The
// artifact from exportP is handed LITERALLY to Chromium's own native
// importKey(spki/pkcs8, ...) -- never decoded and re-encoded in between.
// ---------------------------------------------------------------------

function buildExportOnlyScript(jwk: object, role: 'public' | 'private'): string {
  const argsJson = JSON.stringify({ jwk, role });
  return `
    (async () => {
      const args = ${argsJson};
      try {
        const usage = args.role === 'public' ? 'encrypt' : 'decrypt';
        const key = await crypto.subtle.importKey('jwk', args.jwk, { name: 'RSA-OAEP', hash: 'SHA-256' }, true, [usage]);
        const exportFormat = args.role === 'public' ? 'spki' : 'pkcs8';
        const artifactBuffer = await crypto.subtle.exportKey(exportFormat, key);
        const artifactHex = Array.from(new Uint8Array(artifactBuffer)).map((b) => b.toString(16).padStart(2, '0')).join('');
        return { ok: true, artifactHex };
      } catch (e) {
        return { ok: false, message: String(e && e.message ? e.message : e) };
      }
    })()
  `;
}

function buildImportOnlyScript(artifactHex: string, role: 'public' | 'private', expectedNBase64Url: string, expectedEBase64Url: string): string {
  const argsJson = JSON.stringify({ artifactHex, role, expectedNBase64Url, expectedEBase64Url });
  return `
    (async () => {
      const args = ${argsJson};
      const hexToBytes = (hex) => {
        const out = new Uint8Array(new ArrayBuffer(hex.length / 2));
        for (let i = 0; i < out.length; i++) out[i] = parseInt(hex.substr(i * 2, 2), 16);
        return out;
      };
      try {
        const usage = args.role === 'public' ? 'encrypt' : 'decrypt';
        const importFormat = args.role === 'public' ? 'spki' : 'pkcs8';
        const key = await crypto.subtle.importKey(importFormat, hexToBytes(args.artifactHex), { name: 'RSA-OAEP', hash: 'SHA-256' }, true, [usage]);
        const jwk = await crypto.subtle.exportKey('jwk', key);
        return { ok: true, materialPreserved: jwk.n === args.expectedNBase64Url && jwk.e === args.expectedEBase64Url };
      } catch (e) {
        return { ok: false, message: String(e && e.message ? e.message : e) };
      }
    })()
  `;
}

export interface RsaSerExportOnlyResult {
  readonly backend: typeof CHROMIUM_WEBCRYPTO;
  readonly exportOk: boolean;
  readonly artifactHex?: string;
  readonly errorMessage?: string;
}
export interface RsaSerImportOnlyResult {
  readonly backend: typeof CHROMIUM_WEBCRYPTO;
  readonly importOk: boolean;
  readonly materialPreserved?: boolean;
  readonly errorMessage?: string;
}

export async function rsaSerExportChromium(material: RsaKeyHexMaterial): Promise<RsaSerExportOnlyResult> {
  const page = await getSharedChromiumPage();
  const result: { ok: boolean; artifactHex?: string; message?: string } = await page.evaluate(buildExportOnlyScript(toJwk(material), material.role));
  if (!result.ok) return { backend: CHROMIUM_WEBCRYPTO, exportOk: false, errorMessage: result.message };
  return { backend: CHROMIUM_WEBCRYPTO, exportOk: true, artifactHex: result.artifactHex };
}

export async function rsaSerImportChromium(role: 'public' | 'private', artifactHex: string, expected: RsaKeyHexMaterial): Promise<RsaSerImportOnlyResult> {
  const page = await getSharedChromiumPage();
  const result: { ok: boolean; materialPreserved?: boolean; message?: string } = await page.evaluate(
    buildImportOnlyScript(artifactHex, role, hexToBase64Url(expected.nHex), hexToBase64Url(expected.eHex)),
  );
  if (!result.ok) return { backend: CHROMIUM_WEBCRYPTO, importOk: false, errorMessage: result.message };
  return { backend: CHROMIUM_WEBCRYPTO, importOk: true, materialPreserved: result.materialPreserved };
}
