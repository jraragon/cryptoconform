// M2.5.2 -- EC-ser x real Chromium (Playwright).
// Same conceptual distinction as RSA-ser's own Chromium wiring: the
// portable canonical encoder (exportEcSer/importEcSer, src/contract/
// ec-ser.ts) is pure JS/DER logic with no WebCrypto dependency at all.
// What IS genuinely native here is WebCrypto's own spki/pkcs8 export/
// import round trip via a JWK-built CryptoKey, using ECDSA as the vehicle
// algorithm (P-256 key material is generic across ECDSA/ECDH, same
// principle as RSA-OAEP being the arbitrary vehicle for RSA-ser).

import { CHROMIUM_WEBCRYPTO } from '../schema/backend-identity.js';
import { getSharedChromiumPage } from './chromium-page.js';

export interface EcKeyHexMaterial {
  readonly role: 'public' | 'private';
  readonly xHex: string;
  readonly yHex: string;
  readonly dHex?: string;
}

function hexToBase64Url(hex: string): string {
  return Buffer.from(hex, 'hex').toString('base64url');
}

function toJwk(material: EcKeyHexMaterial): object {
  const base = { kty: 'EC', crv: 'P-256', x: hexToBase64Url(material.xHex), y: hexToBase64Url(material.yHex), ext: true };
  if (material.role === 'public') return base;
  return { ...base, d: hexToBase64Url(material.dHex ?? '') };
}

function buildRoundtripScript(jwk: object, role: 'public' | 'private'): string {
  const argsJson = JSON.stringify({ jwk, role });
  return `
    (async () => {
      const args = ${argsJson};
      try {
        const usage = args.role === 'public' ? ['verify'] : ['sign'];
        const key = await crypto.subtle.importKey('jwk', args.jwk, { name: 'ECDSA', namedCurve: 'P-256' }, true, usage);
        const exportFormat = args.role === 'public' ? 'spki' : 'pkcs8';
        const artifactBuffer = await crypto.subtle.exportKey(exportFormat, key);
        const artifactHex = Array.from(new Uint8Array(artifactBuffer)).map((b) => b.toString(16).padStart(2, '0')).join('');
        const reimportedKey = await crypto.subtle.importKey(exportFormat, artifactBuffer, { name: 'ECDSA', namedCurve: 'P-256' }, true, usage);
        const reimportedJwk = await crypto.subtle.exportKey('jwk', reimportedKey);
        return { ok: true, artifactHex, materialPreserved: reimportedJwk.x === args.jwk.x && reimportedJwk.y === args.jwk.y };
      } catch (e) {
        return { ok: false, message: String(e && e.message ? e.message : e) };
      }
    })()
  `;
}

export interface EcSerRoundtripResult {
  readonly backend: typeof CHROMIUM_WEBCRYPTO;
  readonly exportOk: boolean;
  readonly artifactHex?: string;
  readonly importOk?: boolean;
  readonly materialPreserved?: boolean;
  readonly errorMessage?: string;
}

export async function ecSerRoundtripChromium(material: EcKeyHexMaterial): Promise<EcSerRoundtripResult> {
  const page = await getSharedChromiumPage();
  const result: { ok: boolean; artifactHex?: string; materialPreserved?: boolean; message?: string } =
    await page.evaluate(buildRoundtripScript(toJwk(material), material.role));
  if (!result.ok) {
    return { backend: CHROMIUM_WEBCRYPTO, exportOk: false, errorMessage: result.message };
  }
  return { backend: CHROMIUM_WEBCRYPTO, exportOk: true, artifactHex: result.artifactHex, importOk: true, materialPreserved: result.materialPreserved };
}

// ---------------------------------------------------------------------
// M2.5.3.5 -- separate export/import for cross-provider Phase B. The
// artifact from exportP is handed LITERALLY to Chromium's own native
// importKey(spki/pkcs8, ...) -- never decoded and re-encoded in between.
// Echoes back recovered x/y/d as hex (never re-deriving V_scalar/V_curve/
// V_pair itself) so the caller can verify them independently via M1's own
// real p256.ts arithmetic.
// ---------------------------------------------------------------------

function hexFromBase64Url(b64u: string): string {
  return Buffer.from(b64u, 'base64url').toString('hex');
}

function buildExportOnlyScript(jwk: object, role: 'public' | 'private'): string {
  const argsJson = JSON.stringify({ jwk, role });
  return `
    (async () => {
      const args = ${argsJson};
      try {
        const usage = args.role === 'public' ? ['verify'] : ['sign'];
        const key = await crypto.subtle.importKey('jwk', args.jwk, { name: 'ECDSA', namedCurve: 'P-256' }, true, usage);
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

function buildImportOnlyScript(artifactHex: string, role: 'public' | 'private'): string {
  const argsJson = JSON.stringify({ artifactHex, role });
  return `
    (async () => {
      const args = ${argsJson};
      const hexToBytes = (hex) => {
        const out = new Uint8Array(new ArrayBuffer(hex.length / 2));
        for (let i = 0; i < out.length; i++) out[i] = parseInt(hex.substr(i * 2, 2), 16);
        return out;
      };
      try {
        const usage = args.role === 'public' ? ['verify'] : ['sign'];
        const importFormat = args.role === 'public' ? 'spki' : 'pkcs8';
        const key = await crypto.subtle.importKey(importFormat, hexToBytes(args.artifactHex), { name: 'ECDSA', namedCurve: 'P-256' }, true, usage);
        const jwk = await crypto.subtle.exportKey('jwk', key);
        return { ok: true, xBase64Url: jwk.x, yBase64Url: jwk.y, dBase64Url: args.role === 'private' ? jwk.d : null };
      } catch (e) {
        return { ok: false, message: String(e && e.message ? e.message : e) };
      }
    })()
  `;
}

export interface EcSerExportOnlyResult {
  readonly backend: typeof CHROMIUM_WEBCRYPTO;
  readonly exportOk: boolean;
  readonly artifactHex?: string;
  readonly errorMessage?: string;
}
export interface EcSerImportOnlyResult {
  readonly backend: typeof CHROMIUM_WEBCRYPTO;
  readonly importOk: boolean;
  readonly recoveredXHex?: string;
  readonly recoveredYHex?: string;
  readonly recoveredDHex?: string;
  readonly errorMessage?: string;
}

export async function ecSerExportChromium(material: EcKeyHexMaterial): Promise<EcSerExportOnlyResult> {
  const page = await getSharedChromiumPage();
  const result: { ok: boolean; artifactHex?: string; message?: string } = await page.evaluate(buildExportOnlyScript(toJwk(material), material.role));
  if (!result.ok) return { backend: CHROMIUM_WEBCRYPTO, exportOk: false, errorMessage: result.message };
  return { backend: CHROMIUM_WEBCRYPTO, exportOk: true, artifactHex: result.artifactHex };
}

export async function ecSerImportChromium(role: 'public' | 'private', artifactHex: string): Promise<EcSerImportOnlyResult> {
  const page = await getSharedChromiumPage();
  const result: { ok: boolean; xBase64Url?: string; yBase64Url?: string; dBase64Url?: string | null; message?: string } =
    await page.evaluate(buildImportOnlyScript(artifactHex, role));
  if (!result.ok) return { backend: CHROMIUM_WEBCRYPTO, importOk: false, errorMessage: result.message };
  return {
    backend: CHROMIUM_WEBCRYPTO, importOk: true,
    recoveredXHex: hexFromBase64Url(result.xBase64Url!), recoveredYHex: hexFromBase64Url(result.yBase64Url!),
    recoveredDHex: result.dBase64Url ? hexFromBase64Url(result.dBase64Url) : undefined,
  };
}
