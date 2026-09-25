// Plain-JS (no TS transform) Chromium/WebCrypto harness for EC-ser.
//
// WHY PLAIN .mjs, NOT .ts: Playwright's page.evaluate() serializes the
// callback via .toString() and re-parses it inside the browser's own JS
// context, with NO access to the outer Node process's scope. tsx/esbuild's
// TS-to-JS transform injects a `__name(fn, "identifier")` helper call
// around function expressions in this project's tsconfig -- that helper
// exists in the COMPILED Node module's scope but not inside the
// page-context re-parse, causing "ReferenceError: __name is not defined"
// at runtime (confirmed empirically this session). Plain .mjs bypasses
// the transform entirely, so evaluate() callbacks serialize cleanly.
//
// Chromium build actually used: pinned via Playwright's chromium.launch()
// -- confirmed this session as Chrome for Testing 151.0.7922.34
// (Playwright chromium build v1234). This is a genuinely different
// runtime from Node's own node:crypto webcrypto (used for HKDF/GCM/OAEP/
// PSS/RSA-ser) -- EC-ser is explicitly compared against Chromium/BoringSSL
// specifically, per the Design Freeze's own EC-ser inventory (W3C
// webcrypto#356 and the Chromium ec.cc source trace both concern this
// runtime, not Node's).

import { chromium } from 'playwright';
import http from 'node:http';

export class ChromiumEcHarness {
  #browser;
  #page;
  #server;
  #port;

  async start() {
    this.#server = http.createServer((_req, res) => res.end('<html><body>ec-ser harness</body></html>'));
    this.#port = 18770 + Math.floor(Math.random() * 1000);
    await new Promise((resolve) => this.#server.listen(this.#port, '127.0.0.1', resolve));
    this.#browser = await chromium.launch();
    this.#page = await this.#browser.newPage();
    // 127.0.0.1 is a "potentially trustworthy origin" per the Secure
    // Contexts spec even over plain HTTP, so window.crypto.subtle is
    // exposed here -- confirmed empirically (it is NOT exposed on a bare
    // about:blank page in this Playwright/Chromium build).
    await this.#page.goto(`http://127.0.0.1:${this.#port}/`);
  }

  async stop() {
    await this.#browser?.close();
    this.#server?.close();
  }

  async version() {
    return this.#browser.version();
  }

  /**
   * Generates a real Chromium-native P-256 key pair and returns its JWK
   * components (as hex) plus the genuine native SPKI/PKCS8 exports (as
   * hex) -- ground truth for both the adapter's interop checks and the
   * eventual R_byte cross-provider comparison.
   */
  async generateKeyPair() {
    return this.#page.evaluate(async () => {
      function toHex(buf) {
        return Array.from(new Uint8Array(buf)).map((b) => b.toString(16).padStart(2, '0')).join('');
      }
      function b64uToHex(s) {
        const b64 = s.replace(/-/g, '+').replace(/_/g, '/') + '=='.slice(0, (4 - (s.length % 4)) % 4);
        const bin = atob(b64);
        let hex = '';
        for (let i = 0; i < bin.length; i++) hex += bin.charCodeAt(i).toString(16).padStart(2, '0');
        return hex;
      }
      const kp = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify']);
      const jwk = await crypto.subtle.exportKey('jwk', kp.privateKey);
      const spki = await crypto.subtle.exportKey('spki', kp.publicKey);
      const pkcs8 = await crypto.subtle.exportKey('pkcs8', kp.privateKey);
      return {
        dHex: b64uToHex(jwk.d),
        xHex: b64uToHex(jwk.x),
        yHex: b64uToHex(jwk.y),
        nativeSpkiHex: toHex(spki),
        nativePkcs8Hex: toHex(pkcs8),
      };
    });
  }

  /** Attempts a native import of raw artifact bytes (given as hex). Returns {accepted, errorName?, errorMessage?}. Never touches our own Accept_C -- purely the native surface. */
  async nativeImport(formatHex, role) {
    const { format, hex } = formatHex;
    return this.#page.evaluate(
      async ({ format, hex, role }) => {
        function fromHex(h) {
          const bytes = new Uint8Array(h.length / 2);
          for (let i = 0; i < h.length; i += 2) bytes[i / 2] = parseInt(h.substr(i, 2), 16);
          return bytes.buffer;
        }
        try {
          const usages = role === 'public' ? ['verify'] : ['sign'];
          await crypto.subtle.importKey(format, fromHex(hex), { name: 'ECDSA', namedCurve: 'P-256' }, true, usages);
          return { accepted: true };
        } catch (e) {
          return { accepted: false, errorName: e.name, errorMessage: e.message };
        }
      },
      { format, hex, role },
    );
  }

  /** Native import followed by native export -- the full native round trip, for R_byte/R_ser native-only comparisons. Returns hex of the re-exported artifact, or a rejection. */
  async nativeImportThenExport(formatHex, role) {
    const { format, hex } = formatHex;
    return this.#page.evaluate(
      async ({ format, hex, role }) => {
        function fromHex(h) {
          const bytes = new Uint8Array(h.length / 2);
          for (let i = 0; i < h.length; i += 2) bytes[i / 2] = parseInt(h.substr(i, 2), 16);
          return bytes.buffer;
        }
        function toHex(buf) {
          return Array.from(new Uint8Array(buf)).map((b) => b.toString(16).padStart(2, '0')).join('');
        }
        try {
          const usages = role === 'public' ? ['verify'] : ['sign'];
          const key = await crypto.subtle.importKey(format, fromHex(hex), { name: 'ECDSA', namedCurve: 'P-256' }, true, usages);
          const reExported = await crypto.subtle.exportKey(format, key);
          return { accepted: true, hex: toHex(reExported) };
        } catch (e) {
          return { accepted: false, errorName: e.name, errorMessage: e.message };
        }
      },
      { format, hex, role },
    );
  }

  /** Native export of an arbitrary (already-known) public point, via a fresh CryptoKey built through JWK -- not through our own DER encoder. */
  async nativeExportSpkiFor(xHex, yHex) {
    return this.#page.evaluate(
      async ({ xHex, yHex }) => {
        function toHex(buf) {
          return Array.from(new Uint8Array(buf)).map((b) => b.toString(16).padStart(2, '0')).join('');
        }
        function hexToB64u(hex) {
          const bytes = new Uint8Array(hex.length / 2);
          for (let i = 0; i < hex.length; i += 2) bytes[i / 2] = parseInt(hex.substr(i, 2), 16);
          let bin = '';
          for (const b of bytes) bin += String.fromCharCode(b);
          return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
        }
        const jwk = { kty: 'EC', crv: 'P-256', x: hexToB64u(xHex.padStart(64, '0')), y: hexToB64u(yHex.padStart(64, '0')), ext: true };
        const key = await crypto.subtle.importKey('jwk', jwk, { name: 'ECDSA', namedCurve: 'P-256' }, true, ['verify']);
        const spki = await crypto.subtle.exportKey('spki', key);
        return toHex(spki);
      },
      { xHex, yHex },
    );
  }

  /** Native export of an arbitrary (d,x,y) private material, via a fresh CryptoKey built through JWK. */
  async nativeExportPkcs8For(dHex, xHex, yHex) {
    return this.#page.evaluate(
      async ({ dHex, xHex, yHex }) => {
        function toHex(buf) {
          return Array.from(new Uint8Array(buf)).map((b) => b.toString(16).padStart(2, '0')).join('');
        }
        function hexToB64u(hex) {
          const bytes = new Uint8Array(hex.length / 2);
          for (let i = 0; i < hex.length; i += 2) bytes[i / 2] = parseInt(hex.substr(i, 2), 16);
          let bin = '';
          for (const b of bytes) bin += String.fromCharCode(b);
          return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
        }
        const jwk = {
          kty: 'EC',
          crv: 'P-256',
          d: hexToB64u(dHex.padStart(64, '0')),
          x: hexToB64u(xHex.padStart(64, '0')),
          y: hexToB64u(yHex.padStart(64, '0')),
          ext: true,
        };
        const key = await crypto.subtle.importKey('jwk', jwk, { name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign']);
        const pkcs8 = await crypto.subtle.exportKey('pkcs8', key);
        return toHex(pkcs8);
      },
      { dHex, xHex, yHex },
    );
  }

  /** Native import of arbitrary artifact bytes, returning the recovered material (x,y for public; d for private, read back via a JWK export of the imported key) or a rejection. */
  async nativeImportRecover(formatHex, role) {
    const { format, hex } = formatHex;
    return this.#page.evaluate(
      async ({ format, hex, role }) => {
        function fromHex(h) {
          const bytes = new Uint8Array(h.length / 2);
          for (let i = 0; i < h.length; i += 2) bytes[i / 2] = parseInt(h.substr(i, 2), 16);
          return bytes.buffer;
        }
        function b64uToHex(s) {
          const b64 = s.replace(/-/g, '+').replace(/_/g, '/') + '=='.slice(0, (4 - (s.length % 4)) % 4);
          const bin = atob(b64);
          let hex = '';
          for (let i = 0; i < bin.length; i++) hex += bin.charCodeAt(i).toString(16).padStart(2, '0');
          return hex;
        }
        try {
          const usages = role === 'public' ? ['verify'] : ['sign'];
          const key = await crypto.subtle.importKey(format, fromHex(hex), { name: 'ECDSA', namedCurve: 'P-256' }, true, usages);
          const jwk = await crypto.subtle.exportKey('jwk', key);
          if (role === 'public') return { accepted: true, xHex: b64uToHex(jwk.x), yHex: b64uToHex(jwk.y) };
          return { accepted: true, dHex: b64uToHex(jwk.d) };
        } catch (e) {
          return { accepted: false, errorName: e.name, errorMessage: e.message };
        }
      },
      { format, hex, role },
    );
  }
}
