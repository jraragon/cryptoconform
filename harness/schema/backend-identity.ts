// M2.4.2 -- static materialization only. No behavior here.
// Source: Paper_4_Experimental_Harness v0.21, §10.1.

export interface BackendIdentity {
  readonly family: 'webcrypto' | 'chromium' | 'cryptopp' | 'bouncycastle';
  readonly apiVersion: string;
  readonly sourcePin: string;
  readonly apiSurface: string;
}

// Structural equality over the full tuple (family, apiVersion, sourcePin,
// apiSurface) -- never family alone. Pure function, no I/O.
export function backendIdentityEquals(a: BackendIdentity, b: BackendIdentity): boolean {
  return (
    a.family === b.family &&
    a.apiVersion === b.apiVersion &&
    a.sourcePin === b.sourcePin &&
    a.apiSurface === b.apiSurface
  );
}

// The three frozen, pinned realizations M1 executed against.
// §10.1: "Every cell below is scoped to the identical concrete realizations
// M1 executed against... keeping apiVersion and sourcePin as genuinely
// separate concepts."
export const CHROMIUM_WEBCRYPTO: BackendIdentity = Object.freeze({
  family: 'chromium',
  apiVersion: '151.0.7922.34',
  sourcePin: 'playwright-chromium-revision-1234',
  apiSurface: 'webcrypto-subtlecrypto',
});

// M2.4.7 finding: M1's own real adapter (src/adapters/webcrypto/hkdf.ts)
// runs against NODE's own webcrypto (OpenSSL-backed), confirmed by its own
// realizationId() comment ("not Chromium/BoringSSL") -- no Playwright
// reference exists anywhere in M1's HKDF adapter or its 131/131 test
// suite. This is a GENUINELY DIFFERENT realization from CHROMIUM_WEBCRYPTO
// above, which the capability manifests (M2.3) pin specifically to
// Playwright/Chromium. Kept as its own distinct BackendIdentity rather than
// silently treating "runs against webcrypto" as equivalent to "runs
// against Chromium" -- flagged explicitly for M2.5 (Phase A/B validation)
// to resolve: either wire real Playwright/Chromium execution, or correct
// the manifests' own pin to match what M1 actually executes against.
export const NODE_WEBCRYPTO_OPENSSL: BackendIdentity = Object.freeze({
  family: 'chromium', // same API surface family (WebCrypto/SubtleCrypto), NOT the same realization
  apiVersion: process.version,
  sourcePin: 'node-webcrypto-openssl-backed-not-chromium-boringssl',
  apiSurface: 'webcrypto-subtlecrypto',
});

export const CRYPTOPP: BackendIdentity = Object.freeze({
  family: 'cryptopp',
  apiVersion: 'master-post-8.9', // CRYPTOPP_VERSION macro reads 890 -- not authoritative, see v0.13 §2.1
  sourcePin: '782425901d36fe0944b16aae37801b8ec2fa9000',
  apiSurface: 'cryptopp-generic-api',
});

export const BOUNCY_CASTLE: BackendIdentity = Object.freeze({
  family: 'bouncycastle',
  apiVersion: 'bcprov-jdk18on-1.77',
  sourcePin: 'dabb98c24d72c9b9f585633d1df9c5cd58d9ad373d0cd681367e6a603a495d58',
  apiSurface: 'bc-java-lightweight-and-jca',
});

export const ALL_BACKENDS: readonly BackendIdentity[] = Object.freeze([
  CHROMIUM_WEBCRYPTO,
  CRYPTOPP,
  BOUNCY_CASTLE,
]);
