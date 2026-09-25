// Bloque C2 -- execution dispatch.
//
// A single, total, fail-closed resolution from (operation, backend, role) to
// the M1 wiring that can execute it. Before this, backend selection existed
// only as adapter constants and factory functions scattered across twelve
// wiring modules, so any consumer had to know which shape each operation
// happened to expose -- and an unknown backend would have surfaced as a
// missing import or an undefined value rather than as a refusal.
//
// --- Why the registry is not uniform, and must not be forced to be --------
//
// The six operations genuinely do not expose the same execution shape, and
// flattening them would be a lie about the experiment rather than a tidy-up:
//
//   HKDF          one adapter per backend; a single derive call.
//   GCM/OAEP/PSS  TWO roles per backend (encrypt/decrypt, sign/verify), and
//                 for OAEP/PSS the adapter is parameterised by key material,
//                 so it is a FACTORY, not a constant.
//   RSA-ser/EC-ser  not ExecutionAdapters at all: export/import/roundtrip
//                 functions over hex material, because a serialization
//                 round trip has no single "execute this fixture" shape.
//
// So the registry records a DESCRIPTOR per (operation, backend, role) rather
// than pretending every entry is an ExecutionAdapter. What it guarantees is
// totality and refusal, which is what dispatch is for.

import { ALL_BACKENDS, BOUNCY_CASTLE, CHROMIUM_WEBCRYPTO, CRYPTOPP, backendIdentityEquals } from '../schema/backend-identity.js';
import type { BackendIdentity } from '../schema/backend-identity.js';
import type { OperationId } from '../schema/capability.js';

export class DispatchError extends Error {}

/**
 * The execution roles an operation exposes. Not a stylistic taxonomy: each
 * role is a distinct contractual call with its own request type, and
 * R_interop's producer/consumer split is expressed in exactly these terms.
 */
export type ExecutionRole =
  | 'derive'          // HKDF
  | 'encrypt' | 'decrypt'   // GCM, OAEP -- producer / consumer
  | 'sign' | 'verify'       // PSS -- producer / consumer
  | 'export' | 'import';    // RSA-ser, EC-ser -- producer / consumer

/** How the underlying M1 wiring is shaped, so a caller cannot guess wrong. */
export type WiringShape =
  | 'execution-adapter'         // a ready ExecutionAdapter constant
  | 'execution-adapter-factory' // needs key material before it is an adapter
  | 'roundtrip-function';       // export/import over hex material

export interface DispatchEntry {
  readonly operation: OperationId;
  readonly backend: BackendIdentity;
  readonly role: ExecutionRole;
  readonly shape: WiringShape;
  /** The exported symbol in its wiring module. Named, never guessed. */
  readonly symbol: string;
  readonly module: string;
}

const B = { chromium: CHROMIUM_WEBCRYPTO, cryptopp: CRYPTOPP, bc: BOUNCY_CASTLE } as const;

function e(
  operation: OperationId, backend: BackendIdentity, role: ExecutionRole,
  shape: WiringShape, symbol: string, module: string,
): DispatchEntry {
  return { operation, backend, role, shape, symbol, module };
}

/**
 * Total over (operation, backend, role) for the three frozen backends.
 *
 * "Total" is asserted rather than assumed: the gate recomputes the expected
 * cardinality from ROLES_BY_OPERATION x ALL_BACKENDS and refuses any gap, so
 * adding a backend or an operation cannot leave this table silently partial.
 */
export const ROLES_BY_OPERATION: Readonly<Record<OperationId, readonly ExecutionRole[]>> = Object.freeze({
  hkdf: ['derive'],
  gcm: ['encrypt', 'decrypt'],
  oaep: ['encrypt', 'decrypt'],
  pss: ['sign', 'verify'],
  'rsa-ser': ['export', 'import'],
  'ec-ser': ['export', 'import'],
});

export const DISPATCH_TABLE: readonly DispatchEntry[] = Object.freeze([
  // HKDF
  e('hkdf', B.chromium, 'derive', 'execution-adapter', 'HKDF_CHROMIUM_ADAPTER', 'hkdf-chromium-wiring'),
  e('hkdf', B.cryptopp, 'derive', 'execution-adapter', 'HKDF_CRYPTOPP_ADAPTER', 'hkdf-native-wiring'),
  e('hkdf', B.bc, 'derive', 'execution-adapter', 'HKDF_BOUNCYCASTLE_ADAPTER', 'hkdf-native-wiring'),
  // AES-GCM
  e('gcm', B.chromium, 'encrypt', 'execution-adapter', 'GCM_ENCRYPT_CHROMIUM_ADAPTER', 'gcm-chromium-wiring'),
  e('gcm', B.chromium, 'decrypt', 'execution-adapter', 'GCM_DECRYPT_CHROMIUM_ADAPTER', 'gcm-chromium-wiring'),
  e('gcm', B.cryptopp, 'encrypt', 'execution-adapter', 'GCM_ENCRYPT_CRYPTOPP_ADAPTER', 'gcm-native-wiring'),
  e('gcm', B.cryptopp, 'decrypt', 'execution-adapter', 'GCM_DECRYPT_CRYPTOPP_ADAPTER', 'gcm-native-wiring'),
  e('gcm', B.bc, 'encrypt', 'execution-adapter', 'GCM_ENCRYPT_BOUNCYCASTLE_ADAPTER', 'gcm-native-wiring'),
  e('gcm', B.bc, 'decrypt', 'execution-adapter', 'GCM_DECRYPT_BOUNCYCASTLE_ADAPTER', 'gcm-native-wiring'),
  // RSA-OAEP -- factories: the adapter does not exist until key material is bound
  e('oaep', B.chromium, 'encrypt', 'execution-adapter-factory', 'makeOaepEncryptChromiumAdapter', 'oaep-chromium-wiring'),
  e('oaep', B.chromium, 'decrypt', 'execution-adapter-factory', 'makeOaepDecryptChromiumAdapter', 'oaep-chromium-wiring'),
  e('oaep', B.cryptopp, 'encrypt', 'execution-adapter-factory', 'makeOaepEncryptCryptoppAdapter', 'oaep-native-wiring'),
  e('oaep', B.cryptopp, 'decrypt', 'execution-adapter-factory', 'makeOaepDecryptCryptoppAdapter', 'oaep-native-wiring'),
  e('oaep', B.bc, 'encrypt', 'execution-adapter-factory', 'makeOaepEncryptBouncyCastleAdapter', 'oaep-native-wiring'),
  e('oaep', B.bc, 'decrypt', 'execution-adapter-factory', 'makeOaepDecryptBouncyCastleAdapter', 'oaep-native-wiring'),
  // RSA-PSS
  e('pss', B.chromium, 'sign', 'execution-adapter-factory', 'makePssSignChromiumAdapter', 'pss-chromium-wiring'),
  e('pss', B.chromium, 'verify', 'execution-adapter-factory', 'makePssVerifyChromiumAdapter', 'pss-chromium-wiring'),
  e('pss', B.cryptopp, 'sign', 'execution-adapter-factory', 'makePssSignCryptoppAdapter', 'pss-native-wiring'),
  e('pss', B.cryptopp, 'verify', 'execution-adapter-factory', 'makePssVerifyCryptoppAdapter', 'pss-native-wiring'),
  e('pss', B.bc, 'sign', 'execution-adapter-factory', 'makePssSignBouncyCastleAdapter', 'pss-native-wiring'),
  e('pss', B.bc, 'verify', 'execution-adapter-factory', 'makePssVerifyBouncyCastleAdapter', 'pss-native-wiring'),
  // RSA key serialization
  e('rsa-ser', B.chromium, 'export', 'roundtrip-function', 'rsaSerExportChromium', 'rsa-ser-chromium-wiring'),
  e('rsa-ser', B.chromium, 'import', 'roundtrip-function', 'rsaSerImportChromium', 'rsa-ser-chromium-wiring'),
  e('rsa-ser', B.cryptopp, 'export', 'roundtrip-function', 'rsaSerExportCryptopp', 'rsa-ser-native-wiring'),
  e('rsa-ser', B.cryptopp, 'import', 'roundtrip-function', 'rsaSerImportCryptopp', 'rsa-ser-native-wiring'),
  e('rsa-ser', B.bc, 'export', 'roundtrip-function', 'rsaSerExportBouncyCastle', 'rsa-ser-native-wiring'),
  e('rsa-ser', B.bc, 'import', 'roundtrip-function', 'rsaSerImportBouncyCastle', 'rsa-ser-native-wiring'),
  // EC key serialization
  e('ec-ser', B.chromium, 'export', 'roundtrip-function', 'ecSerExportChromium', 'ec-ser-chromium-wiring'),
  e('ec-ser', B.chromium, 'import', 'roundtrip-function', 'ecSerImportChromium', 'ec-ser-chromium-wiring'),
  e('ec-ser', B.cryptopp, 'export', 'roundtrip-function', 'ecSerExportCryptopp', 'ec-ser-native-wiring'),
  e('ec-ser', B.cryptopp, 'import', 'roundtrip-function', 'ecSerImportCryptopp', 'ec-ser-native-wiring'),
  e('ec-ser', B.bc, 'export', 'roundtrip-function', 'ecSerExportBouncyCastle', 'ec-ser-native-wiring'),
  e('ec-ser', B.bc, 'import', 'roundtrip-function', 'ecSerImportBouncyCastle', 'ec-ser-native-wiring'),
]);

/**
 * Fail-closed on every axis. An unknown backend, an operation that does not
 * expose the role, or a gap in the table all REFUSE -- never return undefined
 * for a caller to coalesce away.
 */
export function resolveDispatch(
  operation: OperationId, backend: BackendIdentity, role: ExecutionRole,
): DispatchEntry {
  if (!ALL_BACKENDS.some((b) => backendIdentityEquals(b, backend))) {
    throw new DispatchError(
      `Unknown backend '${backend.family}'. Dispatch is total over the three frozen backends only; ` +
      'an unrecognised one is refused rather than silently unmatched.',
    );
  }
  const roles = ROLES_BY_OPERATION[operation];
  if (roles === undefined) throw new DispatchError(`Unknown operation '${operation}'.`);
  if (!roles.includes(role)) {
    throw new DispatchError(`Operation '${operation}' exposes no '${role}' role (it has: ${roles.join(', ')}).`);
  }
  const entry = DISPATCH_TABLE.find(
    (d) => d.operation === operation && backendIdentityEquals(d.backend, backend) && d.role === role,
  );
  if (entry === undefined) {
    throw new DispatchError(`No wiring registered for ${operation}/${backend.family}/${role} -- the table is incomplete.`);
  }
  return entry;
}

/** Producer and consumer roles, as R_interop's own directionality needs them. */
export function producerRole(operation: OperationId): ExecutionRole {
  const roles = ROLES_BY_OPERATION[operation];
  if (roles === undefined || roles.length !== 2) {
    throw new DispatchError(`Operation '${operation}' has no producer/consumer split.`);
  }
  return roles[0]!;
}
export function consumerRole(operation: OperationId): ExecutionRole {
  const roles = ROLES_BY_OPERATION[operation];
  if (roles === undefined || roles.length !== 2) {
    throw new DispatchError(`Operation '${operation}' has no producer/consumer split.`);
  }
  return roles[1]!;
}
