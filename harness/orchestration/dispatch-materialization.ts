// M3.7.2 -- dispatch materialization.
//
// The one mechanical step the frozen dispatch table left open: it records a
// SYMBOL and a MODULE as strings, and something has to turn those into the
// actual wiring. That is a LOOKUP, and this module must never become anything
// more.
//
//     dispatch table  =  frozen instrument semantics  (what exists, and what is refused)
//     this module     =  lookup only                  (how to reach it)
//
// It is derived FROM the frozen table, not written alongside it: every entry
// here must correspond to a DISPATCH_TABLE entry, and every table entry must be
// materializable. A gate asserts both directions over all 33, so this cannot
// silently become a second dispatch with its own opinions -- which is exactly
// how a lookup turns into a decision table.

import { DISPATCH_TABLE, DispatchError, resolveDispatch, type DispatchEntry, type ExecutionRole } from './dispatch.js';
import type { BackendIdentity } from '../schema/backend-identity.js';
import type { OperationId } from '../schema/capability.js';

import { HKDF_CHROMIUM_ADAPTER } from './hkdf-chromium-wiring.js';
import { HKDF_CRYPTOPP_ADAPTER, HKDF_BOUNCYCASTLE_ADAPTER } from './hkdf-native-wiring.js';
import { GCM_ENCRYPT_CHROMIUM_ADAPTER, GCM_DECRYPT_CHROMIUM_ADAPTER } from './gcm-chromium-wiring.js';
import {
  GCM_ENCRYPT_CRYPTOPP_ADAPTER, GCM_DECRYPT_CRYPTOPP_ADAPTER,
  GCM_ENCRYPT_BOUNCYCASTLE_ADAPTER, GCM_DECRYPT_BOUNCYCASTLE_ADAPTER,
} from './gcm-native-wiring.js';
import { makeOaepEncryptChromiumAdapter, makeOaepDecryptChromiumAdapter } from './oaep-chromium-wiring.js';
import {
  makeOaepEncryptCryptoppAdapter, makeOaepDecryptCryptoppAdapter,
  makeOaepEncryptBouncyCastleAdapter, makeOaepDecryptBouncyCastleAdapter,
} from './oaep-native-wiring.js';
import { makePssSignChromiumAdapter, makePssVerifyChromiumAdapter } from './pss-chromium-wiring.js';
import {
  makePssSignCryptoppAdapter, makePssVerifyCryptoppAdapter,
  makePssSignBouncyCastleAdapter, makePssVerifyBouncyCastleAdapter,
} from './pss-native-wiring.js';
import { rsaSerExportChromium, rsaSerImportChromium } from './rsa-ser-chromium-wiring.js';
import {
  rsaSerExportCryptopp, rsaSerImportCryptopp,
  rsaSerExportBouncyCastle, rsaSerImportBouncyCastle,
} from './rsa-ser-native-wiring.js';
import { ecSerExportChromium, ecSerImportChromium } from './ec-ser-chromium-wiring.js';
import {
  ecSerExportCryptopp, ecSerImportCryptopp,
  ecSerExportBouncyCastle, ecSerImportBouncyCastle,
} from './ec-ser-native-wiring.js';

export class MaterializationError extends Error {}

/* eslint-disable @typescript-eslint/no-explicit-any */
/**
 * symbol -> the exported value. Keyed by the SYMBOL NAME the frozen dispatch
 * table records, so a typo cannot silently bind the wrong wiring: the gate
 * checks this map's keys against the table's own symbols, both ways.
 */
const BY_SYMBOL: Readonly<Record<string, unknown>> = Object.freeze({
  HKDF_CHROMIUM_ADAPTER, HKDF_CRYPTOPP_ADAPTER, HKDF_BOUNCYCASTLE_ADAPTER,
  GCM_ENCRYPT_CHROMIUM_ADAPTER, GCM_DECRYPT_CHROMIUM_ADAPTER,
  GCM_ENCRYPT_CRYPTOPP_ADAPTER, GCM_DECRYPT_CRYPTOPP_ADAPTER,
  GCM_ENCRYPT_BOUNCYCASTLE_ADAPTER, GCM_DECRYPT_BOUNCYCASTLE_ADAPTER,
  makeOaepEncryptChromiumAdapter, makeOaepDecryptChromiumAdapter,
  makeOaepEncryptCryptoppAdapter, makeOaepDecryptCryptoppAdapter,
  makeOaepEncryptBouncyCastleAdapter, makeOaepDecryptBouncyCastleAdapter,
  makePssSignChromiumAdapter, makePssVerifyChromiumAdapter,
  makePssSignCryptoppAdapter, makePssVerifyCryptoppAdapter,
  makePssSignBouncyCastleAdapter, makePssVerifyBouncyCastleAdapter,
  rsaSerExportChromium, rsaSerImportChromium,
  rsaSerExportCryptopp, rsaSerImportCryptopp,
  rsaSerExportBouncyCastle, rsaSerImportBouncyCastle,
  ecSerExportChromium, ecSerImportChromium,
  ecSerExportCryptopp, ecSerImportCryptopp,
  ecSerExportBouncyCastle, ecSerImportBouncyCastle,
});
/* eslint-enable @typescript-eslint/no-explicit-any */

export interface MaterializedDispatch {
  readonly entry: DispatchEntry;
  /** The exported value itself. Its SHAPE is entry.shape, never guessed. */
  readonly wiring: unknown;
}

/**
 * Fail-closed on both axes: an unresolvable (operation, backend, role) is
 * refused by the frozen dispatch, and a symbol with no materialization is
 * refused here. Neither returns undefined for a caller to coalesce away.
 */
export function materializeDispatch(
  operation: OperationId, backend: BackendIdentity, role: ExecutionRole,
): MaterializedDispatch {
  const entry = resolveDispatch(operation, backend, role);
  const wiring = BY_SYMBOL[entry.symbol];
  if (wiring === undefined) {
    throw new MaterializationError(
      `Dispatch entry ${entry.operation}/${entry.backend.family}/${entry.role} names symbol '${entry.symbol}', ` +
      'which has no materialization. Refusing rather than binding nothing.',
    );
  }
  return { entry, wiring };
}

/** Every symbol this module can materialize. For the totality gate. */
export function materializableSymbols(): readonly string[] {
  return Object.keys(BY_SYMBOL);
}

/** Every symbol the frozen dispatch table names. For the same gate. */
export function dispatchSymbols(): readonly string[] {
  return DISPATCH_TABLE.map((d) => d.symbol);
}

export { DispatchError };
