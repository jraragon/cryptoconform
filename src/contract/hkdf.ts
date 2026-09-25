import { checkClause } from './check-clause.js';

/**
 * HKDF-SHA-256 portable contract. Source: v0.6 HKDF clause table + D-068.
 *
 * hkdf.hash: common profile fixes HKDF-SHA-256 (HashLen = 32 octets).
 * hkdf.length: 1 <= L <= 255*HashLen = 8160 octets (D-068; upper bound RFC 5869,
 *              strict positive lower bound a portable-profile restriction).
 * hkdf.ikm / hkdf.salt / hkdf.info: opaque byte sequences, no implicit normalization.
 *              Absent salt (undefined here) is interpreted as HashLen zero octets
 *              per RFC 5869 -- distinct from an explicitly supplied zero-length salt.
 */

export const HASH_LEN = 32; // HKDF-SHA-256
export const MIN_L = 1;
export const MAX_L = 255 * HASH_LEN; // 8160, per D-068

export interface HkdfRequest {
  readonly ikm: Uint8Array;
  readonly salt: Uint8Array | undefined; // undefined = absent (RFC 5869 default), NOT the same as new Uint8Array(0)
  readonly info: Uint8Array;
  readonly length: number; // requested OKM length L, in octets
}

/**
 * Accept_C(request) for HKDF -- the contractual admission function (v0.6, mirrors
 * the RSA-ser/EC-ser Accept_C pattern). Must hold regardless of what any given
 * backend natively validates.
 */
export function validateHkdfRequest(req: HkdfRequest): void {
  checkClause(
    'hkdf.length',
    Number.isInteger(req.length) && req.length >= MIN_L && req.length <= MAX_L,
    'invalid_parameter',
    `L=${req.length} outside portable-profile bound ${MIN_L}<=L<=${MAX_L} (D-068)`,
  );
  checkClause('hkdf.ikm', req.ikm instanceof Uint8Array, 'invalid_parameter', 'ikm must be a byte sequence');
  checkClause('hkdf.info', req.info instanceof Uint8Array, 'invalid_parameter', 'info must be a byte sequence');
  checkClause(
    'hkdf.salt',
    req.salt === undefined || req.salt instanceof Uint8Array,
    'invalid_parameter',
    'salt must be absent or a byte sequence',
  );
}
