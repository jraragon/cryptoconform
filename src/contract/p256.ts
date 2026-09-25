/**
 * Pure P-256 (secp256r1) field and point arithmetic. NOT a general EC
 * library -- scoped exactly to what EC-ser's Accept_C needs: V_scalar
 * (1<=d<n), V_curve (Q on the curve), V_pair (Q=dG), and uncompressed
 * point encode/decode. Domain constants below were cross-checked against
 * multiple independent published sources (NIST SP 800-186 Appendix G.1.2,
 * SEC 2, several independent curve databases) AND verified computationally
 * in this session: p matches the closed-form NIST formula
 * 2^224*(2^32-1)+2^192+2^96-1 exactly, and G is confirmed to satisfy
 * Gy^2 = Gx^3 + a*Gx + b (mod p) directly -- not merely "multiple sources
 * agree" (which could share a common transcription error), a genuine
 * mathematical check.
 */

export const P256_P = 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFFn;
export const P256_A = P256_P - 3n; // NIST curves use a = p-3 by convention
export const P256_B = 0x5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604Bn;
export const P256_GX = 0x6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296n;
export const P256_GY = 0x4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5n;
export const P256_N = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551n;
export const P256_H = 1n; // cofactor -- confirmed domain constant (Design Freeze v0.6, sec:ec-ser-established)
export const P256_COORD_BYTES = 32;

export type AffinePoint = { readonly x: bigint; readonly y: bigint } | 'infinity';

function mod(x: bigint, m: bigint): bigint {
  const r = x % m;
  return r >= 0n ? r : r + m;
}

function modInverse(a: bigint, m: bigint): bigint {
  // Extended Euclidean algorithm.
  let [oldR, r] = [mod(a, m), m];
  let [oldS, s] = [1n, 0n];
  while (r !== 0n) {
    const q = oldR / r;
    [oldR, r] = [r, oldR - q * r];
    [oldS, s] = [s, oldS - q * s];
  }
  if (oldR !== 1n) throw new Error('modInverse: value is not invertible mod p (this should be unreachable for a valid field element)');
  return mod(oldS, m);
}

/** V_curve: Q != infinity, x,y in F_p (by construction of the caller), and y^2 = x^3+ax+b (mod p). */
export function isOnCurve(point: AffinePoint): boolean {
  if (point === 'infinity') return false; // the point at infinity is explicitly excluded by V_curve's own definition (Design Freeze v0.6: Q != O)
  const { x, y } = point;
  if (x < 0n || x >= P256_P || y < 0n || y >= P256_P) return false;
  const lhs = mod(y * y, P256_P);
  const rhs = mod(mod(x * x, P256_P) * x + P256_A * x + P256_B, P256_P);
  return lhs === rhs;
}

function pointAdd(p1: AffinePoint, p2: AffinePoint): AffinePoint {
  if (p1 === 'infinity') return p2;
  if (p2 === 'infinity') return p1;
  if (p1.x === p2.x) {
    if (mod(p1.y + p2.y, P256_P) === 0n) return 'infinity'; // P + (-P) = O
    return pointDouble(p1);
  }
  const lambda = mod((p2.y - p1.y) * modInverse(mod(p2.x - p1.x, P256_P), P256_P), P256_P);
  const x3 = mod(lambda * lambda - p1.x - p2.x, P256_P);
  const y3 = mod(lambda * (p1.x - x3) - p1.y, P256_P);
  return { x: x3, y: y3 };
}

function pointDouble(p1: AffinePoint): AffinePoint {
  if (p1 === 'infinity') return 'infinity';
  if (p1.y === 0n) return 'infinity';
  const lambda = mod((3n * p1.x * p1.x + P256_A) * modInverse(mod(2n * p1.y, P256_P), P256_P), P256_P);
  const x3 = mod(lambda * lambda - 2n * p1.x, P256_P);
  const y3 = mod(lambda * (p1.x - x3) - p1.y, P256_P);
  return { x: x3, y: y3 };
}

/**
 * Scalar multiplication d*G via double-and-add, MSB-to-LSB. Used
 * specifically to compute Q:=dG for V_pair checks and for adapter-side
 * public-key reconstruction (mirroring what BC's own native writer already
 * does, and what Crypto++'s adapter must do since its native writer omits
 * publicKey[1] -- Design Freeze v0.6, sec:ec-ser-portable).
 *
 * NOT constant-time. This is a conformance/contract-checking utility, not
 * a production signing/derivation primitive -- the frozen design's own
 * scope for this operation is import/export/validation, not ECDSA/ECDH,
 * so no side-channel obligation applies here.
 */
export function scalarMultiplyG(d: bigint): AffinePoint {
  return scalarMultiply(d, { x: P256_GX, y: P256_GY });
}

export function scalarMultiply(d: bigint, point: AffinePoint): AffinePoint {
  if (point === 'infinity' || d === 0n) return 'infinity';
  let result: AffinePoint = 'infinity';
  let addend: AffinePoint = point;
  let k = d;
  while (k > 0n) {
    if (k & 1n) result = pointAdd(result, addend);
    addend = pointDouble(addend);
    k >>= 1n;
  }
  return result;
}

/** V_pair: Q = dG. Computed via scalar multiplication, not assumed. */
export function isPair(d: bigint, q: AffinePoint): boolean {
  const computed = scalarMultiplyG(d);
  if (computed === 'infinity' || q === 'infinity') return false;
  return computed.x === q.x && computed.y === q.y;
}

/** V_scalar: 1 <= d < n. */
export function isValidScalar(d: bigint): boolean {
  return d >= 1n && d < P256_N;
}

/** Uncompressed SEC 1 point encoding: 04 || X_32 || Y_32, 65 bytes total. */
export function encodeUncompressedPoint(point: AffinePoint): Uint8Array {
  if (point === 'infinity') throw new Error('cannot encode the point at infinity as an uncompressed SEC1 point');
  const out = new Uint8Array(1 + 2 * P256_COORD_BYTES);
  out[0] = 0x04;
  const xBytes = bigIntToFixedBytes(point.x, P256_COORD_BYTES);
  const yBytes = bigIntToFixedBytes(point.y, P256_COORD_BYTES);
  out.set(xBytes, 1);
  out.set(yBytes, 1 + P256_COORD_BYTES);
  return out;
}

/**
 * Decodes ONLY the uncompressed form (leading 0x04) -- the portable
 * profile's sole admitted point form (Design Freeze v0.6, sec:ec-ser-portable:
 * "No compressed/hybrid/explicit-parameters/JWK"). Compressed (0x02/0x03)
 * and hybrid forms are deliberately NOT handled here; a request presenting
 * them is a rsa-ser.public.point-equivalent (ec-ser.public.point)
 * violation, classified by the caller, not silently accepted by this
 * decoder falling back to some default.
 */
export function decodeUncompressedPoint(bytes: Uint8Array): AffinePoint {
  if (bytes.length !== 1 + 2 * P256_COORD_BYTES) {
    throw new Error(`uncompressed point must be exactly ${1 + 2 * P256_COORD_BYTES} bytes, got ${bytes.length}`);
  }
  if (bytes[0] !== 0x04) {
    throw new Error(`expected uncompressed point form (0x04), got leading octet 0x${(bytes[0] ?? 0).toString(16)}`);
  }
  const x = bytesToBigInt(bytes.slice(1, 1 + P256_COORD_BYTES));
  const y = bytesToBigInt(bytes.slice(1 + P256_COORD_BYTES));
  return { x, y };
}

function bigIntToFixedBytes(value: bigint, length: number): Uint8Array {
  let hex = value.toString(16);
  if (hex.length % 2 !== 0) hex = '0' + hex;
  const bytes = Uint8Array.from(Buffer.from(hex, 'hex'));
  if (bytes.length > length) throw new Error(`value does not fit in ${length} bytes`);
  const out = new Uint8Array(length);
  out.set(bytes, length - bytes.length);
  return out;
}

function bytesToBigInt(bytes: Uint8Array): bigint {
  return BigInt('0x' + Buffer.from(bytes).toString('hex'));
}
