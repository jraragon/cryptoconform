/**
 * Minimal DER primitives for RSA-ser. NOT a general ASN.1/BER library --
 * deliberately scoped to exactly what the frozen portable profile requires
 * (INTEGER, SEQUENCE, BIT STRING, OCTET STRING, NULL, and the single fixed
 * rsaEncryption OID), so this project controls the byte-level shape
 * directly rather than inheriting a third-party parser's own tolerances
 * (e.g. BER laxity) that the frozen design explicitly excludes (D-053).
 */

export const TAG = {
  INTEGER: 0x02,
  BIT_STRING: 0x03,
  OCTET_STRING: 0x04,
  NULL: 0x05,
  OID: 0x06,
  SEQUENCE: 0x30,
} as const;

/** DER encoding of OID 1.2.840.113549.1.1.1 (rsaEncryption) -- fixed, well-known bytes. */
export const RSA_ENCRYPTION_OID_CONTENT = Uint8Array.from([0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01]);

export class DerError extends Error {}

function encodeLength(len: number): Uint8Array {
  if (len < 0x80) return Uint8Array.from([len]);
  const bytes: number[] = [];
  let n = len;
  while (n > 0) {
    bytes.unshift(n & 0xff);
    n >>>= 8;
  }
  return Uint8Array.from([0x80 | bytes.length, ...bytes]);
}

export function encodeTlv(tag: number, content: Uint8Array): Uint8Array {
  const lenBytes = encodeLength(content.length);
  const out = new Uint8Array(1 + lenBytes.length + content.length);
  out[0] = tag;
  out.set(lenBytes, 1);
  out.set(content, 1 + lenBytes.length);
  return out;
}

export interface DecodedTlv {
  readonly tag: number;
  readonly content: Uint8Array;
  readonly nextOffset: number; // offset in the ORIGINAL buffer immediately after this TLV
}

/**
 * Decodes exactly one DER TLV starting at `offset`. Enforces DER (not BER)
 * length encoding: short form for len<128, minimal-length long form
 * otherwise (no leading zero bytes, no indefinite length 0x80). Throws
 * DerError on any violation -- this is the sole owner of the DER-vs-BER
 * distinction (rsa-ser.der-syntax), never re-checked downstream.
 */
export function decodeTlv(buf: Uint8Array, offset: number): DecodedTlv {
  if (offset >= buf.length) throw new DerError('unexpected end of buffer reading tag');
  const tag = buf[offset];
  if (tag === undefined || (tag & 0x1f) === 0x1f) {
    throw new DerError('multi-byte tags are not supported by this profile');
  }
  let pos = offset + 1;
  if (pos >= buf.length) throw new DerError('unexpected end of buffer reading length');
  const first = buf[pos];
  if (first === undefined) throw new DerError('unexpected end of buffer reading length');
  pos += 1;
  let len: number;
  if (first === 0x80) {
    throw new DerError('indefinite length (BER, not DER)');
  } else if (first < 0x80) {
    len = first;
  } else {
    const numLenBytes = first & 0x7f;
    if (numLenBytes === 0 || numLenBytes > 4) throw new DerError('unsupported long-form length');
    if (pos + numLenBytes > buf.length) throw new DerError('unexpected end of buffer reading long-form length');
    len = 0;
    for (let i = 0; i < numLenBytes; i++) {
      len = (len << 8) | (buf[pos + i] ?? 0);
    }
    pos += numLenBytes;
    if (len < 0x80) throw new DerError('non-minimal long-form length (BER, not DER)');
    if (numLenBytes > 1 && buf[pos - numLenBytes] === 0x00) throw new DerError('non-minimal long-form length (leading zero)');
  }
  if (pos + len > buf.length) throw new DerError('declared length exceeds remaining buffer');
  const content = buf.slice(pos, pos + len);
  return { tag, content, nextOffset: pos + len };
}

export function encodeInteger(value: bigint): Uint8Array {
  if (value < 0n) throw new DerError('negative INTEGER not supported by this profile (RSA values are all positive)');
  if (value === 0n) return encodeTlv(TAG.INTEGER, Uint8Array.from([0x00]));
  let hex = value.toString(16);
  if (hex.length % 2 !== 0) hex = '0' + hex;
  let bytes = Uint8Array.from(Buffer.from(hex, 'hex'));
  if ((bytes[0] ?? 0) & 0x80) {
    const padded = new Uint8Array(bytes.length + 1);
    padded.set(bytes, 1);
    bytes = padded;
  }
  return encodeTlv(TAG.INTEGER, bytes);
}

export function decodeInteger(tlv: DecodedTlv): bigint {
  if (tlv.tag !== TAG.INTEGER) throw new DerError(`expected INTEGER, got tag 0x${tlv.tag.toString(16)}`);
  const c = tlv.content;
  if (c.length === 0) throw new DerError('empty INTEGER content');
  if (c.length > 1) {
    const b0 = c[0] ?? 0;
    const b1 = c[1] ?? 0;
    if (b0 === 0x00 && (b1 & 0x80) === 0) throw new DerError('non-minimal INTEGER encoding (unnecessary leading 0x00)');
  }
  if ((c[0] ?? 0) & 0x80) throw new DerError('negative INTEGER not supported by this profile');
  return BigInt('0x' + Buffer.from(c).toString('hex'));
}

export function encodeBitStringWholeBytes(content: Uint8Array): Uint8Array {
  const out = new Uint8Array(content.length + 1);
  out[0] = 0x00;
  out.set(content, 1);
  return encodeTlv(TAG.BIT_STRING, out);
}

export function decodeBitStringWholeBytes(tlv: DecodedTlv): Uint8Array {
  if (tlv.tag !== TAG.BIT_STRING) throw new DerError(`expected BIT STRING, got tag 0x${tlv.tag.toString(16)}`);
  if (tlv.content.length === 0) throw new DerError('empty BIT STRING content (missing unused-bits octet)');
  if (tlv.content[0] !== 0x00) {
    throw new DerError('BIT STRING has non-zero unused bits; not a whole-byte DER object as this profile requires');
  }
  return tlv.content.slice(1);
}

export function encodeOctetString(content: Uint8Array): Uint8Array {
  return encodeTlv(TAG.OCTET_STRING, content);
}

export function decodeOctetString(tlv: DecodedTlv): Uint8Array {
  if (tlv.tag !== TAG.OCTET_STRING) throw new DerError(`expected OCTET STRING, got tag 0x${tlv.tag.toString(16)}`);
  return tlv.content;
}

export function encodeNull(): Uint8Array {
  return encodeTlv(TAG.NULL, new Uint8Array(0));
}

export function isNullTlv(tlv: DecodedTlv): boolean {
  return tlv.tag === TAG.NULL && tlv.content.length === 0;
}

export function encodeRsaEncryptionOid(): Uint8Array {
  return encodeTlv(TAG.OID, RSA_ENCRYPTION_OID_CONTENT);
}

export function isRsaEncryptionOidTlv(tlv: DecodedTlv): boolean {
  return (
    tlv.tag === TAG.OID &&
    tlv.content.length === RSA_ENCRYPTION_OID_CONTENT.length &&
    tlv.content.every((b, i) => b === RSA_ENCRYPTION_OID_CONTENT[i])
  );
}

export function encodeSequence(children: Uint8Array[]): Uint8Array {
  const totalLen = children.reduce((sum, c) => sum + c.length, 0);
  const content = new Uint8Array(totalLen);
  let off = 0;
  for (const c of children) {
    content.set(c, off);
    off += c.length;
  }
  return encodeTlv(TAG.SEQUENCE, content);
}

// --- EC-ser additions: two more fixed OIDs, and EXPLICIT context tags ---

/** DER encoding of OID 1.2.840.10045.2.1 (id-ecPublicKey). */
export const EC_PUBLIC_KEY_OID_CONTENT = Uint8Array.from([0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01]);

/** DER encoding of OID 1.2.840.10045.3.1.7 (secp256r1 / prime256v1). */
export const SECP256R1_OID_CONTENT = Uint8Array.from([0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07]);

export function encodeEcPublicKeyOid(): Uint8Array {
  return encodeTlv(TAG.OID, EC_PUBLIC_KEY_OID_CONTENT);
}

export function encodeSecp256r1Oid(): Uint8Array {
  return encodeTlv(TAG.OID, SECP256R1_OID_CONTENT);
}

function oidContentEquals(tlv: DecodedTlv, expected: Uint8Array): boolean {
  return tlv.tag === TAG.OID && tlv.content.length === expected.length && tlv.content.every((b, i) => b === expected[i]);
}

export function isEcPublicKeyOidTlv(tlv: DecodedTlv): boolean {
  return oidContentEquals(tlv, EC_PUBLIC_KEY_OID_CONTENT);
}

export function isSecp256r1OidTlv(tlv: DecodedTlv): boolean {
  return oidContentEquals(tlv, SECP256R1_OID_CONTENT);
}

/**
 * EXPLICIT context-specific constructed tags ([0], [1], ...), as used by
 * RFC 5915's ECPrivateKey.parameters[0] and .publicKey[1]. An EXPLICIT tag
 * wraps the FULL TLV of the underlying type as its content -- tag byte
 * 0xA0+n for constructed context-specific tag number n (DER: bit 5 set for
 * "constructed", bits 7-6 = "10" for context-specific class).
 */
export function encodeExplicitTag(tagNumber: number, innerTlvBytes: Uint8Array): Uint8Array {
  return encodeTlv(0xa0 + tagNumber, innerTlvBytes);
}

export function isExplicitTag(tlv: DecodedTlv, tagNumber: number): boolean {
  return tlv.tag === 0xa0 + tagNumber;
}

/**
 * Decodes a SEQUENCE's content into an ordered list of child TLVs.
 * `exactCount`, if given, enforces that exactly that many children are
 * present (used for our frozen 2- and 9-field structures) -- an extra
 * trailing child (e.g. PKCS#8 `attributes`) is rejected, an M1
 * implementation decision within D-055's spirit (the frozen design leaves
 * this specific nested-SEQUENCE question explicitly open; see rsa-ser.ts).
 */
export function decodeSequenceChildren(tlv: DecodedTlv, exactCount?: number): DecodedTlv[] {
  if (tlv.tag !== TAG.SEQUENCE) throw new DerError(`expected SEQUENCE, got tag 0x${tlv.tag.toString(16)}`);
  const children: DecodedTlv[] = [];
  let offset = 0;
  while (offset < tlv.content.length) {
    const child = decodeTlv(tlv.content, offset);
    children.push(child);
    offset = child.nextOffset;
  }
  if (exactCount !== undefined && children.length !== exactCount) {
    throw new DerError(`expected exactly ${exactCount} SEQUENCE elements, got ${children.length}`);
  }
  return children;
}
