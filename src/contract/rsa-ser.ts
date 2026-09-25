import { checkClause } from './check-clause.js';
import {
  DerError,
  decodeTlv,
  decodeSequenceChildren,
  decodeInteger,
  decodeBitStringWholeBytes,
  decodeOctetString,
  isNullTlv,
  isRsaEncryptionOidTlv,
  encodeInteger,
  encodeSequence,
  encodeBitStringWholeBytes,
  encodeOctetString,
  encodeNull,
  encodeRsaEncryptionOid,
  type DecodedTlv,
} from './der.js';

/**
 * RSA Key Serialization portable contract. Source: Design Freeze v0.6,
 * sec:rsa-ser through sec:rsa-ser-clauses (D-053 through D-057).
 *
 * Three layers, kept explicitly distinct: RSA key material -> ASN.1
 * container -> DER encoding.
 *
 * CRITICAL asymmetries this file must respect:
 *   - Import is untrusted-artifact classification (4 SDK error classes,
 *     D-056); export is a postcondition on already-admitted material (only
 *     `unsupported` is a legal export outcome).
 *   - C_math is role-asymmetric (D-055): private keys get FULL RFC 8017
 *     validity (the CRT material exposes p,q directly); public keys get
 *     only the cheap, directly-observable NECESSARY conditions (n>=15, n
 *     odd, 3<=e<=n-1, e odd) -- NOT full compositeness/primality testing.
 *   - Multi-prime RSA is outside the portable profile entirely (D-053) --
 *     this module only ever represents two-prime (version=0) material.
 */

export interface RsaPublicMaterial {
  readonly role: 'public';
  readonly n: bigint;
  readonly e: bigint;
}

export interface RsaPrivateMaterial {
  readonly role: 'private';
  readonly n: bigint;
  readonly e: bigint;
  readonly d: bigint;
  readonly p: bigint;
  readonly q: bigint;
  readonly dP: bigint;
  readonly dQ: bigint;
  readonly qInv: bigint;
}

export type RsaKeyMaterial = RsaPublicMaterial | RsaPrivateMaterial;

// ---------------------------------------------------------------------------
// Layer 1: RSA key material DER (RFC 8017 Appendix A.1)
// ---------------------------------------------------------------------------

function encodeRsaPublicKey(n: bigint, e: bigint): Uint8Array {
  return encodeSequence([encodeInteger(n), encodeInteger(e)]);
}

function decodeRsaPublicKey(tlv: DecodedTlv): { n: bigint; e: bigint } {
  const children = decodeSequenceChildren(tlv, 2);
  const n = decodeInteger(children[0]!);
  const e = decodeInteger(children[1]!);
  return { n, e };
}

function encodeRsaPrivateKeyV0(m: RsaPrivateMaterial): Uint8Array {
  return encodeSequence([
    encodeInteger(0n),
    encodeInteger(m.n),
    encodeInteger(m.e),
    encodeInteger(m.d),
    encodeInteger(m.p),
    encodeInteger(m.q),
    encodeInteger(m.dP),
    encodeInteger(m.dQ),
    encodeInteger(m.qInv),
  ]);
}

function decodeRsaPrivateKeyV0(tlv: DecodedTlv): RsaPrivateMaterial | undefined {
  const children = decodeSequenceChildren(tlv);
  if (children.length !== 9) return undefined;
  const version = decodeInteger(children[0]!);
  if (version !== 0n) return undefined;
  return {
    role: 'private',
    n: decodeInteger(children[1]!),
    e: decodeInteger(children[2]!),
    d: decodeInteger(children[3]!),
    p: decodeInteger(children[4]!),
    q: decodeInteger(children[5]!),
    dP: decodeInteger(children[6]!),
    dQ: decodeInteger(children[7]!),
    qInv: decodeInteger(children[8]!),
  };
}

// ---------------------------------------------------------------------------
// Layer 2/3: containers and DER framing
// ---------------------------------------------------------------------------

function encodeAlgorithmIdentifier(): Uint8Array {
  return encodeSequence([encodeRsaEncryptionOid(), encodeNull()]);
}

function decodeAlgorithmIdentifier(tlv: DecodedTlv): { oidOk: boolean; paramsOk: boolean } {
  const children = decodeSequenceChildren(tlv);
  if (children.length < 1 || children.length > 2) {
    return { oidOk: false, paramsOk: false };
  }
  const oidOk = isRsaEncryptionOidTlv(children[0]!);
  const paramsOk = children.length === 1 || isNullTlv(children[1]!);
  return { oidOk, paramsOk };
}

export function encodeSpki(m: RsaPublicMaterial): Uint8Array {
  const inner = encodeRsaPublicKey(m.n, m.e);
  return encodeSequence([encodeAlgorithmIdentifier(), encodeBitStringWholeBytes(inner)]);
}

export function encodePrivateKeyInfo(m: RsaPrivateMaterial): Uint8Array {
  const inner = encodeRsaPrivateKeyV0(m);
  return encodeSequence([encodeInteger(0n), encodeAlgorithmIdentifier(), encodeOctetString(inner)]);
}

export function exportRsaSer(material: RsaKeyMaterial): Uint8Array {
  return material.role === 'public' ? encodeSpki(material) : encodePrivateKeyInfo(material);
}

interface ParsedContainer {
  readonly containerRole: 'public' | 'private';
  readonly algIdTlv: DecodedTlv;
  readonly innerTlv: DecodedTlv;
}

function parseContainerStructural(artifact: Uint8Array): ParsedContainer {
  let outer: DecodedTlv;
  try {
    outer = decodeTlv(artifact, 0);
  } catch (err) {
    checkClause('rsa-ser.der-syntax', false, 'malformed_artifact', `DER parse failed: ${err instanceof Error ? err.message : String(err)}`);
    throw err;
  }
  checkClause(
    'rsa-ser.exact-consumption',
    outer.nextOffset === artifact.length,
    'malformed_artifact',
    `trailing bytes after the top-level DER object (${artifact.length - outer.nextOffset} byte(s) unconsumed)`,
  );

  let children: DecodedTlv[];
  try {
    children = decodeSequenceChildren(outer);
  } catch (err) {
    checkClause('rsa-ser.der-syntax', false, 'malformed_artifact', `outer SEQUENCE parse failed: ${err instanceof Error ? err.message : String(err)}`);
    throw err;
  }

  if (children.length === 2 && children[1]!.tag === 0x03) {
    return { containerRole: 'public', algIdTlv: children[0]!, innerTlv: children[1]! };
  }
  if (children.length === 3 && children[0]!.tag === 0x02 && children[2]!.tag === 0x04) {
    let version: bigint;
    try {
      version = decodeInteger(children[0]!);
    } catch {
      checkClause('rsa-ser.container', false, 'malformed_artifact', 'PrivateKeyInfo version field is not a valid INTEGER');
      throw new DerError('unreachable');
    }
    checkClause(
      'rsa-ser.container',
      version === 0n,
      'malformed_artifact',
      `PrivateKeyInfo version=${version}, only version=0 (two-prime) instantiates the portable container shape`,
    );
    return { containerRole: 'private', algIdTlv: children[1]!, innerTlv: children[2]! };
  }

  checkClause('rsa-ser.container', false, 'malformed_artifact', 'valid DER instantiating neither the SPKI nor the PrivateKeyInfo container shape');
  throw new DerError('unreachable');
}

// ---------------------------------------------------------------------------
// C_math: RSA mathematical validity (RFC 8017 SS3.1-3.2, exact formulas)
// ---------------------------------------------------------------------------

function isProbablePrime(n: bigint): boolean {
  if (n < 2n) return false;
  for (const p of [2n, 3n, 5n, 7n, 11n, 13n, 17n, 19n, 23n, 29n, 31n, 37n]) {
    if (n === p) return true;
    if (n % p === 0n) return false;
  }
  let d = n - 1n;
  let r = 0n;
  while (d % 2n === 0n) {
    d /= 2n;
    r += 1n;
  }
  const modPow = (base: bigint, exp: bigint, mod: bigint): bigint => {
    let result = 1n;
    let b = base % mod;
    let e = exp;
    while (e > 0n) {
      if (e & 1n) result = (result * b) % mod;
      b = (b * b) % mod;
      e >>= 1n;
    }
    return result;
  };
  for (const a of [2n, 3n, 5n, 7n, 11n, 13n, 17n, 19n, 23n, 29n, 31n, 37n]) {
    if (a >= n) continue;
    let x = modPow(a, d, n);
    if (x === 1n || x === n - 1n) continue;
    let composite = true;
    for (let i = 0n; i < r - 1n; i++) {
      x = (x * x) % n;
      if (x === n - 1n) {
        composite = false;
        break;
      }
    }
    if (composite) return false;
  }
  return true;
}

function gcd(a: bigint, b: bigint): bigint {
  let x = a < 0n ? -a : a;
  let y = b < 0n ? -b : b;
  while (y) {
    [x, y] = [y, x % y];
  }
  return x;
}

function checkPublicValidity(n: bigint, e: bigint): boolean {
  return n >= 15n && n % 2n === 1n && e >= 3n && e <= n - 1n && e % 2n === 1n;
}

function checkPrivateDomain(m: RsaPrivateMaterial): boolean {
  return (
    m.p !== m.q &&
    isProbablePrime(m.p) &&
    isProbablePrime(m.q) &&
    m.p % 2n === 1n &&
    m.q % 2n === 1n &&
    m.e >= 3n &&
    m.e <= m.n - 1n &&
    m.d > 0n &&
    m.d < m.n &&
    m.dP > 0n &&
    m.dP < m.p &&
    m.dQ > 0n &&
    m.dQ < m.q &&
    m.qInv > 0n &&
    m.qInv < m.p
  );
}

function checkPrivateRelations(m: RsaPrivateMaterial): boolean {
  const lambda = (a: bigint, b: bigint): bigint => (a * b) / gcd(a, b);
  const lambdaN = lambda(m.p - 1n, m.q - 1n);
  const modOk = (a: bigint, b: bigint, mod: bigint): boolean => (a * b) % mod === 1n % mod;
  return (
    m.n === m.p * m.q &&
    gcd(m.e, lambdaN) === 1n &&
    modOk(m.e, m.d, lambdaN) &&
    modOk(m.e, m.dP, m.p - 1n) &&
    modOk(m.e, m.dQ, m.q - 1n) &&
    modOk(m.q, m.qInv, m.p)
  );
}

// ---------------------------------------------------------------------------
// Accept_C: the full D-056 directional classifier for import
// ---------------------------------------------------------------------------

export function importRsaSer(artifact: Uint8Array, requestedRole: 'public' | 'private'): RsaKeyMaterial {
  const container = parseContainerStructural(artifact);

  checkClause(
    'rsa-ser.role-container',
    container.containerRole === requestedRole,
    'invalid_parameter',
    `artifact instantiates a ${container.containerRole} container but role=${requestedRole} was requested`,
  );

  let algInfo: { oidOk: boolean; paramsOk: boolean };
  try {
    algInfo = decodeAlgorithmIdentifier(container.algIdTlv);
  } catch {
    checkClause('rsa-ser.algorithm-id', false, 'invalid_parameter', 'AlgorithmIdentifier is not a well-formed SEQUENCE');
    throw new DerError('unreachable');
  }
  checkClause('rsa-ser.algorithm-id', algInfo.oidOk, 'invalid_parameter', 'AlgorithmIdentifier.algorithm != rsaEncryption (D-053)');
  checkClause(
    'rsa-ser.algorithm-params',
    algInfo.paramsOk,
    'invalid_parameter',
    'AlgorithmIdentifier.parameters is neither absent nor explicit NULL (D-053)',
  );

  if (requestedRole === 'public') {
    let pub: { n: bigint; e: bigint };
    try {
      const innerContent = decodeBitStringWholeBytes(container.innerTlv);
      pub = decodeRsaPublicKey(decodeTlv(innerContent, 0));
    } catch (err) {
      checkClause('rsa-ser.container', false, 'malformed_artifact', `RSAPublicKey inner structure malformed: ${err instanceof Error ? err.message : String(err)}`);
      throw new DerError('unreachable');
    }
    checkClause(
      'rsa-ser.public-validity',
      checkPublicValidity(pub.n, pub.e),
      'invalid_key',
      `public key fails C_math^public (n>=15, n odd, 3<=e<=n-1, e odd; got n=${pub.n}, e=${pub.e})`,
    );
    return { role: 'public', n: pub.n, e: pub.e };
  }

  let priv: RsaPrivateMaterial | undefined;
  try {
    const innerContent = decodeOctetString(container.innerTlv);
    priv = decodeRsaPrivateKeyV0(decodeTlv(innerContent, 0));
  } catch (err) {
    checkClause('rsa-ser.container', false, 'malformed_artifact', `RSAPrivateKey inner structure malformed: ${err instanceof Error ? err.message : String(err)}`);
    throw new DerError('unreachable');
  }
  checkClause(
    'rsa-ser.container',
    priv !== undefined,
    'malformed_artifact',
    'RSAPrivateKey is not two-prime (version=0, 9 fields) -- multi-prime is outside the portable profile (D-053)',
  );
  const m = priv!;
  checkClause('rsa-ser.private-domain', checkPrivateDomain(m), 'invalid_key', 'private key fails V_domain^RSA,2 (D-054): component range/primality');
  checkClause('rsa-ser.private-relations', checkPrivateRelations(m), 'invalid_key', 'private key fails V_rel^RSA,2 (D-054): n=pq, ed=1 mod lambda(n), CRT relations');
  return m;
}
