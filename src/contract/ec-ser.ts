import { checkClause } from './check-clause.js';
import {
  DerError,
  decodeTlv,
  decodeSequenceChildren,
  decodeInteger,
  decodeBitStringWholeBytes,
  decodeOctetString,
  isEcPublicKeyOidTlv,
  isSecp256r1OidTlv,
  encodeInteger,
  encodeSequence,
  encodeBitStringWholeBytes,
  encodeOctetString,
  encodeEcPublicKeyOid,
  encodeSecp256r1Oid,
  encodeExplicitTag,
  isExplicitTag,
  type DecodedTlv,
} from './der.js';
import {
  isOnCurve,
  isPair,
  isValidScalar,
  scalarMultiplyG,
  encodeUncompressedPoint,
  decodeUncompressedPoint,
  type AffinePoint,
} from './p256.js';

/**
 * EC P-256 Key Serialization portable contract. Source: Design Freeze v0.6,
 * sec:ec-ser through sec:ec-ser-clauses (D-059 through D-062).
 *
 * GENUINELY NEW relative to RSA-ser, not a re-skin:
 *   - Three separate mathematical properties, not two: V_scalar (1<=d<n),
 *     V_curve (Q on the curve, K1=Membership -- the first Membership
 *     instantiation in this project), V_pair (Q=dG, K1=Key, subtype
 *     PublicPrivateConsistency -- no RSA-ser analogue).
 *   - Accept_C has FIVE conjuncts.
 *   - Import has THREE outcomes, not two: Reject(unsupported), Accept(A)
 *     [already portable], Accept(N(A)) [common-but-not-portable,
 *     normalized], Reject(E_kappa) [outside common or math-invalid]. This
 *     is the first M1 operation with a genuine normalization branch.
 *   - publicKey[1] absence is excluded from D_common itself (not merely
 *     from portable) -- W3C webcrypto#356 demonstrates its absence is not
 *     a stable capability across realizations -- so [1]-absent is
 *     REJECTED, never normalized. parameters[0] absence, by contrast, IS
 *     common (just non-portable) -- so it IS normalized when everything
 *     else is valid.
 *   - Q=dG is NEVER normalized, by construction: normalization requires
 *     C_math^EC(A) to already hold, and PairConsistent(d,Q) is one of its
 *     five conjuncts -- a mathematically inconsistent artifact never
 *     reaches the normalization branch at all.
 */

export interface EcPublicMaterial {
  readonly role: 'public';
  readonly q: AffinePoint;
}

export interface EcPrivateMaterial {
  readonly role: 'private';
  readonly d: bigint;
  readonly q: AffinePoint; // always present in portable material -- PKCS8_portable(d,Q) contractually includes both (D-059), even though abstract semantic material remains Private(d) alone
}

export type EcKeyMaterial = EcPublicMaterial | EcPrivateMaterial;

export interface EcSerImportResult {
  readonly material: EcKeyMaterial;
  /** True iff the artifact was in D_common but not P_portable (currently: parameters[0] absent) and had to be normalized on the way to acceptance. Never true as a result of any V_scalar/V_curve/V_pair repair -- those never normalize (D-061). */
  readonly normalized: boolean;
}

function encodeAlgorithmIdentifier(): Uint8Array {
  return encodeSequence([encodeEcPublicKeyOid(), encodeSecp256r1Oid()]);
}

function decodeAlgorithmIdentifier(tlv: DecodedTlv): { algOk: boolean; curveOk: boolean } {
  const children = decodeSequenceChildren(tlv, 2); // EC AlgorithmIdentifier is ALWAYS two OIDs -- no {absent,NULL} tolerance exists for EC (sharp contrast with RSA-ser, confirmed by RFC 5480's own MUST-be-present text)
  return { algOk: isEcPublicKeyOidTlv(children[0]!), curveOk: isSecp256r1OidTlv(children[1]!) };
}

export function encodeSpki(m: EcPublicMaterial): Uint8Array {
  const point = encodeUncompressedPoint(m.q);
  return encodeSequence([encodeAlgorithmIdentifier(), encodeBitStringWholeBytes(point)]);
}

function encodeEcPrivateKey(m: EcPrivateMaterial): Uint8Array {
  const dBytes = bigIntToFixed32(m.d);
  const paramsExplicit = encodeExplicitTag(0, encodeSecp256r1Oid());
  const pubExplicit = encodeExplicitTag(1, encodeBitStringWholeBytes(encodeUncompressedPoint(m.q)));
  return encodeSequence([encodeInteger(1n), encodeOctetString(dBytes), paramsExplicit, pubExplicit]);
}

export function encodePkcs8(m: EcPrivateMaterial): Uint8Array {
  const inner = encodeEcPrivateKey(m);
  return encodeSequence([encodeInteger(0n), encodeAlgorithmIdentifier(), encodeOctetString(inner)]);
}

export function exportEcSer(material: EcKeyMaterial): Uint8Array {
  return material.role === 'public' ? encodeSpki(material) : encodePkcs8(material);
}

function bigIntToFixed32(value: bigint): Uint8Array {
  let hex = value.toString(16);
  if (hex.length % 2 !== 0) hex = '0' + hex;
  const bytes = Uint8Array.from(Buffer.from(hex, 'hex'));
  if (bytes.length > 32) throw new DerError('scalar does not fit in 32 bytes');
  const out = new Uint8Array(32);
  out.set(bytes, 32 - bytes.length);
  return out;
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
    checkClause('ec-ser.validation.syntax', false, 'malformed_artifact', `DER parse failed: ${err instanceof Error ? err.message : String(err)}`);
    throw err;
  }
  checkClause(
    'ec-ser.validation.syntax',
    outer.nextOffset === artifact.length,
    'malformed_artifact',
    `trailing bytes after the top-level DER object (${artifact.length - outer.nextOffset} byte(s) unconsumed)`,
  );

  let children: DecodedTlv[];
  try {
    children = decodeSequenceChildren(outer);
  } catch (err) {
    checkClause('ec-ser.validation.syntax', false, 'malformed_artifact', `outer SEQUENCE parse failed: ${err instanceof Error ? err.message : String(err)}`);
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
      checkClause('ec-ser.validation.syntax', false, 'malformed_artifact', 'PrivateKeyInfo version field is not a valid INTEGER');
      throw new DerError('unreachable');
    }
    checkClause('ec-ser.validation.syntax', version === 0n, 'malformed_artifact', `PrivateKeyInfo version=${version}, expected 0`);
    return { containerRole: 'private', algIdTlv: children[1]!, innerTlv: children[2]! };
  }

  checkClause('ec-ser.validation.syntax', false, 'malformed_artifact', 'valid DER instantiating neither SPKI nor PrivateKeyInfo');
  throw new DerError('unreachable');
}

export function importEcSer(artifact: Uint8Array, requestedRole: 'public' | 'private'): EcSerImportResult {
  const container = parseContainerStructural(artifact); // syntax layer

  checkClause(
    'ec-ser.key.role',
    container.containerRole === requestedRole,
    'invalid_parameter',
    `artifact instantiates a ${container.containerRole} container but role=${requestedRole} was requested`,
  );

  let algInfo: { algOk: boolean; curveOk: boolean };
  try {
    algInfo = decodeAlgorithmIdentifier(container.algIdTlv);
  } catch {
    checkClause('ec-ser.public.asn1', false, 'invalid_parameter', 'AlgorithmIdentifier is not a well-formed two-OID SEQUENCE');
    throw new DerError('unreachable');
  }
  checkClause(
    requestedRole === 'public' ? 'ec-ser.public.asn1' : 'ec-ser.private.asn1',
    algInfo.algOk,
    'invalid_parameter',
    'AlgorithmIdentifier.algorithm != id-ecPublicKey',
  );
  checkClause('ec-ser.curve', algInfo.curveOk, 'invalid_parameter', 'curve OID != secp256r1 (D-059: no implicit domain substitution)');

  if (requestedRole === 'public') {
    let point: AffinePoint;
    try {
      const pointBytes = decodeBitStringWholeBytes(container.innerTlv);
      point = decodeUncompressedPoint(pointBytes); // rejects compressed/hybrid forms -- portable admits uncompressed only
    } catch (err) {
      checkClause('ec-ser.public.point', false, 'invalid_parameter', `point decode failed: ${err instanceof Error ? err.message : String(err)}`);
      throw new DerError('unreachable');
    }
    checkClause('ec-ser.curveMembership', isOnCurve(point), 'invalid_membership', 'Q is not a point on secp256r1 (V_curve)');
    return { material: { role: 'public', q: point }, normalized: false };
  }

  if (container.innerTlv.tag !== 0x04) {
    checkClause('ec-ser.private.asn1', false, 'malformed_artifact', 'PrivateKeyInfo.privateKey is not an OCTET STRING');
  }
  let innerChildren: DecodedTlv[];
  try {
    const innerSeq = decodeTlv(container.innerTlv.content, 0);
    innerChildren = decodeSequenceChildren(innerSeq);
  } catch (err) {
    checkClause('ec-ser.private.asn1', false, 'malformed_artifact', `ECPrivateKey inner structure malformed: ${err instanceof Error ? err.message : String(err)}`);
    throw new DerError('unreachable');
  }
  checkClause('ec-ser.private.asn1', innerChildren.length >= 2, 'malformed_artifact', 'ECPrivateKey requires at least version and privateKey fields');

  let version: bigint;
  let dBytes: Uint8Array;
  try {
    version = decodeInteger(innerChildren[0]!);
    dBytes = decodeOctetString(innerChildren[1]!);
  } catch (err) {
    checkClause('ec-ser.private.asn1', false, 'malformed_artifact', `ECPrivateKey version/privateKey malformed: ${err instanceof Error ? err.message : String(err)}`);
    throw new DerError('unreachable');
  }
  checkClause('ec-ser.private.asn1', version === 1n, 'malformed_artifact', `ECPrivateKey.version=${version}, expected 1 (RFC 5915)`);
  checkClause('ec-ser.private.asn1', dBytes.length === 32, 'malformed_artifact', `privateKey OCTET STRING is ${dBytes.length} bytes, expected 32`);
  const d = bytesToBigInt(dBytes);

  let sawParamsZero = false;
  let paramsMatch = true;
  let pointBytes: Uint8Array | undefined;

  for (let i = 2; i < innerChildren.length; i++) {
    const child = innerChildren[i]!;
    if (isExplicitTag(child, 0)) {
      sawParamsZero = true;
      try {
        const inner = decodeTlv(child.content, 0);
        paramsMatch = isSecp256r1OidTlv(inner);
      } catch {
        paramsMatch = false;
      }
    } else if (isExplicitTag(child, 1)) {
      try {
        const bitStringTlv = decodeTlv(child.content, 0);
        pointBytes = decodeBitStringWholeBytes(bitStringTlv);
      } catch {
        pointBytes = undefined;
      }
    }
  }

  checkClause('ec-ser.private.asn1', !sawParamsZero || paramsMatch, 'invalid_parameter', 'ECPrivateKey.parameters[0] present but != secp256r1 (D-059: must match outer curve if present)');
  checkClause(
    'ec-ser.private.asn1',
    pointBytes !== undefined,
    'invalid_parameter',
    "ECPrivateKey.publicKey[1] is absent -- excluded from D_import^common entirely (W3C webcrypto#356's cross-runtime divergence), not normalizable, per D-059",
  );

  let point: AffinePoint;
  try {
    point = decodeUncompressedPoint(pointBytes!);
  } catch (err) {
    checkClause('ec-ser.public.point', false, 'invalid_parameter', `embedded publicKey[1] point decode failed: ${err instanceof Error ? err.message : String(err)}`);
    throw new DerError('unreachable');
  }

  checkClause('ec-ser.private.scalar', isValidScalar(d), 'invalid_key', 'private scalar fails V_scalar (1<=d<n)');
  checkClause('ec-ser.curveMembership', isOnCurve(point), 'invalid_membership', 'embedded publicKey[1] is not a point on secp256r1 (V_curve)');
  checkClause('ec-ser.pairConsistency', isPair(d, point), 'invalid_key', 'Q != dG (V_pair) -- never normalized, per D-061');

  return { material: { role: 'private', d, q: point }, normalized: !sawParamsZero };
}

function bytesToBigInt(bytes: Uint8Array): bigint {
  return BigInt('0x' + Buffer.from(bytes).toString('hex'));
}

/** Convenience: reconstruct Q=dG for adapter use (e.g. when a native writer omits publicKey[1] and the adapter must supply it itself to reach the portable form -- Crypto++'s native export, D-059). */
export function derivePublicPoint(d: bigint): AffinePoint {
  return scalarMultiplyG(d);
}
