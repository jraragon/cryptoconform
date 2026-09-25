// M3-reopen v5 -- bounded R_ser observation.
//
// R_ser judges the portable artifact, independently of backend accept/reject.
// This module does exactly two things:
//   RepOK      -- structural/canonical conformance of the artifact bytes.
//   MaterialOK -- preservation of the material the artifact is supposed to carry.
//
// No mutationId branching, no ExpectedSpectrum lookup, no applicability
// decision and no backend-policy decision live here.

import {
  TAG,
  decodeTlv,
  decodeSequenceChildren,
  decodeInteger,
  decodeBitStringWholeBytes,
  decodeOctetString,
  isNullTlv,
  isRsaEncryptionOidTlv,
  isEcPublicKeyOidTlv,
  isSecp256r1OidTlv,
  isExplicitTag,
  type DecodedTlv,
} from '../../src/contract/der.js';
import { parseAeadArtifact } from '../../src/contract/gcm.js';

export class SerializationObserverError extends Error {}

interface AuxExecution {
  readonly executionId: string;
  readonly executionStatus: string;
  readonly outcome: { readonly kind: string };
  readonly output?: { readonly bytes?: string };
}

export interface SerializationObservation {
  readonly repOK?: boolean;
  readonly materialOK?: boolean;
  readonly auxiliaryExecutionId?: string;
}

type GcmDecryptRunner = (input: {
  readonly key: Uint8Array;
  readonly artifact: Uint8Array;
  readonly aad: Uint8Array | undefined;
}) => Promise<AuxExecution>;

type SerOperation = 'gcm' | 'rsa-ser' | 'ec-ser';

type RsaSemantic =
  | { readonly role: 'public'; readonly n: bigint; readonly e: bigint }
  | {
      readonly role: 'private';
      readonly n: bigint; readonly e: bigint; readonly d: bigint;
      readonly p: bigint; readonly q: bigint;
      readonly dP: bigint; readonly dQ: bigint; readonly qInv: bigint;
    };

type EcSemantic =
  | { readonly role: 'public'; readonly x: Uint8Array; readonly y: Uint8Array }
  | { readonly role: 'private'; readonly d: Uint8Array; readonly x: Uint8Array; readonly y: Uint8Array };

const rec = (v: unknown): Record<string, unknown> | undefined =>
  v !== null && typeof v === 'object' ? v as Record<string, unknown> : undefined;

const bytesEq = (a: Uint8Array, b: Uint8Array): boolean =>
  a.length === b.length && a.every((v, i) => v === b[i]);

const hexBytes = (hex: string | undefined): Uint8Array | undefined => {
  if (hex === undefined || hex.length % 2 !== 0 || !/^[0-9a-fA-F]*$/.test(hex)) return undefined;
  return new Uint8Array(Buffer.from(hex, 'hex'));
};

function artifactFromFixture(fixture: unknown): Uint8Array | undefined {
  const a = rec(fixture)?.artifact;
  return a instanceof Uint8Array ? new Uint8Array(a) : undefined;
}

function fixed32(v: bigint): Uint8Array {
  let h = v.toString(16);
  if (h.length % 2 !== 0) h = '0' + h;
  const b = new Uint8Array(Buffer.from(h, 'hex'));
  if (b.length > 32) throw new SerializationObserverError('EC scalar/coordinate exceeds 32 bytes.');
  const out = new Uint8Array(32);
  out.set(b, 32 - b.length);
  return out;
}

function pointBytesSemantic(bytes: Uint8Array): { x: Uint8Array; y: Uint8Array } | undefined {
  // Portable EC representation is the uncompressed P-256 form:
  // 0x04 || X(32) || Y(32). Curve membership belongs to R_val, not RepOK.
  if (bytes.length !== 65 || bytes[0] !== 0x04) return undefined;
  return { x: bytes.slice(1, 33), y: bytes.slice(33, 65) };
}

function decodeInnerExact(bytes: Uint8Array): DecodedTlv {
  const tlv = decodeTlv(bytes, 0);
  if (tlv.nextOffset !== bytes.length) throw new Error('inner DER has trailing bytes');
  return tlv;
}

// ------------------------------------------------------------------
// RSA
// ------------------------------------------------------------------

function parseRsaArtifact(
  artifact: Uint8Array,
  direction: 'export' | 'import',
): { repOK: boolean; material?: RsaSemantic } {
  try {
    let repOK = true;

    const outer = decodeTlv(artifact, 0);
    if (outer.nextOffset !== artifact.length) repOK = false;

    const children = decodeSequenceChildren(outer);

    let role: 'public' | 'private';
    let alg: DecodedTlv;
    let payload: DecodedTlv;

    if (children.length === 2 && children[1]!.tag === TAG.BIT_STRING) {
      role = 'public';
      alg = children[0]!;
      payload = children[1]!;
    } else if (
      children.length === 3
      && children[0]!.tag === TAG.INTEGER
      && children[2]!.tag === TAG.OCTET_STRING
    ) {
      role = 'private';
      if (decodeInteger(children[0]!) !== 0n) repOK = false;
      alg = children[1]!;
      payload = children[2]!;
    } else {
      return { repOK: false };
    }

    let algChildren: DecodedTlv[];
    try {
      algChildren = decodeSequenceChildren(alg);
    } catch {
      return { repOK: false };
    }

    if (algChildren.length < 1 || algChildren.length > 2) repOK = false;
    if (algChildren[0] === undefined || !isRsaEncryptionOidTlv(algChildren[0])) repOK = false;

    // Import admits absent or explicit NULL. Canonical export uses explicit NULL.
    if (direction === 'export') {
      if (algChildren.length !== 2 || algChildren[1] === undefined || !isNullTlv(algChildren[1])) repOK = false;
    } else {
      if (
        algChildren.length === 2
        && (algChildren[1] === undefined || !isNullTlv(algChildren[1]))
      ) repOK = false;
    }

    if (role === 'public') {
      const innerBytes = decodeBitStringWholeBytes(payload);
      const inner = decodeInnerExact(innerBytes);
      const ints = decodeSequenceChildren(inner, 2);
      return {
        repOK,
        material: {
          role: 'public',
          n: decodeInteger(ints[0]!),
          e: decodeInteger(ints[1]!),
        },
      };
    }

    const innerBytes = decodeOctetString(payload);
    const inner = decodeInnerExact(innerBytes);
    const ints = decodeSequenceChildren(inner, 9);
    if (decodeInteger(ints[0]!) !== 0n) repOK = false;

    return {
      repOK,
      material: {
        role: 'private',
        n: decodeInteger(ints[1]!),
        e: decodeInteger(ints[2]!),
        d: decodeInteger(ints[3]!),
        p: decodeInteger(ints[4]!),
        q: decodeInteger(ints[5]!),
        dP: decodeInteger(ints[6]!),
        dQ: decodeInteger(ints[7]!),
        qInv: decodeInteger(ints[8]!),
      },
    };
  } catch {
    return { repOK: false };
  }
}

function rsaExpectedFromFixture(fixture: unknown): RsaSemantic | undefined {
  const r = rec(fixture);
  if (r === undefined) return undefined;

  if (
    r.role === 'public'
    && typeof r.n === 'bigint'
    && typeof r.e === 'bigint'
  ) {
    return { role: 'public', n: r.n, e: r.e };
  }

  if (
    r.role === 'private'
    && typeof r.n === 'bigint' && typeof r.e === 'bigint'
    && typeof r.d === 'bigint' && typeof r.p === 'bigint'
    && typeof r.q === 'bigint' && typeof r.dP === 'bigint'
    && typeof r.dQ === 'bigint' && typeof r.qInv === 'bigint'
  ) {
    return {
      role: 'private',
      n: r.n, e: r.e, d: r.d, p: r.p, q: r.q,
      dP: r.dP, dQ: r.dQ, qInv: r.qInv,
    };
  }

  const artifact = artifactFromFixture(fixture);
  return artifact === undefined ? undefined : parseRsaArtifact(artifact, 'import').material;
}

function rsaMaterialEq(a: RsaSemantic, b: RsaSemantic): boolean {
  if (a.role !== b.role) return false;
  if (a.n !== b.n || a.e !== b.e) return false;
  if (a.role === 'public' || b.role === 'public') return a.role === b.role;

  return a.d === b.d && a.p === b.p && a.q === b.q
    && a.dP === b.dP && a.dQ === b.dQ && a.qInv === b.qInv;
}

// ------------------------------------------------------------------
// EC
// ------------------------------------------------------------------

function parseEcArtifact(artifact: Uint8Array): { repOK: boolean; material?: EcSemantic } {
  try {
    let repOK = true;

    const outer = decodeTlv(artifact, 0);
    if (outer.nextOffset !== artifact.length) repOK = false;
    const children = decodeSequenceChildren(outer);

    let role: 'public' | 'private';
    let alg: DecodedTlv;
    let payload: DecodedTlv;

    if (children.length === 2 && children[1]!.tag === TAG.BIT_STRING) {
      role = 'public';
      alg = children[0]!;
      payload = children[1]!;
    } else if (
      children.length === 3
      && children[0]!.tag === TAG.INTEGER
      && children[2]!.tag === TAG.OCTET_STRING
    ) {
      role = 'private';
      if (decodeInteger(children[0]!) !== 0n) repOK = false;
      alg = children[1]!;
      payload = children[2]!;
    } else {
      return { repOK: false };
    }

    let algChildren: DecodedTlv[];
    try {
      algChildren = decodeSequenceChildren(alg, 2);
    } catch {
      return { repOK: false };
    }

    if (!isEcPublicKeyOidTlv(algChildren[0]!) || !isSecp256r1OidTlv(algChildren[1]!)) {
      repOK = false;
    }

    if (role === 'public') {
      const point = pointBytesSemantic(decodeBitStringWholeBytes(payload));
      if (point === undefined) return { repOK: false };
      return { repOK, material: { role: 'public', x: point.x, y: point.y } };
    }

    const innerBytes = decodeOctetString(payload);
    const inner = decodeInnerExact(innerBytes);
    const innerChildren = decodeSequenceChildren(inner);

    if (innerChildren.length < 2) return { repOK: false };
    if (decodeInteger(innerChildren[0]!) !== 1n) repOK = false;

    const d = decodeOctetString(innerChildren[1]!);
    if (d.length !== 32) repOK = false;

    let paramsSeen = false;
    let paramsOK = false;
    let pubSeen = false;
    let pub: { x: Uint8Array; y: Uint8Array } | undefined;

    for (let i = 2; i < innerChildren.length; i++) {
      const child = innerChildren[i]!;
      if (isExplicitTag(child, 0)) {
        if (paramsSeen) repOK = false;
        paramsSeen = true;
        try {
          const x = decodeInnerExact(child.content);
          paramsOK = isSecp256r1OidTlv(x);
        } catch {
          paramsOK = false;
        }
      } else if (isExplicitTag(child, 1)) {
        if (pubSeen) repOK = false;
        pubSeen = true;
        try {
          const bit = decodeInnerExact(child.content);
          pub = pointBytesSemantic(decodeBitStringWholeBytes(bit));
        } catch {
          pub = undefined;
        }
      } else {
        repOK = false;
      }
    }

    // Portable PKCS8 requires BOTH parameters[0] and publicKey[1].
    // parameters[0]-absent is common-but-non-portable, therefore RepOK=false.
    if (!paramsSeen || !paramsOK || !pubSeen || pub === undefined) repOK = false;

    if (pub === undefined) return { repOK };

    return {
      repOK,
      material: {
        role: 'private',
        d: new Uint8Array(d),
        x: pub.x,
        y: pub.y,
      },
    };
  } catch {
    return { repOK: false };
  }
}

function ecExpectedFromFixture(fixture: unknown): EcSemantic | undefined {
  const r = rec(fixture);
  if (r === undefined) return undefined;

  if (r.role === 'public') {
    const q = rec(r.q);
    if (typeof q?.x === 'bigint' && typeof q?.y === 'bigint') {
      return { role: 'public', x: fixed32(q.x), y: fixed32(q.y) };
    }
  }

  if (r.role === 'private' && typeof r.d === 'bigint') {
    const q = rec(r.q);
    if (typeof q?.x === 'bigint' && typeof q?.y === 'bigint') {
      return { role: 'private', d: fixed32(r.d), x: fixed32(q.x), y: fixed32(q.y) };
    }
  }

  const artifact = artifactFromFixture(fixture);
  return artifact === undefined ? undefined : parseEcArtifact(artifact).material;
}

function ecMaterialEq(a: EcSemantic, b: EcSemantic): boolean {
  if (a.role !== b.role) return false;
  if (!bytesEq(a.x, b.x) || !bytesEq(a.y, b.y)) return false;
  if (a.role === 'public' || b.role === 'public') return a.role === b.role;
  return bytesEq(a.d, b.d);
}

// ------------------------------------------------------------------
// Public observer
// ------------------------------------------------------------------

export async function observeSerialization(params: {
  readonly operation: SerOperation;
  readonly direction: string;
  readonly baseFixture: unknown;
  readonly mutatedFixture: unknown;
  readonly outputHex?: string;
  readonly runGcmDecrypt?: GcmDecryptRunner;
}): Promise<SerializationObservation> {
  const { operation, direction } = params;

  if (operation === 'gcm') {
    if (direction === 'decrypt') {
      const baseArtifact = artifactFromFixture(params.baseFixture);
      const artifact = artifactFromFixture(params.mutatedFixture);
      if (artifact === undefined) return {};

      let repOK = true;
      try {
        parseAeadArtifact(artifact);
      } catch {
        repOK = false;
      }

      return {
        repOK,
        ...(baseArtifact === undefined ? {} : { materialOK: bytesEq(artifact, baseArtifact) }),
      };
    }

    if (direction === 'encrypt') {
      const artifact = hexBytes(params.outputHex);
      const m = rec(params.mutatedFixture);
      if (artifact === undefined || m === undefined) return {};

      let repOK = true;
      try {
        parseAeadArtifact(artifact);
      } catch {
        repOK = false;
      }

      if (!repOK) return { repOK: false };
      if (
        !(m.key instanceof Uint8Array)
        || !(m.plaintext instanceof Uint8Array)
        || !(m.iv instanceof Uint8Array)
        || !(m.aad === undefined || m.aad instanceof Uint8Array)
      ) {
        return { repOK };
      }

      if (params.runGcmDecrypt === undefined) return { repOK };

      const aux = await params.runGcmDecrypt({
        key: new Uint8Array(m.key),
        artifact,
        aad: m.aad === undefined ? undefined : new Uint8Array(m.aad),
      });

      const plaintext = hexBytes(aux.output?.bytes);
      const materialOK =
        aux.executionStatus === 'completed'
        && aux.outcome.kind === 'accept'
        && plaintext !== undefined
        && bytesEq(plaintext, m.plaintext);

      return { repOK, materialOK, auxiliaryExecutionId: aux.executionId };
    }

    throw new SerializationObserverError(`Unsupported GCM serialization direction '${direction}'.`);
  }

  if (operation === 'rsa-ser') {
    const inputArtifact = artifactFromFixture(params.mutatedFixture);
    const artifact = direction === 'import' ? inputArtifact : hexBytes(params.outputHex);
    if (artifact === undefined) return {};

    const parsed = parseRsaArtifact(artifact, direction === 'export' ? 'export' : 'import');
    const expected = rsaExpectedFromFixture(params.baseFixture);

    return {
      repOK: parsed.repOK,
      ...(parsed.material === undefined || expected === undefined
        ? {}
        : { materialOK: rsaMaterialEq(parsed.material, expected) }),
    };
  }

  if (operation === 'ec-ser') {
    const inputArtifact = artifactFromFixture(params.mutatedFixture);
    const artifact = direction === 'import' ? inputArtifact : hexBytes(params.outputHex);
    if (artifact === undefined) return {};

    const parsed = parseEcArtifact(artifact);
    const expected = ecExpectedFromFixture(params.baseFixture);

    return {
      repOK: parsed.repOK,
      ...(parsed.material === undefined || expected === undefined
        ? {}
        : { materialOK: ecMaterialEq(parsed.material, expected) }),
    };
  }

  throw new SerializationObserverError(`R_ser observer has no implementation for '${operation}'.`);
}
