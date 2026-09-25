// M2.4.6 -- EC-ser mutation implementations (14 of 14), the last family.
// Source: src/contract/ec-ser.ts + src/contract/p256.ts + src/contract/der.ts
// (M1, unmodified). No request wrapper exists for import/export here either
// (same situation as RSA-ser) -- every class is artifact-transform,
// adapter-transform, or capability-transform; none is request-transform.

import {
  encodeSpki, encodePkcs8, importEcSer, derivePublicPoint,
  type EcPublicMaterial, type EcPrivateMaterial,
} from '../../src/contract/ec-ser.js';
import {
  isOnCurve, isPair, scalarMultiplyG,
  P256_N, type AffinePoint,
} from '../../src/contract/p256.js';
import {
  decodeTlv, decodeSequenceChildren, encodeTlv, encodeSequence, encodeInteger,
  encodeExplicitTag, isExplicitTag,
} from '../../src/contract/der.js';
import type { MutationImplementation } from './framework.js';

function xorByte(bytes: Uint8Array, index: number): Uint8Array {
  const copy = new Uint8Array(bytes);
  const i = index < 0 ? copy.length + index : index;
  copy[i] = (copy[i] ?? 0) ^ 0xff;
  return copy;
}

// A fixed, valid toy point: G itself scaled by d=1 is G; use d=2 for a
// distinct, independently-valid base point via the REAL scalarMultiplyG
// (pure modular arithmetic, no crypto library call -- same discipline as
// RSA-ser's toy key).
export const TOY_PRIVATE_MATERIAL: EcPrivateMaterial = Object.freeze({ role: 'private', d: 2n, q: scalarMultiplyG(2n) });
export const TOY_PUBLIC_MATERIAL: EcPublicMaterial = Object.freeze({ role: 'public', q: TOY_PRIVATE_MATERIAL.q as { x: bigint; y: bigint } });

// ---------------------------------------------------------------------
// Material-level: perturb before encoding (3 of 14)
// ---------------------------------------------------------------------

export const EC_PUBLIC_OFF_CURVE: MutationImplementation<EcPublicMaterial> = {
  mutationId: 'EC-PUBLIC-OFF-CURVE',
  directInterventionTargets: ['q'],
  mutate: (material) => {
    const q = material.q as { x: bigint; y: bigint };
    return { ...material, q: { x: q.x, y: q.y + 1n } }; // off the curve for almost any point -- verified in the test, never assumed
  },
};

export const EC_PRIVATE_SCALAR_RANGE: MutationImplementation<EcPrivateMaterial> = {
  mutationId: 'EC-PRIVATE-SCALAR-RANGE',
  directInterventionTargets: ['d'], // q is a downstream consequence R_val/R_err observe, never written here
  mutate: (material) => ({ ...material, d: 0n }), // fails V_scalar's own 1<=d<n
};

export const EC_PRIVATE_PAIR_MISMATCH: MutationImplementation<EcPrivateMaterial> = {
  mutationId: 'EC-PRIVATE-PAIR-MISMATCH',
  directInterventionTargets: ['q'],
  // A genuinely different, independently on-curve point (3*G via the real
  // scalarMultiplyG) substituted for the material's own d*G -- on-curve,
  // but Q != dG for this d, isolating V_pair from V_curve exactly as the
  // registry's own Gamma_0 requires.
  mutate: (material) => ({ ...material, q: scalarMultiplyG(3n) as { x: bigint; y: bigint } }),
};

export const EC_SER_MATERIAL_MUTATIONS = { EC_PUBLIC_OFF_CURVE, EC_PRIVATE_SCALAR_RANGE, EC_PRIVATE_PAIR_MISMATCH };

// ---------------------------------------------------------------------
// Artifact-level (real DER, real SPKI/PKCS8 encoders) (9 of 14)
// ---------------------------------------------------------------------

export const EC_ROLE_CONTAINER_MISMATCH: MutationImplementation<{ readonly artifact: Uint8Array; readonly requestedRole: 'public' | 'private' }> = {
  mutationId: 'EC-ROLE-CONTAINER-MISMATCH',
  directInterventionTargets: ['requestedRole'],
  mutate: (state) => ({ ...state, requestedRole: state.requestedRole === 'public' ? 'private' : 'public' }),
};

export const EC_CURVE_SUBSTITUTION: MutationImplementation<{ readonly artifact: Uint8Array }> = {
  mutationId: 'EC-CURVE-SUBSTITUTION',
  directInterventionTargets: ['artifact'],
  mutate: (state) => {
    // Re-parse a real SPKI artifact and corrupt the curve OID content
    // (second child of AlgorithmIdentifier) -- via real decode/encode, never
    // a hand-guessed byte offset.
    const outer = decodeTlv(state.artifact, 0);
    const children = decodeSequenceChildren(outer, 2);
    const algChildren = decodeSequenceChildren(children[0]!, 2);
    const corruptedCurveOid = encodeTlv(algChildren[1]!.tag, xorByte(algChildren[1]!.content, 0));
    const newAlgId = encodeSequence([encodeTlv(algChildren[0]!.tag, algChildren[0]!.content), corruptedCurveOid]);
    return { artifact: encodeSequence([newAlgId, encodeTlv(children[1]!.tag, children[1]!.content)]) };
  },
};

export const EC_PUBLIC_POINT_ENCODING: MutationImplementation<{ readonly artifact: Uint8Array }> = {
  mutationId: 'EC-PUBLIC-POINT-ENCODING',
  directInterventionTargets: ['artifact'],
  mutate: (state) => {
    // Re-parse a real SPKI and flip the point's own leading form-octet
    // (0x04 uncompressed -> something else) inside the real BIT STRING content.
    const outer = decodeTlv(state.artifact, 0);
    const children = decodeSequenceChildren(outer, 2);
    const bitString = children[1]!;
    const corruptedContent = xorByte(bitString.content, 1); // byte 0 is the unused-bits octet; byte 1 is the point's own leading form octet
    return { artifact: encodeSequence([encodeTlv(children[0]!.tag, children[0]!.content), encodeTlv(bitString.tag, corruptedContent)]) };
  },
};

export const EC_PUBLIC_DER_MALFORMED: MutationImplementation<{ readonly artifact: Uint8Array }> = {
  mutationId: 'EC-PUBLIC-DER-MALFORMED',
  directInterventionTargets: ['artifact'],
  mutate: (state) => ({ artifact: xorByte(state.artifact, 1) }), // corrupt the outer length byte -- DER-vs-BER violation territory
};

export const EC_PRIVATE_DER_MALFORMED: MutationImplementation<{ readonly artifact: Uint8Array }> = {
  mutationId: 'EC-PRIVATE-DER-MALFORMED',
  directInterventionTargets: ['artifact'],
  mutate: (state) => ({ artifact: xorByte(state.artifact, 1) }),
};

export const EC_PRIVATE_PARAMS_ABSENT: MutationImplementation<{ readonly artifact: Uint8Array }> = {
  mutationId: 'EC-PRIVATE-PARAMS-ABSENT',
  directInterventionTargets: ['artifact'],
  mutate: (state) => {
    // Re-parse a real PKCS8 artifact and rebuild ECPrivateKey WITHOUT its
    // own [0] explicit tag -- common-but-not-portable, normalizable per
    // D-061 (this is a legal, accept-normalized stimulus, not necessarily
    // a rejection one).
    const outer = decodeTlv(state.artifact, 0);
    const outerChildren = decodeSequenceChildren(outer, 3);
    const algId = outerChildren[1]!;
    const octetString = outerChildren[2]!;
    const innerSeq = decodeTlv(octetString.content, 0);
    const innerChildren = decodeSequenceChildren(innerSeq);
    const withoutParams = innerChildren.filter((c) => !isExplicitTag(c, 0));
    const newInner = encodeSequence(withoutParams.map((c) => encodeTlv(c.tag, c.content)));
    const newOctetString = encodeTlv(octetString.tag, newInner);
    return { artifact: encodeSequence([encodeInteger(0n), encodeTlv(algId.tag, algId.content), newOctetString]) };
  },
};

export const EC_PRIVATE_PARAMS_MISMATCH: MutationImplementation<{ readonly artifact: Uint8Array }> = {
  mutationId: 'EC-PRIVATE-PARAMS-MISMATCH',
  directInterventionTargets: ['artifact'],
  mutate: (state) => {
    // Re-parse and corrupt the CONTENT of the [0] explicit tag's inner OID
    // (present, but no longer secp256r1) -- distinct from PARAMS-ABSENT's
    // own removal.
    const outer = decodeTlv(state.artifact, 0);
    const outerChildren = decodeSequenceChildren(outer, 3);
    const algId = outerChildren[1]!;
    const octetString = outerChildren[2]!;
    const innerSeq = decodeTlv(octetString.content, 0);
    const innerChildren = decodeSequenceChildren(innerSeq);
    const mutatedChildren = innerChildren.map((c) => {
      if (!isExplicitTag(c, 0)) return encodeTlv(c.tag, c.content);
      const innerOid = decodeTlv(c.content, 0);
      const corruptedOid = encodeTlv(innerOid.tag, xorByte(innerOid.content, 0));
      return encodeExplicitTag(0, corruptedOid);
    });
    const newInner = encodeSequence(mutatedChildren);
    const newOctetString = encodeTlv(octetString.tag, newInner);
    return { artifact: encodeSequence([encodeInteger(0n), encodeTlv(algId.tag, algId.content), newOctetString]) };
  },
};

export const EC_PRIVATE_PUBKEY_ABSENT: MutationImplementation<{ readonly artifact: Uint8Array }> = {
  mutationId: 'EC-PRIVATE-PUBKEY-ABSENT',
  directInterventionTargets: ['artifact'],
  mutate: (state) => {
    // Remove the [1] explicit tag entirely -- per the contract's own text,
    // this is EXCLUDED from D_common itself and must be REJECTED, never
    // normalized (sharp contrast with PARAMS-ABSENT's own [0] case).
    const outer = decodeTlv(state.artifact, 0);
    const outerChildren = decodeSequenceChildren(outer, 3);
    const algId = outerChildren[1]!;
    const octetString = outerChildren[2]!;
    const innerSeq = decodeTlv(octetString.content, 0);
    const innerChildren = decodeSequenceChildren(innerSeq);
    const withoutPubkey = innerChildren.filter((c) => !isExplicitTag(c, 1));
    const newInner = encodeSequence(withoutPubkey.map((c) => encodeTlv(c.tag, c.content)));
    const newOctetString = encodeTlv(octetString.tag, newInner);
    return { artifact: encodeSequence([encodeInteger(0n), encodeTlv(algId.tag, algId.content), newOctetString]) };
  },
};

export const EC_SER_ARTIFACT_MUTATIONS = {
  EC_ROLE_CONTAINER_MISMATCH, EC_CURVE_SUBSTITUTION, EC_PUBLIC_POINT_ENCODING,
  EC_PUBLIC_DER_MALFORMED, EC_PRIVATE_DER_MALFORMED,
  EC_PRIVATE_PARAMS_ABSENT, EC_PRIVATE_PARAMS_MISMATCH, EC_PRIVATE_PUBKEY_ABSENT,
};

// ---------------------------------------------------------------------
// adapter-transform (2 of 14)
// ---------------------------------------------------------------------

// Models the exact scenario src/contract/ec-ser.ts's own derivePublicPoint()
// comment documents: a native writer (Crypto++) omits publicKey[1], and the
// (possibly faulty) adapter must decide whether to reconstruct it via dG
// before reaching the portable form.
export interface EcNativeExportIntervention {
  readonly material: EcPrivateMaterial;
  readonly adapterReconstructsPubkey: boolean;
}

export const EC_NATIVE_EXPORT_LEAK: MutationImplementation<EcNativeExportIntervention> = {
  mutationId: 'EC-NATIVE-EXPORT-LEAK',
  directInterventionTargets: ['adapterReconstructsPubkey'],
  mutate: (state) => ({ ...state, adapterReconstructsPubkey: !state.adapterReconstructsPubkey }),
};

export interface EcSerErrorMappingIntervention {
  readonly triggeringCondition: string;
  readonly declaredErrorClass: string;
}

export const EC_ERROR_MAP_SWAP: MutationImplementation<EcSerErrorMappingIntervention> = {
  mutationId: 'EC-ERROR-MAP-SWAP',
  directInterventionTargets: ['declaredErrorClass'],
  mutate: (state) => ({
    ...state,
    declaredErrorClass: state.declaredErrorClass === 'invalid_membership' ? 'invalid_key' : 'invalid_membership',
  }),
};

export const EC_SER_ADAPTER_MUTATIONS = { EC_NATIVE_EXPORT_LEAK, EC_ERROR_MAP_SWAP };

// ---------------------------------------------------------------------
// capability-transform (1 of 14)
// ---------------------------------------------------------------------

export interface CapabilityDeclarationExperimentalView {
  readonly capabilityId: string;
  readonly kind: 'provider-support';
  readonly support: 'supported' | 'unsupported';
}

export const EC_CAPABILITY_MANIFEST_MISMATCH: MutationImplementation<CapabilityDeclarationExperimentalView> = {
  mutationId: 'EC-CAPABILITY-MANIFEST-MISMATCH',
  directInterventionTargets: ['support'],
  mutate: (state) => ({ ...state, support: state.support === 'supported' ? 'unsupported' : 'supported' }),
};

export const EC_SER_NON_MATERIAL_MUTATIONS = {
  ...EC_SER_ARTIFACT_MUTATIONS,
  ...EC_SER_ADAPTER_MUTATIONS,
  EC_CAPABILITY_MANIFEST_MISMATCH,
};

export const EC_SER_ALL_MUTATION_IDS: readonly string[] = [
  ...Object.values(EC_SER_MATERIAL_MUTATIONS).map((m) => m.mutationId),
  ...Object.values(EC_SER_NON_MATERIAL_MUTATIONS).map((m) => m.mutationId),
];

// Re-exported for the test file, so tests build artifacts via the same
// frozen M1 functions rather than any hand-rolled bytes.
export { encodeSpki, encodePkcs8, importEcSer, derivePublicPoint, isOnCurve, isPair, P256_N };
export type { AffinePoint };
