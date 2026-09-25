// M2.4.6 -- RSA-ser mutation implementations (17 of 17).
// Source of types/functions: src/contract/rsa-ser.ts and src/contract/der.ts
// (M1, unmodified). Uses the REAL encode/decode primitives throughout --
// never reconstructs ASN.1/DER by hand, per the standing instruction to
// reuse frozen M1 parsers/builders rather than reimplementing them.
//
// Correction made before implementing (metadata-only, harness/registry/
// mutations.ts): four classes previously misclassified as request-transform
// in M2.4.6a's first pass are corrected to artifact-transform here --
// export() in this operation takes RsaKeyMaterial directly, there is no
// "request" wrapper object the way OaepEncryptRequest/PssSignRequest exist.
// This changes neither Gamma_0 nor any mutationId.

import {
  encodeSpki, encodePrivateKeyInfo,
  type RsaPublicMaterial, type RsaPrivateMaterial,
} from '../../src/contract/rsa-ser.js';
import {
  encodeTlv, encodeSequence, encodeInteger, TAG,
  decodeTlv, decodeSequenceChildren,
} from '../../src/contract/der.js';
import type { MutationImplementation } from './framework.js';

// A small, internally-consistent toy RSA private key, computed via pure
// modular arithmetic (extended Euclid), NOT via any cryptographic library
// call -- verified against the exact same six relations
// checkPrivateRelations/checkPrivateDomain use. R_ser tests serialization
// correctness, not real-world security, so a tiny key is a legitimate fixture.
export const TOY_PRIVATE_MATERIAL: RsaPrivateMaterial = Object.freeze({
  role: 'private', n: 3233n, e: 17n, d: 413n, p: 61n, q: 53n, dP: 53n, dQ: 49n, qInv: 38n,
});
export const TOY_PUBLIC_MATERIAL: RsaPublicMaterial = Object.freeze({ role: 'public', n: 3233n, e: 17n });

function xorByte(bytes: Uint8Array, index: number): Uint8Array {
  const copy = new Uint8Array(bytes);
  const i = index < 0 ? copy.length + index : index;
  copy[i] = (copy[i] ?? 0) ^ 0xff;
  return copy;
}

// ---------------------------------------------------------------------
// Material-level divergence: perturb material BEFORE encoding (2 of 17)
// ---------------------------------------------------------------------

export const RSA_SER_PUBLIC_MATERIAL_DIVERGENCE: MutationImplementation<RsaPublicMaterial> = {
  mutationId: 'RSA-SER-PUBLIC-MATERIAL-DIVERGENCE',
  directInterventionTargets: ['e'],
  // A different, still C_math^public-valid public exponent. The general
  // condition is 3 <= e' <= n-1 with e' odd; e'=7 satisfies it for any
  // modulus this profile admits. (M3-H3: the original comment justified the
  // choice against the toy key's own n=3233 and lambda=780, which is true
  // but says nothing about the real frozen key -- unlike its sibling, this
  // mutation does use its argument, so only the comment was misleading.)
  mutate: (material) => ({ ...material, e: 7n }),
};

// M3-H3 (M3.2.4b-2.15-H) -- inherited defect, remediated prospectively.
//
// The original implementation IGNORED its argument and returned
// TOY_PRIVATE_MATERIAL with recomputed exponents. That was self-consistent
// while the only caller was a unit test built on the toy key, but it
// silently breaks the class's own experimental meaning once Phase C feeds
// it the real frozen RSA-3072 material: fed a 3072-bit key it returned a
// 12-bit one, so the "divergence" observed would have been 3072-vs-12 bits
// -- a different universe, not a divergent material for the same key.
//
// The scientific INTENT is unchanged: same modulus, a different but still
// fully valid public exponent, with every dependent value recomputed so the
// tuple remains a genuine RSA private key. Only the implementation is
// corrected, so that it derives from its input:
//
//     n' = n,  p' = p,  q' = q,  e' = 7
//     d'   = e'^-1 mod lambda(n)
//     d'P  = d' mod (p-1)
//     d'Q  = d' mod (q-1)
//     q'Inv = qInv   (depends only on p and q, which are unchanged)
//
// e' = 7 is the same choice the original made, but its validity is now
// CHECKED rather than justified for one specific key: gcd(7, lambda(n)) = 1
// must hold, and a future key that fails it raises rather than silently
// producing a broken tuple.
//
// M2's frozen artifacts are untouched: this correction lives in the M3
// development tree, exactly as the M3-H1a/M3-H1b aggregation fixes did.
const DIVERGENT_PUBLIC_EXPONENT = 7n;

function egcd(a: bigint, b: bigint): { g: bigint; x: bigint; y: bigint } {
  if (b === 0n) return { g: a, x: 1n, y: 0n };
  const r = egcd(b, a % b);
  return { g: r.g, x: r.y, y: r.x - (a / b) * r.y };
}
function modInverse(a: bigint, m: bigint): bigint {
  const r = egcd(((a % m) + m) % m, m);
  if (r.g !== 1n) throw new Error(`no modular inverse: gcd=${r.g}`);
  return ((r.x % m) + m) % m;
}

export const RSA_SER_PRIVATE_MATERIAL_DIVERGENCE: MutationImplementation<RsaPrivateMaterial> = {
  mutationId: 'RSA-SER-PRIVATE-MATERIAL-DIVERGENCE',
  directInterventionTargets: ['e', 'd', 'dP', 'dQ'], // change e AND its derived exponents together -- e alone would break relations without matching d/dP/dQ
  mutate: (material) => {
    const { p, q } = material;
    // lambda(n) = lcm(p-1, q-1), the Carmichael function the contract's own
    // V_rel check uses. Pure modular arithmetic over already-frozen values:
    // nothing is generated, no cryptographic library is called.
    const pm = p - 1n;
    const qm = q - 1n;
    const lambda = (pm * qm) / egcd(pm, qm).g;

    if (egcd(DIVERGENT_PUBLIC_EXPONENT, lambda).g !== 1n) {
      throw new Error(
        `RSA-SER-PRIVATE-MATERIAL-DIVERGENCE: gcd(${DIVERGENT_PUBLIC_EXPONENT}, lambda(n)) != 1 for this key, ` +
        'so the divergent exponent would not yield a valid private key.',
      );
    }

    const d = modInverse(DIVERGENT_PUBLIC_EXPONENT, lambda);
    return {
      ...material, // n, p, q and qInv are preserved: same key, divergent material
      e: DIVERGENT_PUBLIC_EXPONENT,
      d,
      dP: d % pm,
      dQ: d % qm,
    };
  },
};

export const RSA_SER_MATERIAL_MUTATIONS = { RSA_SER_PUBLIC_MATERIAL_DIVERGENCE, RSA_SER_PRIVATE_MATERIAL_DIVERGENCE };

// ---------------------------------------------------------------------
// Artifact-level (DER bytes) structural/semantic tampering (9 of 17)
// All built on the REAL encodeSpki/encodePrivateKeyInfo/decodeTlv/
// decodeSequenceChildren/encodeSequence/encodeInteger -- never hand-rolled.
// ---------------------------------------------------------------------

export const RSA_SER_DER_IMPORT_BYPASS: MutationImplementation<{ readonly artifact: Uint8Array }> = {
  mutationId: 'RSA-SER-DER-IMPORT-BYPASS',
  directInterventionTargets: ['artifact'],
  mutate: (state) => ({ artifact: xorByte(state.artifact, 1) }), // corrupt the length byte -- DER-vs-BER violation territory
};

// INSPECTED during M3-H4 and deliberately NOT changed. Its small modulus is
// a CONSTRUCTED DER boundary case, not a TOY residue -- the distinction that
// matters is the field's causal function, not its size:
//     M3-H3   a TOY constant accidentally REPLACES experimental material
//     M3-H4   a TOY-oriented FORMULA degenerates to a no-op
//     here    a small constant intentionally constructs a DER boundary case
// Gamma_0 here is der-syntax, not material divergence, and a test pins the
// resulting 00 FF 01 INTEGER content so the intent rests on evidence rather
// than on this comment.
export const RSA_SER_DER_EXPORT_DIVERGENCE: MutationImplementation<RsaPublicMaterial> = {
  mutationId: 'RSA-SER-DER-EXPORT-DIVERGENCE',
  directInterventionTargets: ['n'],
  // A probe value likely to expose leading-zero/padding handling differences:
  // an n whose top byte is >=0x80, forcing the INTEGER encoder's own
  // leading-zero-byte insertion path (encodeInteger's own documented behavior).
  mutate: (material) => ({ ...material, n: 0xffn * 256n + 0x01n }),
};

export const RSA_SER_CONTAINER_IMPORT_BYPASS: MutationImplementation<{ readonly artifact: Uint8Array }> = {
  mutationId: 'RSA-SER-CONTAINER-IMPORT-BYPASS',
  directInterventionTargets: ['artifact'],
  mutate: (state) => {
    // Re-parse the real SPKI artifact and rebuild it with a 3-child outer
    // SEQUENCE (SPKI is frozen at exactly 2 children) -- structural
    // corruption via the real decode/encode primitives, never a hand
    // edited byte guess.
    const outer = decodeTlv(state.artifact, 0);
    const children = decodeSequenceChildren(outer);
    return { artifact: encodeSequence([...children.map((c) => encodeTlv(c.tag, c.content)), encodeInteger(0n)]) };
  },
};

// M3-H4 -- inherited defect, remediated prospectively.
//
// The original formula was `e: 65537n % material.n`, chosen so that the
// probe would stay below the toy modulus. It diverged correctly there
// (65537 mod 3233 = 877, distinct from the toy's own e=17) but degenerates
// to the IDENTITY on any real key: for a 3072-bit modulus, 65537 mod n is
// 65537, which is exactly the frozen key's own public exponent. So
//     mutate(F_0) = F_0     and     Delta(F_0, F_1) = 0
// -- the intervention disappears and the class measures nothing.
//
// This is a different failure mode from M3-H3, and worth distinguishing:
//     M3-H3  a TOY constant accidentally REPLACES the experimental material
//     M3-H4  a TOY-oriented FORMULA degenerates to a no-op
//
// The intent is unchanged: change e, and only e, to an admissible value
// distinct from the one received. The historic computation is kept as the
// FIRST choice, so the toy domain still yields 877 exactly as before, and a
// deterministic alternative is used only when it degenerates.
//
// No gcd(e', lambda(n)) check is imposed here: this mutation's input is
// RsaPublicMaterial, which carries no p or q, so such a check is not
// something the fixture could perform. The type's real constraints are
// respected rather than invented.
const CONTAINER_EXPORT_FALLBACK_EXPONENT = 7n;

export const RSA_SER_CONTAINER_EXPORT_DIVERGENCE: MutationImplementation<RsaPublicMaterial> = {
  mutationId: 'RSA-SER-CONTAINER-EXPORT-DIVERGENCE',
  directInterventionTargets: ['e'],
  mutate: (material) => {
    const historic = 65537n % material.n;
    // The postcondition the original silently lacked: the result must
    // actually differ from the input.
    const e = historic !== material.e && historic > 1n
      ? historic
      : CONTAINER_EXPORT_FALLBACK_EXPONENT;
    if (e === material.e) {
      throw new Error(
        'RSA-SER-CONTAINER-EXPORT-DIVERGENCE: no divergent public exponent available for this key ' +
        `(e=${material.e}); the intervention would be a no-op.`,
      );
    }
    return { ...material, e };
  },
};

export const RSA_SER_TRAILING_DATA_BYPASS: MutationImplementation<{ readonly artifact: Uint8Array }> = {
  mutationId: 'RSA-SER-TRAILING-DATA-BYPASS',
  directInterventionTargets: ['artifact'],
  mutate: (state) => {
    const withTrailer = new Uint8Array(state.artifact.length + 1);
    withTrailer.set(state.artifact, 0);
    withTrailer[state.artifact.length] = 0x00; // one trailing byte after an otherwise-valid, exactly-consumed DER object
    return { artifact: withTrailer };
  },
};

export const RSA_SER_ROLE_CONTAINER_BYPASS: MutationImplementation<{ readonly artifact: Uint8Array; readonly requestedRole: 'public' | 'private' }> = {
  mutationId: 'RSA-SER-ROLE-CONTAINER-BYPASS',
  directInterventionTargets: ['requestedRole'], // the artifact (a real, valid SPKI) is untouched; only the requested role is flipped
  mutate: (state) => ({ ...state, requestedRole: state.requestedRole === 'public' ? 'private' : 'public' }),
};

export const RSA_SER_OID_IMPORT_PROFILE_BYPASS: MutationImplementation<{ readonly artifact: Uint8Array }> = {
  mutationId: 'RSA-SER-OID-IMPORT-PROFILE-BYPASS',
  directInterventionTargets: ['artifact'],
  mutate: (state) => {
    // Re-parse the real SPKI and corrupt one byte inside the AlgorithmIdentifier's own OID content.
    const outer = decodeTlv(state.artifact, 0);
    const children = decodeSequenceChildren(outer, 2);
    const algId = children[0]!;
    const algChildren = decodeSequenceChildren(algId);
    const corruptedOid = encodeTlv(algChildren[0]!.tag, xorByte(algChildren[0]!.content, 0));
    const newAlgId = encodeSequence([corruptedOid, ...algChildren.slice(1).map((c) => encodeTlv(c.tag, c.content))]);
    return { artifact: encodeSequence([newAlgId, encodeTlv(children[1]!.tag, children[1]!.content)]) };
  },
};

export const RSA_SER_OID_EXPORT_DIVERGENCE: MutationImplementation<RsaPublicMaterial> = {
  mutationId: 'RSA-SER-OID-EXPORT-DIVERGENCE',
  directInterventionTargets: ['n'],
  mutate: (material) => ({ ...material, n: material.n + 2n }), // distinct probe from DER-EXPORT-DIVERGENCE's own leading-byte-forcing value
};

export const RSA_SER_PARAMETERS_IMPORT_PROFILE_BYPASS: MutationImplementation<{ readonly artifact: Uint8Array }> = {
  mutationId: 'RSA-SER-PARAMETERS-IMPORT-PROFILE-BYPASS',
  directInterventionTargets: ['artifact'],
  mutate: (state) => {
    // Replace AlgorithmIdentifier.parameters (the real NULL) with an INTEGER instead.
    const outer = decodeTlv(state.artifact, 0);
    const children = decodeSequenceChildren(outer, 2);
    const algChildren = decodeSequenceChildren(children[0]!);
    const oidTlv = algChildren[0]!;
    const newAlgId = encodeSequence([encodeTlv(oidTlv.tag, oidTlv.content), encodeInteger(0n)]); // INTEGER instead of NULL
    return { artifact: encodeSequence([newAlgId, encodeTlv(children[1]!.tag, children[1]!.content)]) };
  },
};

export const RSA_SER_PARAMETERS_EXPORT_CANONICALIZATION_DIVERGENCE: MutationImplementation<RsaPublicMaterial> = {
  mutationId: 'RSA-SER-PARAMETERS-EXPORT-CANONICALIZATION-DIVERGENCE',
  directInterventionTargets: ['e'],
  mutate: (material) => ({ ...material, e: 5n }), // a third, distinct valid-e probe from the other two export-divergence classes
};

export const RSA_SER_ARTIFACT_MUTATIONS = {
  RSA_SER_DER_IMPORT_BYPASS, RSA_SER_DER_EXPORT_DIVERGENCE,
  RSA_SER_CONTAINER_IMPORT_BYPASS, RSA_SER_CONTAINER_EXPORT_DIVERGENCE,
  RSA_SER_TRAILING_DATA_BYPASS, RSA_SER_ROLE_CONTAINER_BYPASS,
  RSA_SER_OID_IMPORT_PROFILE_BYPASS, RSA_SER_OID_EXPORT_DIVERGENCE,
  RSA_SER_PARAMETERS_IMPORT_PROFILE_BYPASS, RSA_SER_PARAMETERS_EXPORT_CANONICALIZATION_DIVERGENCE,
};

// ---------------------------------------------------------------------
// Material-validity artifact-transforms (3 of 17)
// ---------------------------------------------------------------------

export const RSA_SER_PUBLIC_VALIDITY_BYPASS: MutationImplementation<RsaPublicMaterial> = {
  mutationId: 'RSA-SER-PUBLIC-VALIDITY-BYPASS',
  directInterventionTargets: ['e'],
  mutate: (material) => ({ ...material, e: material.e + 1n }), // a valid odd e+1 is even -- fails checkPublicValidity's own "e odd" clause
};

export const RSA_SER_PRIVATE_DOMAIN_BYPASS: MutationImplementation<RsaPrivateMaterial> = {
  mutationId: 'RSA-SER-PRIVATE-DOMAIN-BYPASS',
  directInterventionTargets: ['q'],
  mutate: (material) => ({ ...material, q: material.p }), // p===q -- fails checkPrivateDomain's own "p !== q" clause
};

export const RSA_SER_PRIVATE_RELATIONAL_BYPASS: MutationImplementation<RsaPrivateMaterial> = {
  mutationId: 'RSA-SER-PRIVATE-RELATIONAL-BYPASS',
  directInterventionTargets: ['n', 'd', 'dP', 'dQ', 'qInv'], // one instance corrupts one relation; the others are left as the union of all five possible targets
  mutate: (material, stimulusInstanceId) => {
    switch (stimulusInstanceId) {
      case 'n-neq-pq': return { ...material, n: material.n + 1n };
      case 'ed-not-1': return { ...material, d: material.d + 1n };
      case 'edP-not-1': return { ...material, dP: material.dP + 1n };
      case 'edQ-not-1': return { ...material, dQ: material.dQ + 1n };
      case 'qqInv-not-1': return { ...material, qInv: material.qInv + 1n };
      default: throw new Error(`RSA-SER-PRIVATE-RELATIONAL-BYPASS: unknown stimulusInstanceId '${stimulusInstanceId}'`);
    }
  },
};

export const RSA_SER_VALIDITY_MUTATIONS = { RSA_SER_PUBLIC_VALIDITY_BYPASS, RSA_SER_PRIVATE_DOMAIN_BYPASS, RSA_SER_PRIVATE_RELATIONAL_BYPASS };

// ---------------------------------------------------------------------
// adapter-transform (1 of 17) and capability-transform (1 of 17)
// ---------------------------------------------------------------------

export interface RsaSerErrorMappingIntervention {
  readonly triggeringCondition: string;
  readonly declaredErrorClass: string;
}

export const RSA_SER_ERROR_MISCLASSIFICATION: MutationImplementation<RsaSerErrorMappingIntervention> = {
  mutationId: 'RSA-SER-ERROR-MISCLASSIFICATION',
  directInterventionTargets: ['declaredErrorClass'],
  mutate: (state) => ({
    ...state,
    declaredErrorClass: state.declaredErrorClass === 'invalid_key' ? 'malformed_artifact' : 'invalid_key',
  }),
};

export interface CapabilityDeclarationExperimentalView {
  readonly capabilityId: string;
  readonly kind: 'provider-support';
  readonly support: 'supported' | 'unsupported';
}

export const RSA_SER_PROVIDER_CAPABILITY_MISREPORT: MutationImplementation<CapabilityDeclarationExperimentalView> = {
  mutationId: 'RSA-SER-PROVIDER-CAPABILITY-MISREPORT',
  directInterventionTargets: ['support'],
  mutate: (state) => ({ ...state, support: state.support === 'supported' ? 'unsupported' : 'supported' }),
};

export const RSA_SER_NON_MATERIAL_MUTATIONS = {
  ...RSA_SER_ARTIFACT_MUTATIONS,
  ...RSA_SER_VALIDITY_MUTATIONS,
  RSA_SER_ERROR_MISCLASSIFICATION,
  RSA_SER_PROVIDER_CAPABILITY_MISREPORT,
};

export const RSA_SER_ALL_MUTATION_IDS: readonly string[] = [
  ...Object.values(RSA_SER_MATERIAL_MUTATIONS).map((m) => m.mutationId),
  ...Object.values(RSA_SER_NON_MATERIAL_MUTATIONS).map((m) => m.mutationId),
];

// Real encoders re-exported for the test file, so tests build artifacts via
// the same frozen M1 functions rather than any hand-rolled bytes.
export { encodeSpki, encodePrivateKeyInfo };
