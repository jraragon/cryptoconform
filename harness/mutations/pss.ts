// M2.4.6 -- PSS mutation implementations (15 of 15).
// Source of the request shapes: src/contract/pss.ts (M1, unmodified).
// Key finding, verified before implementing: saltLengthBytes IS a
// PssSignRequest/PssVerifyRequest field (a request-transform target), but
// the actual RANDOM SALT BYTES themselves are never exposed as a field
// anywhere -- confirming PSS-SALT-BYTES-INTERFACE-LEAK genuinely needs
// adapter-transform, distinct from PSS-SALTLENGTH-PROFILE-BYPASS's own
// request-transform on saltLengthBytes.

import {
  MODULUS_BITS, PSS_HASH, SALT_LEN_BYTES,
  type PssSignRequest, type PssVerifyRequest, type PssKeyRef,
} from '../../src/contract/pss.js';
import type { MutationImplementation } from './framework.js';

function probe(length: number, seed: number): Uint8Array {
  return Uint8Array.from({ length }, (_, i) => (i + seed) % 256);
}

function xorByte(bytes: Uint8Array, index: number): Uint8Array {
  const copy = new Uint8Array(bytes);
  const i = index < 0 ? copy.length + index : index;
  copy[i] = (copy[i] ?? 0) ^ 0xff;
  return copy;
}

export function baseSignFixture(): PssSignRequest {
  return { key: { role: 'private', modulusBits: MODULUS_BITS }, message: new Uint8Array([1, 2, 3]), hash: PSS_HASH, mgfHash: PSS_HASH, saltLengthBytes: SALT_LEN_BYTES };
}

// ---------------------------------------------------------------------
// request-transform: PssSignRequest fields (7 of 15)
// ---------------------------------------------------------------------

export const PSS_SIGN_MESSAGE_NORMALIZATION: MutationImplementation<PssSignRequest> = {
  mutationId: 'PSS-SIGN-MESSAGE-NORMALIZATION',
  directInterventionTargets: ['message'], // pss.signature is a downstream consequence, never written here
  mutate: (fixture) => ({ ...fixture, message: probe(16, 1) }),
};

export const PSS_SIGNATURE_COMPUTATION_DIVERGENCE: MutationImplementation<PssSignRequest> = {
  mutationId: 'PSS-SIGNATURE-COMPUTATION-DIVERGENCE',
  directInterventionTargets: ['message'],
  mutate: (fixture) => ({ ...fixture, message: probe(64, 7) }), // a genuinely distinct probe from SIGN-MESSAGE-NORMALIZATION's
};

export const PSS_SIGNATURE_LENGTH_DIVERGENCE: MutationImplementation<PssSignRequest> = {
  mutationId: 'PSS-SIGNATURE-LENGTH-DIVERGENCE',
  directInterventionTargets: ['message'],
  mutate: (fixture) => ({ ...fixture, message: new Uint8Array(0) }), // zero-length probe: |signature|=K_BYTES always per the frozen profile
};

export const PSS_MODULUS_PROFILE_BYPASS: MutationImplementation<PssSignRequest> = {
  mutationId: 'PSS-MODULUS-PROFILE-BYPASS',
  directInterventionTargets: ['key'], // pss.validation/pss.cap.portable are consequences, never written here
  mutate: (fixture) => ({ ...fixture, key: { ...fixture.key, modulusBits: 2048 } }),
};

export const PSS_HASH_PROFILE_BYPASS: MutationImplementation<PssSignRequest> = {
  mutationId: 'PSS-HASH-PROFILE-BYPASS',
  directInterventionTargets: ['hash', 'mgfHash'], // stays coupled, isolates hash choice -- same discipline as OAEP-HASH-PROFILE-BYPASS
  mutate: (fixture) => ({ ...fixture, hash: 'SHA-384', mgfHash: 'SHA-384' }),
};

export const PSS_MGF_COUPLING_BYPASS: MutationImplementation<PssSignRequest> = {
  mutationId: 'PSS-MGF-COUPLING-BYPASS',
  directInterventionTargets: ['mgfHash'], // hash stays portable; only mgfHash decouples
  mutate: (fixture) => ({ ...fixture, hash: PSS_HASH, mgfHash: 'SHA-1' }),
};

export const PSS_SALTLENGTH_PROFILE_BYPASS: MutationImplementation<PssSignRequest> = {
  mutationId: 'PSS-SALTLENGTH-PROFILE-BYPASS',
  directInterventionTargets: ['saltLengthBytes'],
  mutate: (fixture) => ({ ...fixture, saltLengthBytes: 20 }), // provider-valid on WebCrypto/BC, non-portable (D-041)
};

export const PSS_REQUEST_MUTATIONS: readonly MutationImplementation<PssSignRequest>[] = [
  PSS_SIGN_MESSAGE_NORMALIZATION,
  PSS_SIGNATURE_COMPUTATION_DIVERGENCE,
  PSS_SIGNATURE_LENGTH_DIVERGENCE,
  PSS_MODULUS_PROFILE_BYPASS,
  PSS_HASH_PROFILE_BYPASS,
  PSS_MGF_COUPLING_BYPASS,
  PSS_SALTLENGTH_PROFILE_BYPASS,
];

// PSS-VERIFY-MESSAGE-NORMALIZATION acts on the verify side specifically
// (pss.verification, not pss.signature) -- a genuinely distinct request type.
export function baseVerifyFixture(): PssVerifyRequest {
  return { key: { role: 'public', modulusBits: MODULUS_BITS }, message: new Uint8Array([1, 2, 3]), signature: new Uint8Array(384), hash: PSS_HASH, mgfHash: PSS_HASH, saltLengthBytes: SALT_LEN_BYTES };
}

export const PSS_VERIFY_MESSAGE_NORMALIZATION: MutationImplementation<PssVerifyRequest> = {
  mutationId: 'PSS-VERIFY-MESSAGE-NORMALIZATION',
  directInterventionTargets: ['message'],
  mutate: (fixture) => ({ ...fixture, message: probe(16, 2) }),
};

// ---------------------------------------------------------------------
// PSS-KEY-ROLE-BYPASS (1 of 15): registry currently pre-registers a single
// stimulus instance ('default') -- implemented as sign-with-public,
// mirroring OAEP-KEY-ROLE-BYPASS's own discriminated-union shape so a
// second instance (verify-with-private) could be added later without a
// mechanism change, but only the frozen single instance is exercised here.
// ---------------------------------------------------------------------

export type PssKeyRoleBypassState =
  | { readonly kind: 'sign'; readonly request: PssSignRequest }
  | { readonly kind: 'verify'; readonly request: PssVerifyRequest };

function withRole<T extends { key: PssKeyRef }>(req: T, role: PssKeyRef['role']): T {
  return { ...req, key: { ...req.key, role } };
}

export const PSS_KEY_ROLE_BYPASS: MutationImplementation<PssKeyRoleBypassState> = {
  mutationId: 'PSS-KEY-ROLE-BYPASS',
  directInterventionTargets: ['request'],
  mutate: (state, stimulusInstanceId) => {
    if (stimulusInstanceId === 'default' && state.kind === 'sign') {
      return { kind: 'sign', request: withRole(state.request, 'public') }; // sign requires private; this presents public
    }
    throw new Error(`PSS-KEY-ROLE-BYPASS: stimulusInstanceId '${stimulusInstanceId}' does not match state.kind '${state.kind}'`);
  },
};

// ---------------------------------------------------------------------
// artifact-transform: verification-outcome classes (2 of 15)
// ---------------------------------------------------------------------

export interface PssVerificationStimulus {
  readonly message: Uint8Array;
  readonly signature: Uint8Array; // pre-established valid material, supplied externally -- mutate() never signs anything itself
}

export const PSS_VERIFICATION_FALSE_ACCEPT: MutationImplementation<PssVerificationStimulus> = {
  mutationId: 'PSS-VERIFICATION-FALSE-ACCEPT',
  directInterventionTargets: ['signature'],
  // Corrupts an otherwise-valid signature -- the correct verify() outcome is
  // false; a backend that instead returns true is the false-accept this
  // class exists to catch.
  mutate: (state) => ({ ...state, signature: xorByte(state.signature, -1) }),
};

export interface PssFalseRejectStimulus {
  readonly message: Uint8Array;
  readonly signature: Uint8Array; // the currently-presented, independently valid signature
  readonly alternateSignature: Uint8Array; // a second, independently valid signature for the SAME message (different randomness) -- both supplied externally, never generated here
}

export const PSS_VERIFICATION_FALSE_REJECT: MutationImplementation<PssFalseRejectStimulus> = {
  mutationId: 'PSS-VERIFICATION-FALSE-REJECT',
  directInterventionTargets: ['signature', 'alternateSignature'],
  // Swaps which of the two independently-valid signatures is "current" --
  // both are cryptographically valid for the same message; the correct
  // verify() outcome is true for either. A backend that incorrectly rejects
  // the swapped-in alternate (e.g. due to a subtle salt-handling bug) is the
  // false-reject this class exists to catch. No cryptography is executed
  // here -- both signatures are pre-established, only their roles swap.
  mutate: (state) => ({ ...state, signature: state.alternateSignature, alternateSignature: state.signature }),
};

export const PSS_ARTIFACT_MUTATIONS = { PSS_VERIFICATION_FALSE_ACCEPT, PSS_VERIFICATION_FALSE_REJECT };

// ---------------------------------------------------------------------
// adapter-transform (3 of 15): no request field exists for any of these --
// RNG control, explicit salt bytes, and error-class mapping all live
// outside PssSignRequest/PssVerifyRequest entirely.
// ---------------------------------------------------------------------

export interface PssAdapterInvocation {
  readonly request: PssSignRequest;
  readonly externalRandomnessProvided: boolean;
  readonly explicitSaltBytesProvided: boolean;
}

export const PSS_RNG_INTERFACE_LEAK: MutationImplementation<PssAdapterInvocation> = {
  mutationId: 'PSS-RNG-INTERFACE-LEAK',
  directInterventionTargets: ['externalRandomnessProvided'],
  mutate: (state) => ({ ...state, externalRandomnessProvided: !state.externalRandomnessProvided }),
};

export const PSS_SALT_BYTES_INTERFACE_LEAK: MutationImplementation<PssAdapterInvocation> = {
  mutationId: 'PSS-SALT-BYTES-INTERFACE-LEAK',
  directInterventionTargets: ['explicitSaltBytesProvided'],
  mutate: (state) => ({ ...state, explicitSaltBytesProvided: !state.explicitSaltBytesProvided }),
};

export interface PssErrorMappingIntervention {
  readonly triggeringCondition: string;
  readonly declaredErrorClass: string; // one of PSS's own three: unsupported | invalid_key | invalid_parameter (D-047)
}

export const PSS_ERROR_MISCLASSIFICATION: MutationImplementation<PssErrorMappingIntervention> = {
  mutationId: 'PSS-ERROR-MISCLASSIFICATION',
  directInterventionTargets: ['declaredErrorClass'],
  mutate: (state) => ({
    ...state,
    declaredErrorClass: state.declaredErrorClass === 'invalid_key' ? 'invalid_parameter' : 'invalid_key',
  }),
};

export const PSS_ADAPTER_MUTATIONS = { PSS_RNG_INTERFACE_LEAK, PSS_SALT_BYTES_INTERFACE_LEAK, PSS_ERROR_MISCLASSIFICATION };

// ---------------------------------------------------------------------
// capability-transform (1 of 15)
// ---------------------------------------------------------------------

export interface CapabilityDeclarationExperimentalView {
  readonly capabilityId: string;
  readonly kind: 'provider-support';
  readonly support: 'supported' | 'unsupported';
}

export const PSS_PROVIDER_CAPABILITY_MISREPORT: MutationImplementation<CapabilityDeclarationExperimentalView> = {
  mutationId: 'PSS-PROVIDER-CAPABILITY-MISREPORT',
  directInterventionTargets: ['support'],
  mutate: (state) => ({ ...state, support: state.support === 'supported' ? 'unsupported' : 'supported' }),
};

export const PSS_NON_SIGN_REQUEST_MUTATIONS = {
  PSS_VERIFY_MESSAGE_NORMALIZATION,
  PSS_KEY_ROLE_BYPASS,
  ...PSS_ARTIFACT_MUTATIONS,
  ...PSS_ADAPTER_MUTATIONS,
  PSS_PROVIDER_CAPABILITY_MISREPORT,
};

export const PSS_ALL_MUTATION_IDS: readonly string[] = [
  ...PSS_REQUEST_MUTATIONS.map((m) => m.mutationId),
  ...Object.values(PSS_NON_SIGN_REQUEST_MUTATIONS).map((m) => m.mutationId),
];
