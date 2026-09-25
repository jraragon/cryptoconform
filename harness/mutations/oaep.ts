// M2.4.6 -- OAEP mutation implementations (12 of 12).
// Source of the request shapes: src/contract/oaep.ts (M1, unmodified).
// Key finding, verified before implementing (not assumed from HKDF/GCM):
// OaepEncryptRequest/OaepDecryptRequest DO expose `hash` and `mgfHash`
// directly as request fields -- unlike HKDF, where the hash choice lived
// entirely outside HkdfRequest. OAEP-HASH-PROFILE-BYPASS and
// OAEP-MGF-COUPLING-BYPASS are therefore genuine request-transforms, never
// needing adapter-transform.

import {
  MAX_MESSAGE_LEN_BYTES, OAEP_HASH,
  type OaepEncryptRequest, type OaepDecryptRequest, type OaepKeyRef,
} from '../../src/contract/oaep.js';
import type { MutationImplementation } from './framework.js';

function probe(length: number, seed: number): Uint8Array {
  return Uint8Array.from({ length }, (_, i) => (i + seed) % 256);
}

// ---------------------------------------------------------------------
// request-transform: OaepEncryptRequest fields (8 of 12)
// ---------------------------------------------------------------------

export const OAEP_MESSAGE_NORMALIZATION: MutationImplementation<OaepEncryptRequest> = {
  mutationId: 'OAEP-MESSAGE-NORMALIZATION',
  directInterventionTargets: ['plaintext'], // oaep.ciphertext is a downstream consequence, never written here
  mutate: (fixture) => ({ ...fixture, plaintext: probe(16, 1) }),
};

export const OAEP_CIPHERTEXT_COMPUTATION_DIVERGENCE: MutationImplementation<OaepEncryptRequest> = {
  mutationId: 'OAEP-CIPHERTEXT-COMPUTATION-DIVERGENCE',
  directInterventionTargets: ['plaintext'],
  mutate: (fixture) => ({ ...fixture, plaintext: probe(MAX_MESSAGE_LEN_BYTES, 3) }), // full-length probe, a genuinely different boundary from MESSAGE-NORMALIZATION's short probe
};

export const OAEP_CIPHERTEXT_LENGTH_DIVERGENCE: MutationImplementation<OaepEncryptRequest> = {
  mutationId: 'OAEP-CIPHERTEXT-LENGTH-DIVERGENCE',
  directInterventionTargets: ['plaintext'],
  mutate: (fixture) => ({ ...fixture, plaintext: new Uint8Array(0) }), // zero-length probe -- |C|=k=384 always per the frozen profile; this is the other boundary from COMPUTATION-DIVERGENCE's full-length probe
};

export const OAEP_MODULUS_PROFILE_BYPASS: MutationImplementation<OaepEncryptRequest> = {
  mutationId: 'OAEP-MODULUS-PROFILE-BYPASS',
  // 'key' is the top-level field replaced (modulusBits lives nested inside
  // it); oaep.validation/oaep.cap.portable are consequences, never written here.
  directInterventionTargets: ['key'],
  mutate: (fixture) => ({ ...fixture, key: { ...fixture.key, modulusBits: 2048 } }), // provider-valid, non-portable modulus size
};

export const OAEP_HASH_PROFILE_BYPASS: MutationImplementation<OaepEncryptRequest> = {
  mutationId: 'OAEP-HASH-PROFILE-BYPASS',
  directInterventionTargets: ['hash', 'mgfHash'], // coupled: SHA-512 for BOTH, isolating hash choice from MGF-coupling per the registry's own note
  mutate: (fixture) => ({ ...fixture, hash: 'SHA-512', mgfHash: 'SHA-512' }),
};

export const OAEP_MGF_COUPLING_BYPASS: MutationImplementation<OaepEncryptRequest> = {
  mutationId: 'OAEP-MGF-COUPLING-BYPASS',
  directInterventionTargets: ['mgfHash'], // hash stays at the portable SHA-256; only mgfHash decouples
  mutate: (fixture) => ({ ...fixture, hash: OAEP_HASH, mgfHash: 'SHA-1' }),
};

export const OAEP_LABEL_PROFILE_BYPASS: MutationImplementation<OaepEncryptRequest> = {
  mutationId: 'OAEP-LABEL-PROFILE-BYPASS',
  directInterventionTargets: ['label'],
  mutate: (fixture) => ({ ...fixture, label: new Uint8Array([0x01]) }), // non-empty label -- portable profile requires L=empty
};

export const OAEP_MESSAGE_BOUNDARY_BYPASS: MutationImplementation<OaepEncryptRequest> = {
  mutationId: 'OAEP-MESSAGE-BOUNDARY-BYPASS',
  directInterventionTargets: ['plaintext'],
  mutate: (fixture) => ({ ...fixture, plaintext: probe(MAX_MESSAGE_LEN_BYTES + 1, 5) }), // one byte beyond the portable bound
};

export const OAEP_REQUEST_MUTATIONS: readonly MutationImplementation<OaepEncryptRequest>[] = [
  OAEP_MESSAGE_NORMALIZATION,
  OAEP_CIPHERTEXT_COMPUTATION_DIVERGENCE,
  OAEP_CIPHERTEXT_LENGTH_DIVERGENCE,
  OAEP_MODULUS_PROFILE_BYPASS,
  OAEP_HASH_PROFILE_BYPASS,
  OAEP_MGF_COUPLING_BYPASS,
  OAEP_LABEL_PROFILE_BYPASS,
  OAEP_MESSAGE_BOUNDARY_BYPASS,
];

// ---------------------------------------------------------------------
// OAEP-KEY-ROLE-BYPASS (1 of 12): two instances need genuinely different
// base request shapes (encrypt vs decrypt) -- modeled as a discriminated
// union so ONE mutationId still covers both, per the standing rule that a
// class with multiple StimulusInstances never becomes multiple mutationIds.
// ---------------------------------------------------------------------

export type OaepKeyRoleBypassState =
  | { readonly kind: 'encrypt'; readonly request: OaepEncryptRequest }
  | { readonly kind: 'decrypt'; readonly request: OaepDecryptRequest };

function withRole<T extends { key: OaepKeyRef }>(req: T, role: OaepKeyRef['role']): T {
  return { ...req, key: { ...req.key, role } };
}

export const OAEP_KEY_ROLE_BYPASS: MutationImplementation<OaepKeyRoleBypassState> = {
  mutationId: 'OAEP-KEY-ROLE-BYPASS',
  directInterventionTargets: ['request'], // 'kind' (the discriminant) is never touched
  mutate: (state, stimulusInstanceId) => {
    if (stimulusInstanceId === 'encrypt-with-private' && state.kind === 'encrypt') {
      return { kind: 'encrypt', request: withRole(state.request, 'private') };
    }
    if (stimulusInstanceId === 'decrypt-with-public' && state.kind === 'decrypt') {
      return { kind: 'decrypt', request: withRole(state.request, 'public') };
    }
    throw new Error(`OAEP-KEY-ROLE-BYPASS: stimulusInstanceId '${stimulusInstanceId}' does not match state.kind '${state.kind}'`);
  },
};

// ---------------------------------------------------------------------
// adapter-transform (2 of 12): no request field exists for either --
// OaepEncryptRequest has no randomness-control field at all, and error
// classification is an adapter-internal mapping concern, not request data.
// ---------------------------------------------------------------------

export interface OaepAdapterInvocation {
  readonly request: OaepEncryptRequest;
  readonly externalRandomnessProvided: boolean; // native RNG-injection control, absent from the portable request entirely
}

export const OAEP_RANDOMNESS_INTERFACE_LEAK: MutationImplementation<OaepAdapterInvocation> = {
  mutationId: 'OAEP-RANDOMNESS-INTERFACE-LEAK',
  directInterventionTargets: ['externalRandomnessProvided'],
  mutate: (state) => ({ ...state, externalRandomnessProvided: !state.externalRandomnessProvided }),
};

export interface OaepErrorMappingIntervention {
  readonly triggeringCondition: string;
  readonly declaredErrorClass: string;
}

export const OAEP_DECRYPT_ERROR_DISCLOSURE: MutationImplementation<OaepErrorMappingIntervention> = {
  mutationId: 'OAEP-DECRYPT-ERROR-DISCLOSURE',
  directInterventionTargets: ['declaredErrorClass'],
  mutate: (state) => ({
    ...state,
    // The frozen contract collapses several native causes to decryption_error
    // (RFC 8017's own anti-oracle rule, D-034); this intervention reports a
    // MORE SPECIFIC (and therefore wrong, oracle-leaking) class instead.
    declaredErrorClass: state.declaredErrorClass === 'decryption_error' ? 'invalid_key' : 'decryption_error',
  }),
};

export const OAEP_ADAPTER_MUTATIONS = { OAEP_RANDOMNESS_INTERFACE_LEAK, OAEP_DECRYPT_ERROR_DISCLOSURE };

// ---------------------------------------------------------------------
// capability-transform (1 of 12)
// ---------------------------------------------------------------------

export interface CapabilityDeclarationExperimentalView {
  readonly capabilityId: string;
  readonly kind: 'provider-support';
  readonly support: 'supported' | 'unsupported';
}

export const OAEP_PROVIDER_CAPABILITY_MISREPORT: MutationImplementation<CapabilityDeclarationExperimentalView> = {
  mutationId: 'OAEP-PROVIDER-CAPABILITY-MISREPORT',
  directInterventionTargets: ['support'],
  mutate: (state) => ({ ...state, support: state.support === 'supported' ? 'unsupported' : 'supported' }),
};

export const OAEP_NON_REQUEST_MUTATIONS = {
  OAEP_KEY_ROLE_BYPASS,
  ...OAEP_ADAPTER_MUTATIONS,
  OAEP_PROVIDER_CAPABILITY_MISREPORT,
};

export const OAEP_ALL_MUTATION_IDS: readonly string[] = [
  ...OAEP_REQUEST_MUTATIONS.map((m) => m.mutationId),
  ...Object.values(OAEP_NON_REQUEST_MUTATIONS).map((m) => m.mutationId),
];
