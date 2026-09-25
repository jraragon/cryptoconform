// M2.4.6 -- GCM mutation implementations (13 of 13).
// Source of the request/artifact shapes: src/contract/gcm.ts (M1, unmodified).
// Applies the corrected M2.4.6a mechanism model throughout: each mutation's
// directInterventionTargets is a SUBSET of its own Gamma_0, never asserted
// equal to it, and no mutation invokes any adapter, evaluates any relation,
// or reads manifests/.

import {
  TAG_LEN_BYTES, MIN_ARTIFACT_LEN_BYTES,
  parseAeadArtifact, buildAeadArtifact,
  type GcmEncryptRequest,
} from '../../src/contract/gcm.js';
import type { MutationImplementation } from './framework.js';

function xorByte(bytes: Uint8Array, index: number): Uint8Array {
  const copy = new Uint8Array(bytes); // never mutate the input in place
  const i = index < 0 ? copy.length + index : index;
  copy[i] = (copy[i] ?? 0) ^ 0xff;
  return copy;
}

// ---------------------------------------------------------------------
// request-transform: GcmEncryptRequest fields (8 of 13)
// ---------------------------------------------------------------------

// A deterministic multi-block probe: 33 bytes spans two full AES blocks
// (16+16) plus one byte, a natural boundary-crossing choice for exposing
// block-counter/endianness divergences that a single-block plaintext could
// not -- distinct from the probe used by CIPHERTEXT-COMPUTATION-DIVERGENCE.
function multiBlockProbe(seed: number): Uint8Array {
  return Uint8Array.from({ length: 33 }, (_, i) => (i + seed) % 256);
}

export const GCM_PLAINTEXT_NORMALIZATION: MutationImplementation<GcmEncryptRequest> = {
  mutationId: 'GCM-PLAINTEXT-NORMALIZATION',
  directInterventionTargets: ['plaintext'], // gcm.ciphertext is a downstream consequence, never written here
  mutate: (fixture) => ({ ...fixture, plaintext: multiBlockProbe(1) }),
};

export const GCM_AAD_ABSENT_EMPTY_DIVERGENCE: MutationImplementation<GcmEncryptRequest> = {
  mutationId: 'GCM-AAD-ABSENT-EMPTY-DIVERGENCE',
  directInterventionTargets: ['aad'],
  mutate: (fixture) => ({ ...fixture, aad: fixture.aad === undefined ? new Uint8Array(0) : undefined }),
};

export const GCM_AAD_IGNORED: MutationImplementation<GcmEncryptRequest> = {
  mutationId: 'GCM-AAD-IGNORED',
  directInterventionTargets: ['aad'], // gcm.authentication is observed later, never written here
  mutate: (fixture) => ({
    ...fixture,
    aad: fixture.aad === undefined || fixture.aad.length === 0 ? new Uint8Array([0xaa]) : xorByte(fixture.aad, 0),
  }),
};

export const GCM_IV_INTERPRETATION_DIVERGENCE: MutationImplementation<GcmEncryptRequest> = {
  mutationId: 'GCM-IV-INTERPRETATION-DIVERGENCE',
  directInterventionTargets: ['iv'], // gcm.ciphertext is a downstream consequence, never written here
  mutate: (fixture) => ({ ...fixture, iv: xorByte(fixture.iv, -1) }), // last byte -- counter/endianness boundary
};

export const GCM_CIPHERTEXT_COMPUTATION_DIVERGENCE: MutationImplementation<GcmEncryptRequest> = {
  mutationId: 'GCM-CIPHERTEXT-COMPUTATION-DIVERGENCE',
  directInterventionTargets: ['plaintext'],
  mutate: (fixture) => ({ ...fixture, plaintext: multiBlockProbe(7) }), // distinct probe from PLAINTEXT-NORMALIZATION
};

export const GCM_KEY_PROFILE_BOUNDARY_BYPASS: MutationImplementation<GcmEncryptRequest> = {
  mutationId: 'GCM-KEY-PROFILE-BOUNDARY-BYPASS',
  directInterventionTargets: ['key'], // gcm.validation/gcm.cap.portable are consequences observed by R_val/R_cap, never written here
  mutate: (fixture) => ({ ...fixture, key: new Uint8Array(24) }), // AES-192-shaped key: provider-valid on some backends, outside the 256-bit portable profile
};

export const GCM_IV_PROFILE_BOUNDARY_BYPASS: MutationImplementation<GcmEncryptRequest> = {
  mutationId: 'GCM-IV-PROFILE-BOUNDARY-BYPASS',
  directInterventionTargets: ['iv'],
  mutate: (fixture) => ({ ...fixture, iv: new Uint8Array(16) }), // wider-than-portable IV, still natively acceptable to some backends
};

export const GCM_TAGLENGTH_PROFILE_BOUNDARY_BYPASS: MutationImplementation<GcmEncryptRequest> = {
  mutationId: 'GCM-TAGLENGTH-PROFILE-BOUNDARY-BYPASS',
  directInterventionTargets: ['tagLengthBits'],
  mutate: (fixture, stimulusInstanceId) => {
    const bitsByInstance: Record<string, number> = {
      'tagLength-80': 80,
      'tagLength-below-floor-16': 16,
      'tagLength-below-floor-0': 0,
    };
    const bits = bitsByInstance[stimulusInstanceId];
    if (bits === undefined) throw new Error(`GCM-TAGLENGTH-PROFILE-BOUNDARY-BYPASS: unknown stimulusInstanceId '${stimulusInstanceId}'`);
    return { ...fixture, tagLengthBits: bits };
  },
};

export const GCM_REQUEST_MUTATIONS: readonly MutationImplementation<GcmEncryptRequest>[] = [
  GCM_PLAINTEXT_NORMALIZATION,
  GCM_AAD_ABSENT_EMPTY_DIVERGENCE,
  GCM_AAD_IGNORED,
  GCM_IV_INTERPRETATION_DIVERGENCE,
  GCM_CIPHERTEXT_COMPUTATION_DIVERGENCE,
  GCM_KEY_PROFILE_BOUNDARY_BYPASS,
  GCM_IV_PROFILE_BOUNDARY_BYPASS,
  GCM_TAGLENGTH_PROFILE_BOUNDARY_BYPASS,
];

// ---------------------------------------------------------------------
// artifact-transform: post-hoc artifact/decrypt-input tampering (3 of 13)
// ---------------------------------------------------------------------

// State fed to a (future, M2.4.7-owned) decrypt call: the artifact plus the
// AAD supplied alongside it. AAD is explicitly NOT part of the artifact
// (src/contract/gcm.ts's own comment) -- an AAD-TAMPER stimulus therefore
// targets this field, never the artifact bytes.
export interface GcmDecryptStimulus {
  readonly artifact: Uint8Array;
  readonly aad: Uint8Array | undefined;
}

export const GCM_AUTHENTICATION_BYPASS: MutationImplementation<GcmDecryptStimulus> = {
  mutationId: 'GCM-AUTHENTICATION-BYPASS',
  // gcm.validation is the consequence R_val observes later, never written here.
  directInterventionTargets: ['artifact', 'aad'],
  mutate: (state, stimulusInstanceId) => {
    const parts = parseAeadArtifact(state.artifact);
    switch (stimulusInstanceId) {
      case 'TAG-TAMPER':
        return { ...state, artifact: buildAeadArtifact(parts.iv, parts.ciphertext, xorByte(parts.tag, 0)) };
      case 'IV-TAMPER':
        return { ...state, artifact: buildAeadArtifact(xorByte(parts.iv, 0), parts.ciphertext, parts.tag) };
      case 'CIPHERTEXT-TAMPER':
        return { ...state, artifact: buildAeadArtifact(parts.iv, xorByte(parts.ciphertext, 0), parts.tag) };
      case 'AAD-TAMPER':
        return { ...state, aad: state.aad === undefined || state.aad.length === 0 ? new Uint8Array([0xaa]) : xorByte(state.aad, 0) };
      default:
        throw new Error(`GCM-AUTHENTICATION-BYPASS: unknown stimulusInstanceId '${stimulusInstanceId}'`);
    }
  },
};

export const GCM_ARTIFACT_C_T_SWAP: MutationImplementation<{ readonly artifact: Uint8Array }> = {
  mutationId: 'GCM-ARTIFACT-C-T-SWAP',
  directInterventionTargets: ['artifact'],
  mutate: (state) => {
    const parts = parseAeadArtifact(state.artifact);
    // Swap ciphertext and tag positions -- only meaningful/comparable when
    // their lengths match (the minimal-ciphertext case, |C|=0 excluded;
    // callers select a fixture with |C|=TAG_LEN_BYTES for this class).
    if (parts.ciphertext.length !== TAG_LEN_BYTES) {
      throw new Error('GCM-ARTIFACT-C-T-SWAP requires a fixture whose ciphertext length equals the tag length (16 bytes)');
    }
    return { artifact: buildAeadArtifact(parts.iv, parts.tag, parts.ciphertext) };
  },
};

export const GCM_ARTIFACT_STRUCTURE_CORRUPTION: MutationImplementation<{ readonly artifact: Uint8Array }> = {
  mutationId: 'GCM-ARTIFACT-STRUCTURE-CORRUPTION',
  directInterventionTargets: ['artifact'],
  mutate: (state) => ({ artifact: state.artifact.slice(0, MIN_ARTIFACT_LEN_BYTES - 1) }), // below the structural floor -- malformed_artifact territory
};

export const GCM_ARTIFACT_MUTATIONS = { GCM_AUTHENTICATION_BYPASS, GCM_ARTIFACT_C_T_SWAP, GCM_ARTIFACT_STRUCTURE_CORRUPTION };

// ---------------------------------------------------------------------
// capability-transform (1 of 13)
// ---------------------------------------------------------------------

export interface CapabilityDeclarationExperimentalView {
  readonly capabilityId: string;
  readonly kind: 'provider-support';
  readonly support: 'supported' | 'unsupported';
}

export const GCM_PROVIDER_CAPABILITY_MISMATCH: MutationImplementation<CapabilityDeclarationExperimentalView> = {
  mutationId: 'GCM-PROVIDER-CAPABILITY-MISMATCH',
  directInterventionTargets: ['support'],
  mutate: (state) => ({ ...state, support: state.support === 'supported' ? 'unsupported' : 'supported' }),
};

// ---------------------------------------------------------------------
// adapter-transform (1 of 13)
// ---------------------------------------------------------------------

// Describes an intervened error-mapping the orchestrator would later wire
// into a harness-owned adapter call -- never src/adapters itself. Distinct
// from a NativeExceptionClass (§5.16): this represents the SDK-facing class
// the (mutated) adapter would wrongly report.
export interface GcmErrorMappingIntervention {
  readonly triggeringCondition: string; // e.g. 'undersized-ciphertext'
  readonly declaredErrorClass: string; // the (possibly wrong) SDK-facing class the mutated mapping reports
}

export const GCM_ERROR_MISCLASSIFICATION: MutationImplementation<GcmErrorMappingIntervention> = {
  mutationId: 'GCM-ERROR-MISCLASSIFICATION',
  directInterventionTargets: ['declaredErrorClass'],
  mutate: (state) => ({
    ...state,
    declaredErrorClass: state.declaredErrorClass === 'authentication_failure' ? 'invalid_parameter' : 'authentication_failure',
  }),
};

export const GCM_NON_REQUEST_MUTATIONS = {
  ...GCM_ARTIFACT_MUTATIONS,
  GCM_PROVIDER_CAPABILITY_MISMATCH,
  GCM_ERROR_MISCLASSIFICATION,
};

export const GCM_ALL_MUTATION_IDS: readonly string[] = [
  ...GCM_REQUEST_MUTATIONS.map((m) => m.mutationId),
  ...Object.values(GCM_NON_REQUEST_MUTATIONS).map((m) => m.mutationId),
];
