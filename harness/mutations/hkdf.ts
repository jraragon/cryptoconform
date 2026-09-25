// M2.4.6 -- HKDF mutation implementations (5 of 8; 3 flagged, see
// M2.4.6-CONTRACT.md -- HKDF-HASH-MISMATCH, HKDF-UNSUPPORTED-HASH-DECLARATION,
// HKDF-CAPABILITY-BOUNDARY-MISMATCH are not expressible as HkdfRequest
// field mutations and are deliberately not implemented here).
// Source of the request shape: src/contract/hkdf.ts (M1, unmodified).

import { MAX_L, type HkdfRequest } from '../../src/contract/hkdf.js';
import type { MutationImplementation } from './framework.js';

function xorFirstByte(bytes: Uint8Array): Uint8Array {
  const copy = new Uint8Array(bytes); // never mutate the input in place
  copy[0] = (copy[0] ?? 0) ^ 0xff;
  if (copy.length === 0) return new Uint8Array([0xff]); // deterministic extension for an empty array
  return copy;
}

export const HKDF_NULL_VS_EMPTY_SALT: MutationImplementation<HkdfRequest> = {
  mutationId: 'HKDF-NULL-VS-EMPTY-SALT',
  directInterventionTargets: ['salt'],
  mutate: (fixture) => ({
    ...fixture,
    salt: fixture.salt === undefined ? new Uint8Array(0) : undefined,
  }),
};

export const HKDF_INFO_TAMPER: MutationImplementation<HkdfRequest> = {
  mutationId: 'HKDF-INFO-TAMPER',
  directInterventionTargets: ['info'],
  mutate: (fixture) => ({ ...fixture, info: xorFirstByte(fixture.info) }),
};

export const HKDF_IKM_NORMALIZATION: MutationImplementation<HkdfRequest> = {
  mutationId: 'HKDF-IKM-NORMALIZATION',
  directInterventionTargets: ['ikm'],
  mutate: (fixture) => ({ ...fixture, ikm: xorFirstByte(fixture.ikm) }),
};

export const HKDF_LENGTH_WITHIN_DOMAIN_PERTURBATION: MutationImplementation<HkdfRequest> = {
  mutationId: 'HKDF-LENGTH-WITHIN-DOMAIN-PERTURBATION',
  directInterventionTargets: ['length'],
  mutate: (fixture) => {
    const perturbed = fixture.length + 1 <= MAX_L ? fixture.length + 1 : fixture.length - 1;
    return { ...fixture, length: perturbed };
  },
};

export const HKDF_LENGTH_BOUNDARY_CROSSING: MutationImplementation<HkdfRequest> = {
  mutationId: 'HKDF-LENGTH-BOUNDARY-CROSSING',
  directInterventionTargets: ['length'],
  mutate: (fixture, stimulusInstanceId) => {
    if (stimulusInstanceId === 'L=0') return { ...fixture, length: 0 };
    if (stimulusInstanceId === 'L=8161') return { ...fixture, length: MAX_L + 1 };
    throw new Error(`HKDF-LENGTH-BOUNDARY-CROSSING: unknown stimulusInstanceId '${stimulusInstanceId}'`);
  },
};

// ---------------------------------------------------------------------
// M2.4.6a: adapter-transform and capability-transform mechanisms.
// These act on DATA DESCRIBING an intervened invocation/declaration, never
// on HkdfRequest, and never actually invoke any adapter or cryptography --
// that remains M2.4.7's own orchestration concern. This keeps src/adapters
// and manifests/ completely untouched, per M2.4.6's own boundary.
// ---------------------------------------------------------------------

// Describes an HKDF adapter invocation the ORCHESTRATOR (M2.4.7) would
// later carry out -- the portable request plus which hash the adapter is
// actually told to use. The common profile fixes this to 'SHA-256'
// (src/contract/hkdf.ts's own comment); it is not a request field, so it
// cannot be mutated through HkdfRequest at all.
export interface HkdfAdapterInvocation {
  readonly request: HkdfRequest; // untouched by either mutation below
  readonly effectiveHash: string;
}

export const HKDF_HASH_MISMATCH: MutationImplementation<HkdfAdapterInvocation> = {
  mutationId: 'HKDF-HASH-MISMATCH',
  // hkdf.output is a CAUSAL CONSEQUENCE of this intervention, observed
  // later by R_byte -- never written directly here. hkdf.cap is R_cap's own
  // concern once the intervention is executed, also not written here.
  directInterventionTargets: ['effectiveHash'],
  // A real, implementable hash different from the fixed SHA-256 -- a
  // genuine byte-level divergence, not an unsupported-algorithm case
  // (that is HKDF-UNSUPPORTED-HASH-DECLARATION's own, distinct concern).
  mutate: (state) => ({ ...state, effectiveHash: 'SHA-384' }),
};

export const HKDF_UNSUPPORTED_HASH_DECLARATION: MutationImplementation<HkdfAdapterInvocation> = {
  mutationId: 'HKDF-UNSUPPORTED-HASH-DECLARATION',
  directInterventionTargets: ['effectiveHash'],
  mutate: (state) => ({
    ...state,
    // Declares/selects an algorithm outside the common profile's own
    // recognized set entirely -- distinct from HASH-MISMATCH's "a
    // different but real hash". No expected outcome is baked in here;
    // R_cap/R_val/R_err observe the consequence independently.
    effectiveHash: 'SHA3-256-UNRECOGNIZED',
  }),
};

// Describes a capability declaration the ORCHESTRATOR would later compare
// against observed effective capability (R_cap's own job, M2.4.4). This
// mutation acts on a COPY only -- FrozenManifest != MutatedExperimentalView
// is enforced by construction: mutate() never receives, and therefore
// cannot touch, the actual frozen manifest objects in manifests/.
export interface CapabilityDeclarationExperimentalView {
  readonly capabilityId: string;
  readonly kind: 'provider-support';
  readonly support: 'supported' | 'unsupported';
}

export const HKDF_CAPABILITY_BOUNDARY_MISMATCH: MutationImplementation<CapabilityDeclarationExperimentalView> = {
  mutationId: 'HKDF-CAPABILITY-BOUNDARY-MISMATCH',
  directInterventionTargets: ['support'],
  mutate: (state) => ({
    ...state,
    support: state.support === 'supported' ? 'unsupported' : 'supported',
  }),
};

export const HKDF_MUTATIONS: readonly MutationImplementation<HkdfRequest>[] = [
  HKDF_NULL_VS_EMPTY_SALT,
  HKDF_INFO_TAMPER,
  HKDF_IKM_NORMALIZATION,
  HKDF_LENGTH_WITHIN_DOMAIN_PERTURBATION,
  HKDF_LENGTH_BOUNDARY_CROSSING,
];

// The two adapter-transform and one capability-transform HKDF mutations,
// kept in their own list since their state type is not HkdfRequest.
export const HKDF_NON_REQUEST_MUTATIONS = {
  HKDF_HASH_MISMATCH,
  HKDF_UNSUPPORTED_HASH_DECLARATION,
  HKDF_CAPABILITY_BOUNDARY_MISMATCH,
};

// All eight, now that the mechanism model resolves the three that were
// previously flagged. Nothing here is silently missing.
export const HKDF_ALL_MUTATION_IDS: readonly string[] = [
  ...HKDF_MUTATIONS.map((m) => m.mutationId),
  ...Object.values(HKDF_NON_REQUEST_MUTATIONS).map((m) => m.mutationId),
];
