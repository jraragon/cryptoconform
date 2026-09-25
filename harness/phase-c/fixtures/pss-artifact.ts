// M3.2.4b-2.8 -- PSS x artifact-transform fixture resolvers.
//
// The project's FIRST artifact-transform group. 2 classes, 2 pairs, TWO
// shapes -- they do not share one merely because both are
// artifact-transform:
//
//   PssVerificationStimulus  { message, signature }
//   PssFalseRejectStimulus   { message, signature, alternateSignature }
//
// --- The additional property this mechanism requires ---
//
//     Valid(A_0) = true   BEFORE   A_m = mutate(A_0, s)
//
// Established by IDENTITY to already-validated frozen material, not by
// re-verifying inside the resolver. A_0 is loaded from the pool, whose
// records were cryptographically validated and cross-provider qualified in
// M3.2.4a-6 (and, for the second signature, in this step). Making the
// resolver a PSS verifier would duplicate scientific semantics in the
// binding layer -- exactly what Binding != ScientificSemantics forbids.
// The tests assert byte-identity with the frozen artifacts, and separately
// re-verify cryptographically, keeping that check outside the resolver.
//
// --- Why a second frozen signature was required ---
//
// PSS-VERIFICATION-FALSE-REJECT's mutate() SWAPS which of two signatures is
// current, and the correct verify() outcome is true for BOTH. A second
// signature that were inert or invalid would invert the experiment: the
// swap would produce a legitimate rejection, and the class exists precisely
// to catch an ILLEGITIMATE one. So sigma_02 is FrozenCryptographicMaterial,
// generated once and cross-provider qualified alongside sigma_01, with
//     M_02 = M_01,  K_02 = K_01,  sigma_02 != sigma_01
// This contrasts with OAEP's inert ciphertext, which Gamma_0 never reached.

import type { PssVerificationStimulus, PssFalseRejectStimulus } from '../../mutations/pss.js';
import type { FrozenMaterialPool } from '../material/pool.js';
import type { PssValidSignatureArtifact } from '../material/schema.js';
import { PHASE_C_MATERIAL_IDS } from '../material/load.js';
import { MUTATION_REGISTRY } from '../../registry/mutations.js';
import { FixtureResolutionError } from './hkdf-request.js';
import { getMutationImplementation } from '../mutation-index.js';

// The second frozen signature. Not in PHASE_C_MATERIAL_IDS' original set:
// it was a corpus extension discovered during exhaustive binding, appended
// without touching sigma_01's value, schema or hash.
export const PSS_SECOND_SIGNATURE_MATERIAL_ID = 'pss-valid-signature-02';

const PSS_ARTIFACT_ENTRIES = MUTATION_REGISTRY.filter(
  (e) => e.operation === 'pss' && e.mechanism === 'artifact-transform',
);

export const PSS_ARTIFACT_MUTATION_IDS: readonly string[] =
  PSS_ARTIFACT_ENTRIES.map((e) => e.mutationId).sort();

export const PSS_ARTIFACT_STIMULUS_PAIRS: readonly (readonly [string, string])[] =
  PSS_ARTIFACT_ENTRIES
    .flatMap((e) => e.stimulusInstances.map((s) => [e.mutationId, s.stimulusInstanceId] as const))
    .sort((a, b) => (a[0] === b[0] ? a[1].localeCompare(b[1]) : a[0].localeCompare(b[0])));

// Both classes share Gamma_0 = { pss.verification }, so Gamma_0 cannot
// separate them here -- the first group where it could not. Shape selection
// is instead derived from each implementation's OWN declared
// directInterventionTargets, read from the global mutation index: the
// false-reject class is the one that intervenes on an 'alternateSignature'
// field, which is precisely what makes it need a second signature.
export function isPssFalseRejectClass(mutationId: string): boolean {
  return getMutationImplementation(mutationId)
    .directInterventionTargets.some((t) => String(t).toLowerCase().includes('alternate'));
}

function assertRegistered(mutationId: string, stimulusInstanceId: string): void {
  const known = PSS_ARTIFACT_STIMULUS_PAIRS.some(([m, s]) => m === mutationId && s === stimulusInstanceId);
  if (!known) {
    throw new FixtureResolutionError(
      `(${mutationId}, ${stimulusInstanceId}) is not a registered pss x artifact-transform stimulus pair.`,
    );
  }
}

function frozenSignature(pool: FrozenMaterialPool, materialId: string): PssValidSignatureArtifact {
  return pool.valueOf<PssValidSignatureArtifact>(materialId, 'pss-valid-signature');
}

// ---------------------------------------------------------------------
// Resolver A: PssVerificationStimulus -- one valid signature
// ---------------------------------------------------------------------

export function resolvePssVerificationStimulusFixture(
  mutationId: string,
  stimulusInstanceId: string,
  pool: FrozenMaterialPool,
): PssVerificationStimulus {
  assertRegistered(mutationId, stimulusInstanceId);
  const a0 = frozenSignature(pool, PHASE_C_MATERIAL_IDS.pssSignature);
  // Fresh copies: a mutation must never be able to reach back into the
  // frozen corpus, nor contaminate the next resolution.
  return { message: new Uint8Array(a0.message), signature: new Uint8Array(a0.signature) };
}

// ---------------------------------------------------------------------
// Resolver B: PssFalseRejectStimulus -- TWO independently valid signatures
// ---------------------------------------------------------------------

export function resolvePssFalseRejectStimulusFixture(
  mutationId: string,
  stimulusInstanceId: string,
  pool: FrozenMaterialPool,
): PssFalseRejectStimulus {
  assertRegistered(mutationId, stimulusInstanceId);
  const first = frozenSignature(pool, PHASE_C_MATERIAL_IDS.pssSignature);
  const second = frozenSignature(pool, PSS_SECOND_SIGNATURE_MATERIAL_ID);

  // The pair's own preconditions, checked structurally here because a
  // violation would silently invert this class's experiment. The
  // cryptographic validity of each is established by the freeze, not
  // re-derived here.
  if (Buffer.compare(Buffer.from(first.message), Buffer.from(second.message)) !== 0) {
    throw new FixtureResolutionError('the two frozen signatures do not cover the same message');
  }
  if (Buffer.compare(Buffer.from(first.signature), Buffer.from(second.signature)) === 0) {
    throw new FixtureResolutionError('the two frozen signatures are identical; the swap would be a no-op');
  }
  if (first.sourceMaterialId !== second.sourceMaterialId) {
    throw new FixtureResolutionError('the two frozen signatures were made under different keys');
  }

  return {
    message: new Uint8Array(first.message),
    signature: new Uint8Array(first.signature),
    alternateSignature: new Uint8Array(second.signature),
  };
}

export function resolvePssArtifactFixture(
  mutationId: string,
  stimulusInstanceId: string,
  pool: FrozenMaterialPool,
): PssVerificationStimulus | PssFalseRejectStimulus {
  return isPssFalseRejectClass(mutationId)
    ? resolvePssFalseRejectStimulusFixture(mutationId, stimulusInstanceId, pool)
    : resolvePssVerificationStimulusFixture(mutationId, stimulusInstanceId, pool);
}
