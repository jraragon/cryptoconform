// M3.2.4b-2.13 -- GCM x artifact-transform fixture resolvers.
//
// 3 classes, 6 pairs, TWO shapes:
//     GcmDecryptStimulus  { artifact, aad }        GCM-AUTHENTICATION-BYPASS (4 stimuli)
//     { artifact }                                 C-T-SWAP, STRUCTURE-CORRUPTION
//
// Gamma_0 DOES discriminate here (gcm.authentication vs gcm.artifact),
// unlike PSS x artifact where both classes shared one clause and selection
// had to fall to directInterventionTargets.
//
// --- Consumes only QUALIFIED material ---
//
// The artifacts this group needs are the SDK-format ones frozen by the
// M3.2.4b-2.13 corpus remediation. The earlier GCM artifact record is
// SUPERSEDED -- it holds raw provider output, C||tag, which
// parseAeadArtifact rejects -- and the pool refuses to serve it through
// get()/valueOf(). This module never uses the audit accessor, so
//     HistoricalMaterial  intersect  EligibleExperimentalMaterial  =  empty
// holds by construction rather than by care.
//
// --- Two artifacts, because M2's own contract requires two ---
//
// GCM-ARTIFACT-C-T-SWAP throws unless |C| = TAG_LEN_BYTES, since swapping
// ciphertext and tag positions is only meaningful when their lengths match.
// The general artifact deliberately has |C| = 35, so it cannot serve that
// class, and the ct-len artifact is not used where a realistic payload
// length matters.
//
// --- No cryptography here ---
//
//     Resolver: QualifiedFrozenMaterial -> TFixture
//
// Validity was established by the corpus qualification gate (SDK-format
// parse, canonical round trip, genuine decryption, cross-checked IV). The
// resolver re-checks only the STRUCTURAL preconditions that are causal for
// each intervention -- the same discipline applied to V_pair in EC-ser --
// and never encrypts, decrypts or re-derives anything.

import type { GcmDecryptStimulus } from '../../mutations/gcm.js';
import { parseAeadArtifact, TAG_LEN_BYTES } from '../../../src/contract/gcm.js';
import type { FrozenMaterialPool } from '../material/pool.js';
import type { GcmValidArtifact, AesBaseMaterial } from '../material/schema.js';
import { PHASE_C_MATERIAL_IDS } from '../material/load.js';
import { MUTATION_REGISTRY } from '../../registry/mutations.js';
import { FixtureResolutionError } from './hkdf-request.js';
import { getMutationImplementation } from '../mutation-index.js';

export interface GcmArtifactStimulus {
  readonly artifact: Uint8Array;
}

const GCM_ARTIFACT_ENTRIES = MUTATION_REGISTRY.filter(
  (e) => e.operation === 'gcm' && e.mechanism === 'artifact-transform',
);

export const GCM_ARTIFACT_MUTATION_IDS: readonly string[] =
  GCM_ARTIFACT_ENTRIES.map((e) => e.mutationId).sort();

export const GCM_ARTIFACT_STIMULUS_PAIRS: readonly (readonly [string, string])[] =
  GCM_ARTIFACT_ENTRIES
    .flatMap((e) => e.stimulusInstances.map((s) => [e.mutationId, s.stimulusInstanceId] as const))
    .sort((a, b) => (a[0] === b[0] ? a[1].localeCompare(b[1]) : a[0].localeCompare(b[0])));

// Shape selection from the frozen Gamma_0: the authentication class is the
// one whose intervened clause is the authentication decision itself.
function gamma0Of(mutationId: string): readonly string[] {
  return GCM_ARTIFACT_ENTRIES.find((e) => e.mutationId === mutationId)?.gamma0 ?? [];
}

export function isGcmAuthenticationClass(mutationId: string): boolean {
  return gamma0Of(mutationId).some((c) => c.endsWith('.authentication'));
}

// Which class needs the equal-length artifact is derived from its own
// declared BEHAVIOUR, never from its id: each non-authentication class is
// probed once with a deliberately non-equal-length artifact, and those that
// refuse it are recorded. A future class carrying the same precondition is
// therefore picked up automatically.
const EQUAL_LENGTH_REQUIRED: Set<string> = new Set<string>();

function classifyByPrecondition(pool: FrozenMaterialPool): void {
  if (EQUAL_LENGTH_REQUIRED.size > 0) return;
  const general = pool.valueOf<GcmValidArtifact>(PHASE_C_MATERIAL_IDS.gcmSdkArtifactGeneral, 'gcm-valid-artifact');
  for (const entry of GCM_ARTIFACT_ENTRIES) {
    if (isGcmAuthenticationClass(entry.mutationId)) continue;
    try {
      getMutationImplementation(entry.mutationId).mutate({ artifact: new Uint8Array(general.ciphertext) }, 'default');
    } catch {
      EQUAL_LENGTH_REQUIRED.add(entry.mutationId);
    }
  }
}

function assertRegistered(mutationId: string, stimulusInstanceId: string): void {
  const known = GCM_ARTIFACT_STIMULUS_PAIRS.some(([m, s]) => m === mutationId && s === stimulusInstanceId);
  if (!known) {
    throw new FixtureResolutionError(
      `(${mutationId}, ${stimulusInstanceId}) is not a registered gcm x artifact-transform stimulus pair.`,
    );
  }
}

// Loads a qualified SDK artifact and re-checks the structural precondition
// that is causal for the calling intervention.
function qualifiedArtifact(pool: FrozenMaterialPool, materialId: string, requireEqualLengths: boolean): Uint8Array {
  const record = pool.valueOf<GcmValidArtifact>(materialId, 'gcm-valid-artifact');
  const bytes = new Uint8Array(record.ciphertext);

  // Causal precondition for EVERY class in this group: all three mutations
  // begin by parsing the artifact, so an unparseable A_0 would make the
  // intervention throw rather than intervene.
  const parts = parseAeadArtifact(bytes);

  if (requireEqualLengths && parts.ciphertext.length !== TAG_LEN_BYTES) {
    throw new FixtureResolutionError(
      `${materialId}: |C|=${parts.ciphertext.length}, but this intervention requires |C|=${TAG_LEN_BYTES}; ` +
      'swapping ciphertext and tag is only meaningful when their lengths match.',
    );
  }
  return bytes;
}

// ---------------------------------------------------------------------
// Resolver A: GcmDecryptStimulus -- artifact plus AAD
// ---------------------------------------------------------------------

export function resolveGcmAuthenticationFixture(
  mutationId: string,
  stimulusInstanceId: string,
  pool: FrozenMaterialPool,
): GcmDecryptStimulus {
  assertRegistered(mutationId, stimulusInstanceId);
  if (!isGcmAuthenticationClass(mutationId)) {
    throw new FixtureResolutionError(`${mutationId} does not use GcmDecryptStimulus.`);
  }

  // All four stimuli receive the SAME base fixture: which of tag/IV/
  // ciphertext/AAD is perturbed is chosen inside mutate(), not here.
  const artifact = qualifiedArtifact(pool, PHASE_C_MATERIAL_IDS.gcmSdkArtifactGeneral, false);
  const aes = pool.valueOf<AesBaseMaterial>(PHASE_C_MATERIAL_IDS.aes, 'aes-base-material');

  // The AAD must be the one the artifact was actually produced under,
  // otherwise the baseline would already fail authentication and the
  // AAD-TAMPER stimulus would perturb an already-broken state. It is also
  // non-empty, which is what makes that stimulus exercise a real
  // perturbation rather than the substitution branch.
  const aad = aes.aad === undefined ? undefined : new Uint8Array(aes.aad);
  return { artifact, aad };
}

// ---------------------------------------------------------------------
// Resolver B: GcmArtifactStimulus -- artifact alone
// ---------------------------------------------------------------------

export function resolveGcmArtifactStimulusFixture(
  mutationId: string,
  stimulusInstanceId: string,
  pool: FrozenMaterialPool,
): GcmArtifactStimulus {
  assertRegistered(mutationId, stimulusInstanceId);
  if (isGcmAuthenticationClass(mutationId)) {
    throw new FixtureResolutionError(`${mutationId} uses GcmDecryptStimulus, not a bare artifact stimulus.`);
  }

  classifyByPrecondition(pool);
  const needsEqualLengths = EQUAL_LENGTH_REQUIRED.has(mutationId);
  const materialId = needsEqualLengths
    ? PHASE_C_MATERIAL_IDS.gcmSdkArtifactCtLen
    : PHASE_C_MATERIAL_IDS.gcmSdkArtifactGeneral;

  return { artifact: qualifiedArtifact(pool, materialId, needsEqualLengths) };
}

export function resolveGcmArtifactFixture(
  mutationId: string,
  stimulusInstanceId: string,
  pool: FrozenMaterialPool,
): GcmDecryptStimulus | GcmArtifactStimulus {
  return isGcmAuthenticationClass(mutationId)
    ? resolveGcmAuthenticationFixture(mutationId, stimulusInstanceId, pool)
    : resolveGcmArtifactStimulusFixture(mutationId, stimulusInstanceId, pool);
}

/**
 * M3.7.3 -- which frozen artifact record an artifact-side GCM class consumes.
 *
 * PROPAGATES the resolver's own decision. EQUAL_LENGTH_REQUIRED is the frozen
 * precondition classification, and the ct-len record is the one whose producer
 * needs D17's promoted plaintext so that |C| = |tag|.
 */
export function gcmConsumedArtifactId(mutationId: string, pool: FrozenMaterialPool): string {
  classifyByPrecondition(pool);
  return EQUAL_LENGTH_REQUIRED.has(mutationId)
    ? PHASE_C_MATERIAL_IDS.gcmSdkArtifactCtLen
    : PHASE_C_MATERIAL_IDS.gcmSdkArtifactGeneral;
}
