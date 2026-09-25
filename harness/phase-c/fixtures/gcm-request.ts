// M3.2.4b-2.2 -- GCM x request-transform fixture resolver.
//
//     Resolver: (mutationId, stimulusInstanceId, FrozenMaterialPool) -> GcmEncryptRequest
//
// Same contract as the HKDF resolver (H1..H5), and the same general
// principle confirmed there:
//     stimulusInstanceId in ResolverInput  =/=>  it influences baseFixture
// The resolver consults it only where the BASE fixture genuinely depends on
// the stimulus. Where the differentiation already lives in mutate(), the
// binding layer must not duplicate it.
//
// Inspection findings for this group, verified against the real types
// rather than carried over from HKDF:
//   - All 8 request-transform classes share exactly one shape,
//     GcmEncryptRequest. (GCM's other classes belong to different
//     mechanisms with different types.)
//   - 10 (class, stimulus) pairs, not 8: GCM-TAGLENGTH-PROFILE-BOUNDARY-
//     BYPASS carries three (tagLength-80, -below-floor-16, -below-floor-0).
//   - Only that one class consumes stimulusInstanceId, and it does so
//     inside its own mutate(). The base fixture is therefore
//     stimulus-independent across this entire group.
//   - The frozen GCM ciphertext artifact is NOT needed here. A0_GCM belongs
//     to GCM x artifact-transform, whose fixtures are ciphertexts rather
//     than encrypt requests -- confirmed from the real TFixture types, not
//     assumed from the architectural expectation.

import type { GcmEncryptRequest } from '../../../src/contract/gcm.js';
import { KEY_LEN_BYTES, IV_LEN_BYTES, TAG_LEN_BYTES } from '../../../src/contract/gcm.js';
import type { FrozenMaterialPool } from '../material/pool.js';
import type { AesBaseMaterial } from '../material/schema.js';
import { PHASE_C_MATERIAL_IDS } from '../material/load.js';
import { MUTATION_REGISTRY } from '../../registry/mutations.js';
import { FixtureResolutionError } from './hkdf-request.js';

// The one structural parameter GcmEncryptRequest carries that the frozen
// pool does not supply. AesBaseMaterial holds key/iv/plaintext/aad (all
// byte material); the requested tag length is a scalar property of the
// request, not material. Fixed as a named constant derived from the frozen
// portable profile itself rather than an inline literal.
export const GCM_BASELINE_TAG_LENGTH_BITS = TAG_LEN_BYTES * 8;

export const GCM_REQUEST_MUTATION_IDS: readonly string[] = MUTATION_REGISTRY
  .filter((e) => e.operation === 'gcm' && e.mechanism === 'request-transform')
  .map((e) => e.mutationId)
  .sort();

export const GCM_REQUEST_STIMULUS_PAIRS: readonly (readonly [string, string])[] = MUTATION_REGISTRY
  .filter((e) => e.operation === 'gcm' && e.mechanism === 'request-transform')
  .flatMap((e) => e.stimulusInstances.map((s) => [e.mutationId, s.stimulusInstanceId] as const))
  .sort((a, b) => (a[0] === b[0] ? a[1].localeCompare(b[1]) : a[0].localeCompare(b[0])));

export function resolveGcmRequestFixture(
  mutationId: string,
  stimulusInstanceId: string,
  pool: FrozenMaterialPool,
): GcmEncryptRequest {
  const known = GCM_REQUEST_STIMULUS_PAIRS.some(([m, s]) => m === mutationId && s === stimulusInstanceId);
  if (!known) {
    throw new FixtureResolutionError(
      `(${mutationId}, ${stimulusInstanceId}) is not a registered gcm x request-transform stimulus pair.`,
    );
  }

  const material = pool.valueOf<AesBaseMaterial>(PHASE_C_MATERIAL_IDS.aes, 'aes-base-material');

  // The pool schema already enforces these widths, but the base fixture must
  // be contractually valid pre-mutation under GCM's own portable profile, so
  // the agreement between the two frozen layers is checked rather than
  // assumed -- a divergence would otherwise surface only as a confusing
  // Accept_C rejection much later.
  if (material.key.length !== KEY_LEN_BYTES || material.iv.length !== IV_LEN_BYTES) {
    throw new FixtureResolutionError(
      `aes-phasec-primary-01 supplies key=${material.key.length}B iv=${material.iv.length}B, but GCM's portable ` +
      `profile requires key=${KEY_LEN_BYTES}B iv=${IV_LEN_BYTES}B.`,
    );
  }

  // Byte fields are copies, never aliases into the frozen pool (H2).
  return {
    key: new Uint8Array(material.key),
    plaintext: new Uint8Array(material.plaintext),
    aad: material.aad === undefined ? undefined : new Uint8Array(material.aad),
    iv: new Uint8Array(material.iv),
    tagLengthBits: GCM_BASELINE_TAG_LENGTH_BITS,
  };
}
