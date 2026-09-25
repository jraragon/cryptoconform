// M3.7-D2 -- ProducerExecutionPreservesStimulusIdentity.
//
// An artifact-side R_interop obligation is comparable only if the artifact
// that DEFINES the stimulus can be obtained by a real execution of scope.from
// without changing the experimental identity of the frozen stimulus.
//
//     ¬ProducerExecutionPreservesStimulusIdentity  ⇒  ¬InteropEligible
//
// The property is evaluated on the SHAPE of the obligation, never on a class
// name, and it is emphatically NOT "PSS is probabilistic, exclude it": PSS
// keeps every R_interop obligation whose stimulus is a producer input, and
// loses only those whose stimulus IS a pre-established artifact.
//
// Two conditions must hold together:
//
//   artifact-bearing   the mutated fixture carries the artifact itself --
//                      a signature or a serialized artifact -- so the
//                      artifact is part of the stimulus rather than a
//                      product of it.
//   randomized producer  the producer role cannot reproduce that exact
//                      artifact from frozen inputs.
//
// Where the producer is DETERMINISTIC given frozen inputs, an artifact-side
// stimulus is reconstructible -- scope.from produces the identical A_0 and
// the frozen mutation then applies to it -- so GCM, RSA-ser and EC-ser keep
// their obligations. Where it is randomized, Sig_p(m) != sigma_frozen and
// substituting a fresh signature would change the stimulus: FALSE-REJECT
// swaps two specific pre-established signatures, FALSE-ACCEPT consumes one as
// part of the stimulus, and VERIFY-MESSAGE-NORMALIZATION asks how the
// consumer treats a GIVEN signature.

import type { OperationId } from '../schema/capability.js';

/**
 * Whether an operation's producer role reproduces its artifact exactly from
 * frozen inputs. A property of the ALGORITHM, stated once with its reason --
 * not a per-class exception.
 */
export const PRODUCER_RECONSTRUCTION: Readonly<Record<OperationId, {
  readonly kind: 'deterministic-from-frozen-inputs' | 'requires-randomized-execution';
  readonly why: string;
}>> = Object.freeze({
  hkdf: {
    kind: 'deterministic-from-frozen-inputs',
    why: 'HKDF is a deterministic KDF, and it has no producer/consumer split, so no interop obligation reaches this.',
  },
  gcm: {
    kind: 'deterministic-from-frozen-inputs',
    why: 'AES-GCM encryption is deterministic given key, IV, plaintext and AAD -- all four frozen in the AES Phase-C '
      + 'material -- so scope.from reproduces the identical A_0.',
  },
  oaep: {
    kind: 'requires-randomized-execution',
    why: 'OAEP padding draws a random seed, so a ciphertext cannot be reproduced from frozen inputs.',
  },
  pss: {
    kind: 'requires-randomized-execution',
    why: 'PSS draws a random salt, so Sig_p(m) != sigma_frozen in general. M3 already froze that a PSS signature '
      + 'cannot be built by a pure encoder and needs a real execution, which is why mutate() must not sign.',
  },
  'rsa-ser': {
    kind: 'deterministic-from-frozen-inputs',
    why: 'exportRsaSer is a pure encoder over frozen key material: same key in, same DER out.',
  },
  'ec-ser': {
    kind: 'deterministic-from-frozen-inputs',
    why: 'exportEcSer is a pure encoder over frozen key material: same key in, same DER out.',
  },
});

/** Fields whose presence means the artifact is part of the stimulus. */
const ARTIFACT_BEARING_FIELDS = ['artifact', 'signature', 'alternateSignature'] as const;

export function isArtifactBearing(mutatedFixture: unknown): boolean {
  if (mutatedFixture === null || typeof mutatedFixture !== 'object') return false;
  const f = mutatedFixture as Record<string, unknown>;
  return ARTIFACT_BEARING_FIELDS.some((k) => f[k] !== undefined);
}

export function producerExecutionPreservesStimulusIdentity(
  operation: OperationId, mutatedFixture: unknown,
): boolean {
  if (!isArtifactBearing(mutatedFixture)) return true; // the stimulus IS a producer input
  return PRODUCER_RECONSTRUCTION[operation]?.kind === 'deterministic-from-frozen-inputs';
}
