// M3.7.3 -- the artifact-side producer route.
//
//   frozen producer inputs -> E_scope.from -> A_0 -> mutate(A_0,s) -> E_scope.to
//
// For an artifact-bearing obligation the fixture carries an artifact drawn
// from the corpus, which is enough to build the stimulus but NOT enough to
// sustain R_interop's directional claim: the artifact must have been produced
// by scope.from. So the producer executes from frozen inputs, and the frozen
// intervention is then applied to what it actually produced.
//
// --- The intervention is REUSED, never reimplemented -----------------------
//
// A second implementation of the mutation would be a second definition of the
// experiment. Instead the freshly produced A_0 is substituted into the
// fixture's own artifact field and the FROZEN mutate() runs on that. What
// reaches the consumer is therefore mutate(A_0, s) by the same code path that
// produced mutate(A_corpus, s) before -- only the artifact's origin changed,
// which is exactly what D2 required.
//
// --- Where the producer input comes from ----------------------------------
//
// Nominal frozen material, never the fixture and never a search:
//
//   gcm       aes-phasec-primary-01 -- key, iv, plaintext, aad, all four frozen
//   C-T-swap  the same, except the plaintext promoted by D17, because that
//             artifact needs |C| = |tag| and the AES record's own plaintext
//             would not give it
//   rsa-ser   PHASE_C_MATERIAL_IDS.rsa, exported by a pure encoder
//   ec-ser    PHASE_C_MATERIAL_IDS.ec, likewise
//
// PSS never reaches here: D2 removed its artifact-side obligations precisely
// because no producer execution preserves their stimulus identity.

import type { OperationId } from '../schema/capability.js';
import type { BoundMaterial } from './execution-binding.js';
import { realizeEcSerMaterial, realizeRsaSerMaterial } from './wiring-realization.js';
import { ctSwapPlaintextBytes, CT_SWAP_PRODUCER_PLAINTEXT } from './material/ct-swap-parameter.js';

export class ArtifactSideProducerError extends Error {}

/* eslint-disable @typescript-eslint/no-explicit-any */

/** The field an operation's artifact occupies in its own fixture shape. */
const ARTIFACT_FIELD: Readonly<Partial<Record<OperationId, string>>> = Object.freeze({
  gcm: 'artifact', 'rsa-ser': 'artifact', 'ec-ser': 'artifact',
});

/**
 * The producer's input, built from nominal frozen material alone.
 *
 * `materialId` selects nothing: it is the record the M3.7.2 binding already
 * named. The C-T-swap plaintext substitution is keyed on the artifact record
 * the class consumes, not on the class's name.
 */
export function producerInputFor(params: {
  readonly operation: OperationId;
  readonly material: BoundMaterial;
  readonly consumesArtifactId?: string;
  /** The role the FROZEN artifact selection already determined. */
  readonly producerRole?: 'public' | 'private';
}): unknown {
  const { operation, material } = params;
  switch (operation) {
    case 'gcm': {
      const m = material.value as any;
      const needsCtSwapPlaintext = params.consumesArtifactId === CT_SWAP_PRODUCER_PLAINTEXT.appliesToMaterialId;
      return {
        key: m.key, iv: m.iv, aad: m.aad,
        plaintext: needsCtSwapPlaintext ? ctSwapPlaintextBytes() : m.plaintext,
        tagLengthBits: 128,
      };
    }
    case 'rsa-ser':
      return realizeRsaSerMaterial(material, params.producerRole ?? 'private');
    case 'ec-ser':
      // The role is PROPAGATED from the frozen artifact selection, never a
      // default and never read from the DER.
      return realizeEcSerMaterial(material, params.producerRole ?? 'private');
    default:
      throw new ArtifactSideProducerError(
        `Operation '${operation}' has no artifact-side producer route. PSS artifact-side obligations were removed ` +
        'by M3.7-D2 because no producer execution preserves their stimulus identity.',
      );
  }
}

/**
 * Substitutes the freshly produced A_0 into the fixture and runs the FROZEN
 * intervention on it.
 *
 * Takes the UNMUTATED fixture, so `mutate` sees exactly the shape it was
 * written against, with only the artifact's origin changed.
 */
export function mutateFreshArtifact(params: {
  readonly operation: OperationId;
  readonly baseFixture: unknown;
  readonly freshArtifactHex: string;
  readonly stimulusInstanceId: string;
  readonly mutate: (fixture: unknown, stimulusInstanceId: string) => unknown;
}): unknown {
  const field = ARTIFACT_FIELD[params.operation];
  if (field === undefined) {
    throw new ArtifactSideProducerError(`Operation '${params.operation}' has no artifact field to substitute.`);
  }
  const base = params.baseFixture as Record<string, unknown>;
  if (base?.[field] === undefined) {
    throw new ArtifactSideProducerError(
      `The fixture has no '${field}' to substitute, so this is not an artifact-side obligation.`,
    );
  }
  const withFresh = { ...base, [field]: Buffer.from(params.freshArtifactHex, 'hex') };
  return params.mutate(withFresh, params.stimulusInstanceId);
}

/* eslint-enable @typescript-eslint/no-explicit-any */

/**
 * The consumer's view of the SAME bound material the producer used.
 *
 * Shapes it to the field names the consumer input expects, and nothing more:
 * no component is added, removed or recomputed. GCM's consumer needs the key
 * and AAD it was encrypted under; the serialization consumers need the role
 * their container declares.
 */
export function realizeConsumerMaterial(operation: OperationId, material: BoundMaterial): unknown {
  const m = material.value as any;
  switch (operation) {
    case 'gcm': return { key: m.key, aad: m.aad };
    case 'rsa-ser':
    case 'ec-ser': return { role: 'private' };
    default: return undefined;
  }
}
