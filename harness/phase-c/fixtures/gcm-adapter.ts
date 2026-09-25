// M3.2.4b-2.3 -- GCM x adapter-transform fixture resolver.
//
//     Resolver: (mutationId, stimulusInstanceId, FrozenMaterialPool)
//               -> GcmErrorMappingIntervention
//
// Chosen as the third group deliberately: it holds the OPERATION fixed
// (GCM) while changing the MECHANISM, so that the two dimensions of the
// binding framework are validated independently rather than both at once.
//
// The inspection produced a genuinely new case, which is exactly why this
// ordering was worth it:
//
//   GcmErrorMappingIntervention carries NO byte material at all --
//   { triggeringCondition: string, declaredErrorClass: string }.
//
// So this resolver requires nothing from the frozen pool. H1 ("uses
// exclusively material X") is vacuous here rather than violated: an
// adapter-transform intervention perturbs an adapter's own error MAPPING,
// which is configuration, not cryptographic input. The pool parameter is
// kept for interface uniformity across the ~15 groups and is deliberately
// unused -- recorded as a finding, like the unused stimulusInstanceId in
// the HKDF group, rather than left looking like an oversight.
//
//     AdapterFixture != RequestFixture
//
// even where both concern the same operation. Nothing here may be built
// from, or degenerate into, GcmEncryptRequest: the two mechanisms
// intervene on different experimental state, and a shared shape would
// erase that distinction.

import { MIN_ARTIFACT_LEN_BYTES } from '../../../src/contract/gcm.js';
import type { GcmErrorMappingIntervention } from '../../mutations/gcm.js';
import type { FrozenMaterialPool } from '../material/pool.js';
import { MUTATION_REGISTRY } from '../../registry/mutations.js';
import { FixtureResolutionError } from './hkdf-request.js';

// The baseline must declare the CONTRACTUALLY CORRECT error class for its
// triggering condition, so that mutate() -- which flips the declared class
// -- produces a genuine misclassification. Both values are derived from the
// frozen contract rather than invented:
//   - 'undersized-ciphertext' is the condition parseAeadArtifact guards,
//     rejecting any artifact shorter than MIN_ARTIFACT_LEN_BYTES.
//   - 'malformed_artifact' is the class that check actually raises. Notably
//     it is NEITHER of the two classes mutate() toggles between, so the
//     mutation genuinely departs from correct behaviour rather than
//     swapping one wrong answer for another.
export const GCM_BASELINE_TRIGGERING_CONDITION = 'undersized-ciphertext';
export const GCM_BASELINE_DECLARED_ERROR_CLASS = 'malformed_artifact';

// Referenced so that a change to the artifact floor is a visible
// compile-time dependency of this baseline's own justification, not a
// silent drift between the contract and the fixture's rationale.
export const GCM_ARTIFACT_FLOOR_BYTES = MIN_ARTIFACT_LEN_BYTES;

export const GCM_ADAPTER_MUTATION_IDS: readonly string[] = MUTATION_REGISTRY
  .filter((e) => e.operation === 'gcm' && e.mechanism === 'adapter-transform')
  .map((e) => e.mutationId)
  .sort();

export const GCM_ADAPTER_STIMULUS_PAIRS: readonly (readonly [string, string])[] = MUTATION_REGISTRY
  .filter((e) => e.operation === 'gcm' && e.mechanism === 'adapter-transform')
  .flatMap((e) => e.stimulusInstances.map((s) => [e.mutationId, s.stimulusInstanceId] as const))
  .sort((a, b) => (a[0] === b[0] ? a[1].localeCompare(b[1]) : a[0].localeCompare(b[0])));

export function resolveGcmAdapterFixture(
  mutationId: string,
  stimulusInstanceId: string,
  _pool: FrozenMaterialPool, // intentionally unused: this group needs no material
): GcmErrorMappingIntervention {
  const known = GCM_ADAPTER_STIMULUS_PAIRS.some(([m, s]) => m === mutationId && s === stimulusInstanceId);
  if (!known) {
    throw new FixtureResolutionError(
      `(${mutationId}, ${stimulusInstanceId}) is not a registered gcm x adapter-transform stimulus pair.`,
    );
  }

  return {
    triggeringCondition: GCM_BASELINE_TRIGGERING_CONDITION,
    declaredErrorClass: GCM_BASELINE_DECLARED_ERROR_CLASS,
  };
}
