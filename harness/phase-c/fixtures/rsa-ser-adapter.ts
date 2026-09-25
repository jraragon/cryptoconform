// M3.2.4b-2.10 -- RSA-ser x adapter-transform fixture resolver.
//
// The smallest group in the whole inventory: ONE class, ONE pair, ONE
// shape. Taken before the two large artifact groups so that any surprise
// in serialization surfaces on a minimal surface first.
//
// Result: no surprise. RsaSerErrorMappingIntervention is
// { triggeringCondition, declaredErrorClass } -- structurally the same
// error-mapping shape already seen in GCM, OAEP and PSS adapter groups, and
// like them it needs NO frozen material: an error-mapping intervention
// perturbs an adapter's own classification, not cryptographic input. This
// is the fourth operation to reuse the shape, and the first time a shape
// has recurred across four operations without variation.
//
// --- Where the interesting decision was ---
//
// Not in the shape, but in the BASELINE. The RSA-ser contract raises three
// classes, and mutate() toggles only two of them:
//     malformed_artifact   DER parse / container structure failures (6 sites)
//     invalid_key          C_math^public, V_domain^RSA,2, V_rel^RSA,2 (3 sites)
//     invalid_parameter    role-container mismatch, AlgorithmIdentifier (3 sites)
//                          -- NOT toggled by this mutation
//
// So both GCM's argument shape (baseline is the untoggled third class, so
// the mutation necessarily departs from correct) and OAEP/PSS's (baseline
// IS one of the toggled pair) were available here. The second was chosen,
// for a reason specific to serialization:
//
// The contract enforces a STAGE ORDER -- DER is parsed first, and only an
// artifact that parsed successfully is then checked for mathematical key
// validity. A key failing C_math^public has therefore ALREADY passed DER
// parsing. Reporting it as malformed_artifact asserts the bytes were bad
// when they demonstrably were not, collapsing two distinct failure stages
// into one. That conflation is precisely what a serialization operation's
// error model exists to prevent, so it is the more informative
// misclassification to test.

import type { RsaSerErrorMappingIntervention } from '../../mutations/rsa-ser.js';
import type { FrozenMaterialPool } from '../material/pool.js';
import { MUTATION_REGISTRY } from '../../registry/mutations.js';
import { FixtureResolutionError } from './hkdf-request.js';

// Derived from the frozen contract: checkPublicValidity failing raises
// 'invalid_key' (rsa-ser.public-validity). That is what a correct adapter
// reports for this condition, so it is what the unmutated baseline
// declares; mutate() then reports 'malformed_artifact' instead.
export const RSA_SER_BASELINE_TRIGGERING_CONDITION = 'public-key-fails-mathematical-validity';
export const RSA_SER_BASELINE_DECLARED_ERROR_CLASS = 'invalid_key';

// The third class the contract raises but this mutation never toggles.
// Named so that the deliberate choice between the two available baseline
// arguments stays visible rather than looking accidental.
export const RSA_SER_UNTOGGLED_ERROR_CLASS = 'invalid_parameter';

const RSA_SER_ADAPTER_ENTRIES = MUTATION_REGISTRY.filter(
  (e) => e.operation === 'rsa-ser' && e.mechanism === 'adapter-transform',
);

export const RSA_SER_ADAPTER_MUTATION_IDS: readonly string[] =
  RSA_SER_ADAPTER_ENTRIES.map((e) => e.mutationId).sort();

export const RSA_SER_ADAPTER_STIMULUS_PAIRS: readonly (readonly [string, string])[] =
  RSA_SER_ADAPTER_ENTRIES
    .flatMap((e) => e.stimulusInstances.map((s) => [e.mutationId, s.stimulusInstanceId] as const))
    .sort((a, b) => (a[0] === b[0] ? a[1].localeCompare(b[1]) : a[0].localeCompare(b[0])));

export function resolveRsaSerAdapterFixture(
  mutationId: string,
  stimulusInstanceId: string,
  _pool: FrozenMaterialPool, // an error-mapping intervention needs no material
): RsaSerErrorMappingIntervention {
  const known = RSA_SER_ADAPTER_STIMULUS_PAIRS.some(([m, s]) => m === mutationId && s === stimulusInstanceId);
  if (!known) {
    throw new FixtureResolutionError(
      `(${mutationId}, ${stimulusInstanceId}) is not a registered rsa-ser x adapter-transform stimulus pair.`,
    );
  }
  return {
    triggeringCondition: RSA_SER_BASELINE_TRIGGERING_CONDITION,
    declaredErrorClass: RSA_SER_BASELINE_DECLARED_ERROR_CLASS,
  };
}
