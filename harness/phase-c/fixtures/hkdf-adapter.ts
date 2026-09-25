// M3.2.4b-2.11 -- HKDF x adapter-transform fixture resolver.
//
// 2 classes, 2 pairs, ONE shape shared by both:
//     HkdfAdapterInvocation { request: HkdfRequest, effectiveHash: string }
//
// --- A finer distribution than PSS x adapter's ---
//
// PSS x adapter also had two classes sharing one composed shape, but there
// they intervened on DIFFERENT fields (externalRandomnessProvided vs
// explicitSaltBytesProvided), so directInterventionTargets distinguished
// them. Here both classes declare the SAME single target, 'effectiveHash',
// and are distinguished only by the VALUE each writes:
//
//     HKDF-HASH-MISMATCH                -> 'SHA-384'
//         a real, implementable hash that is simply not the profile's one:
//         a genuine byte-level divergence, observed later by R_byte.
//     HKDF-UNSUPPORTED-HASH-DECLARATION -> 'SHA3-256-UNRECOGNIZED'
//         an algorithm outside the recognized set entirely: a capability /
//         validation / error concern, not a byte-comparison one.
//
// So the discriminator that served earlier groups (Gamma_0, or
// directInterventionTargets) would fail here -- and it does not matter,
// because with a single shape there is nothing to discriminate. What this
// group adds is the observation that two classes can be experimentally
// distinct while sharing shape, target AND baseline: the distinction lives
// entirely in mutate(). One resolver is therefore not merely permissible
// but the only correct answer; two would necessarily be identical.

import type { HkdfRequest } from '../../../src/contract/hkdf.js';
import { HASH_LEN } from '../../../src/contract/hkdf.js';
import type { HkdfAdapterInvocation } from '../../mutations/hkdf.js';
import type { FrozenMaterialPool } from '../material/pool.js';
import { MUTATION_REGISTRY } from '../../registry/mutations.js';
import { FixtureResolutionError } from './hkdf-request.js';
import { resolveHkdfRequestFixture } from './hkdf-request.js';

// The effective hash a CORRECT adapter uses. Unlike OAEP and PSS -- which
// export their own OAEP_HASH / PSS_HASH constants -- the HKDF contract
// names no hash string: it fixes the algorithm structurally, as
// "HKDF-SHA-256 (HashLen = 32 octets)", exposing only HASH_LEN.
//
// So the baseline is derived from that invariant rather than copied from a
// sibling operation: HASH_LEN is asserted to be SHA-256's own 32-octet
// output length, making a change to the frozen profile a visible
// compile-time dependency of this baseline instead of a silent drift.
export const HKDF_BASELINE_EFFECTIVE_HASH = 'SHA-256';
export const HKDF_PROFILE_HASH_LEN = HASH_LEN;

if (HKDF_PROFILE_HASH_LEN !== 32) {
  throw new FixtureResolutionError(
    `HKDF's frozen profile declares HASH_LEN=${HKDF_PROFILE_HASH_LEN}, which is not SHA-256's 32 octets; ` +
    `the baseline effectiveHash '${HKDF_BASELINE_EFFECTIVE_HASH}' no longer follows from the contract.`,
  );
}

const HKDF_ADAPTER_ENTRIES = MUTATION_REGISTRY.filter(
  (e) => e.operation === 'hkdf' && e.mechanism === 'adapter-transform',
);

export const HKDF_ADAPTER_MUTATION_IDS: readonly string[] =
  HKDF_ADAPTER_ENTRIES.map((e) => e.mutationId).sort();

export const HKDF_ADAPTER_STIMULUS_PAIRS: readonly (readonly [string, string])[] =
  HKDF_ADAPTER_ENTRIES
    .flatMap((e) => e.stimulusInstances.map((s) => [e.mutationId, s.stimulusInstanceId] as const))
    .sort((a, b) => (a[0] === b[0] ? a[1].localeCompare(b[1]) : a[0].localeCompare(b[0])));

export function resolveHkdfAdapterFixture(
  mutationId: string,
  stimulusInstanceId: string,
  pool: FrozenMaterialPool,
): HkdfAdapterInvocation {
  const known = HKDF_ADAPTER_STIMULUS_PAIRS.some(([m, s]) => m === mutationId && s === stimulusInstanceId);
  if (!known) {
    throw new FixtureResolutionError(
      `(${mutationId}, ${stimulusInstanceId}) is not a registered hkdf x adapter-transform stimulus pair.`,
    );
  }

  // Composition, per the settled rule: the type structurally contains the
  // same canonical object, so the embedded request is borrowed from the
  // request-transform resolver rather than rebuilt. Both mutations leave it
  // untouched -- the field comment in the mutation module says as much, and
  // a test confirms it rather than trusting the comment.
  const carrierId = MUTATION_REGISTRY.find(
    (e) => e.operation === 'hkdf' && e.mechanism === 'request-transform' && e.stimulusInstances.length === 1,
  )?.mutationId;
  if (carrierId === undefined) {
    throw new FixtureResolutionError('No single-stimulus hkdf request-transform class available to supply the embedded request.');
  }
  const request: HkdfRequest = resolveHkdfRequestFixture(carrierId, 'default', pool);

  return { request, effectiveHash: HKDF_BASELINE_EFFECTIVE_HASH };
}
