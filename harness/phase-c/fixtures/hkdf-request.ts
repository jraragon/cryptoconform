// M3.2.4b-2.1 -- HKDF x request-transform fixture resolver.
//
//     Resolver: (stimulusInstanceId, FrozenMaterialPool) -> HkdfRequest
//
// Contract (H1..H5):
//   H1  uses exclusively hkdf-phasec-primary-01 from the frozen pool
//   H2  generates no new bytes
//   H3  never calls mutate()
//   H4  produces exactly the real TFixture (HkdfRequest)
//   H5  every registered stimulus of the group resolves exactly once
//
// Deliberately NOT generalised yet. This is the first of ~15 groups; the
// common abstraction is extracted only after enough groups exist to show
// what is genuinely shared, rather than guessed from one instance.

import type { HkdfRequest } from '../../../src/contract/hkdf.js';
import { MIN_L, MAX_L } from '../../../src/contract/hkdf.js';
import type { FrozenMaterialPool } from '../material/pool.js';
import type { HkdfBaseMaterial } from '../material/schema.js';
import { PHASE_C_MATERIAL_IDS } from '../material/load.js';
import { MUTATION_REGISTRY } from '../../registry/mutations.js';

export class FixtureResolutionError extends Error {}

// The single structural parameter HkdfRequest carries that the frozen pool
// does NOT supply: HkdfBaseMaterial holds ikm/salt/info (all byte material)
// but no requested output length. L is not material -- it is a scalar
// property of the request -- so it is fixed here as a named, documented
// constant rather than an inline literal, and chosen strictly inside the
// contractual bound MIN_L <= L <= MAX_L (D-068) so that the BASE fixture is
// always contractually valid pre-mutation.
export const HKDF_BASELINE_L = 32;

if (!Number.isInteger(HKDF_BASELINE_L) || HKDF_BASELINE_L < MIN_L || HKDF_BASELINE_L > MAX_L) {
  throw new FixtureResolutionError(
    `HKDF_BASELINE_L=${HKDF_BASELINE_L} is outside the portable-profile bound ${MIN_L}..${MAX_L}.`,
  );
}

// Group membership is DERIVED from the frozen registry, never hard-coded:
// a class added to (or moved out of) hkdf x request-transform is picked up
// automatically, and the coverage tests below hold this set to equality
// with what the resolver actually serves.
export const HKDF_REQUEST_MUTATION_IDS: readonly string[] = MUTATION_REGISTRY
  .filter((e) => e.operation === 'hkdf' && e.mechanism === 'request-transform')
  .map((e) => e.mutationId)
  .sort();

export const HKDF_REQUEST_STIMULUS_PAIRS: readonly (readonly [string, string])[] = MUTATION_REGISTRY
  .filter((e) => e.operation === 'hkdf' && e.mechanism === 'request-transform')
  .flatMap((e) => e.stimulusInstances.map((s) => [e.mutationId, s.stimulusInstanceId] as const))
  .sort((a, b) => (a[0] === b[0] ? a[1].localeCompare(b[1]) : a[0].localeCompare(b[0])));

// Resolves the unmutated base fixture for one (mutationId, stimulusInstanceId).
//
// stimulusInstanceId is accepted but NOT consulted for this group, and that
// is a finding rather than an oversight: the multi-stimulus class here
// (HKDF-LENGTH-BOUNDARY-CROSSING, with L=0 and L=8161) resolves its own
// stimulus INSIDE mutate(), which switches on stimulusInstanceId to set the
// length. The base fixture is therefore identical across that class's two
// stimuli -- the difference between them IS the mutation, not the input.
// Pretending to vary the fixture here would duplicate mutation semantics in
// the binding layer, violating Binding != ScientificSemantics.
export function resolveHkdfRequestFixture(
  mutationId: string,
  stimulusInstanceId: string,
  pool: FrozenMaterialPool,
): HkdfRequest {
  const known = HKDF_REQUEST_STIMULUS_PAIRS.some(([m, s]) => m === mutationId && s === stimulusInstanceId);
  if (!known) {
    throw new FixtureResolutionError(
      `(${mutationId}, ${stimulusInstanceId}) is not a registered hkdf x request-transform stimulus pair.`,
    );
  }

  const material = pool.valueOf<HkdfBaseMaterial>(PHASE_C_MATERIAL_IDS.hkdf, 'hkdf-base-material');

  // Byte fields come straight from the frozen material (H1, H2). They are
  // copied rather than aliased so that a downstream mutate() -- which must
  // never mutate its input in place, but is not trusted to -- cannot reach
  // back into the pool's own arrays.
  return {
    ikm: new Uint8Array(material.ikm),
    salt: new Uint8Array(material.salt),
    info: new Uint8Array(material.info),
    length: HKDF_BASELINE_L,
  };
}
