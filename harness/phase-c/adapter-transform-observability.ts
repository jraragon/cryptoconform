// M3.8.2 -- observability of adapter-transform classes.
//
// The freeze fixes the taxonomy and its cardinality --
//
//     31 request-transform + 31 artifact-transform
//   + 11 adapter-transform +  6 capability-transform = 79
//
// -- and says nothing about how an adapter-transform is EXECUTED. That is a
// genuine gap, of the same kind M3.9 found for R_cap: a concept frozen in the
// model whose executable materialisation nobody built. It surfaced only when
// the runner was made to drive the whole instrument.
//
// Enumerating all eleven splits them cleanly, and the split is derived from
// the FIXTURE SHAPE and from Gamma_0 -- never from class names:
//
//   G1  a substitutable PARAMETER          effectiveHash + request
//   G2  a property of the INTERFACE        <flag>Provided + request
//   G3  no operational input at all        no request
//
// G1 is NOT executable either, though it reads as if it were: SHA-256 is a
// literal in every frozen HKDF wiring, so parameterising the hash means
// modifying an M1 wiring or fabricating a backend surface M1 never validated.
//
// G2 is NOT executable as a mutation. externalRandomnessProvided is a boolean
// about whether the provider EXPOSES control, not a value to pass. Running the
// wrapped request unchanged would execute the BASE CASE and the intervention
// would not occur at all. And the design already says where these live: all
// three carry *.cap.portable in Gamma_0, and each corresponds one-to-one with
// a frozen manifest claim -- oaep.provider.external-randomness-control,
// pss.provider.rng-control, pss.provider.explicit-salt-bytes -- which cite
// them in their own necessity column. They are observable through R_cap,
// which M3.9-B materialised, and not through executing the operation.
//
// G3 has no request and no material: nothing to execute, as the declarative
// fixtures already showed.
//
//     all eleven -> observable via R_cap only, never by executing the mutation
//
// The consequence is structural non-comparability for the relations that
// require executing the mutated operation, and NOT for R_cap.

import { MUTATION_REGISTRY } from '../registry/mutations.js';
import type { RelationId } from '../schema/registry-types.js';

export type AdapterTransformGroup = 'parameterised' | 'interface-property' | 'declarative';

/**
 * M3.8.2 (revised) -- NONE of the three groups is executable, and the reason
 * is the same for all eleven.
 *
 * G1 looked executable because `effectiveHash` reads as a substitutable
 * parameter. It is not: SHA-256 is a literal in every frozen HKDF wiring --
 * `{ name: 'HKDF', hash: 'SHA-256', ... }`, evidence operation 'HKDF-SHA-256',
 * and the script builder takes no digest argument. Parameterising it would
 * mean modifying an M1 wiring, or writing a second adapter over a backend
 * surface M1 never validated.
 *
 * M2.3.3b-I had already reasoned this one level up, when it justified HKDF
 * contributing exactly ONE declaration:
 *
 *     "v0.6's HKDF contract references only SHA-256 throughout. Inventing a
 *      placeholder second hash for this manifest would be exactly the kind of
 *      symmetry-driven fabrication this section exists to prevent."
 *
 * Inventing the adapter is the same fabrication, one level lower. And Gamma_0
 * agrees: both G1 classes carry hkdf.cap, exactly as the G2 classes carry
 * *.cap.portable. What looked like a parameter was a capability all along.
 *
 * So the mechanism is uniform: an adapter-transform is observable through
 * R_cap and never by executing the mutated operation.
 */

/** Relations whose observation requires executing the mutated operation. */
export const EXECUTION_REQUIRING: readonly RelationId[] =
  Object.freeze(['R_byte', 'R_interop', 'R_ser', 'R_val', 'R_err']);

/**
 * Classifies by the shape of the mutated fixture, not by name.
 *
 *   has a `request` and a non-boolean parameter  -> parameterised
 *   has a `request` and only boolean flags       -> interface-property
 *   has no `request`                             -> declarative
 */
export function classifyAdapterTransform(mutatedFixture: unknown): AdapterTransformGroup {
  if (mutatedFixture === null || typeof mutatedFixture !== 'object') return 'declarative';
  const f = mutatedFixture as Record<string, unknown>;
  if (f['request'] === undefined) return 'declarative';
  const extras = Object.keys(f).filter((k) => k !== 'request');
  const allBooleanFlags = extras.length > 0 && extras.every((k) => typeof f[k] === 'boolean');
  return allBooleanFlags ? 'interface-property' : 'parameterised';
}

export function isAdapterTransform(mutationId: string): boolean {
  return MUTATION_REGISTRY.find((e) => e.mutationId === mutationId)?.mechanism === 'adapter-transform';
}

/**
 * Whether an adapter-transform class can be observed by executing the mutated
 * operation for this relation.
 *
 * R_cap is always observable: M3.9-B contrasts a frozen manifest declaration
 * against a probe, and needs no mutated execution at all.
 */
export function adapterTransformObservable(
  group: AdapterTransformGroup, relation: RelationId,
): boolean {
  void group; // uniform across all three: the group is recorded, not decisive
  return relation === 'R_cap';
}
