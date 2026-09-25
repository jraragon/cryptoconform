// Bloque D / M3.3 -- the registry binding.
//
// M3.1's own closure requirement 3 states that a MutationResult must be bound
// to the exact content of Gamma_0(c) at freeze time, "e.g. via a
// registryEntryHash, so a later registry change can never be silently
// absorbed into an already-frozen result". Until now that requirement had no
// implementation anywhere in the tree, and gamma0Ref carried the string
// `registry:<mutationId>` -- a NAME, not a binding. A name survives a change
// of content: the registry could be edited and every frozen result would go
// on pointing at it, agreeing with whatever it now says.
//
// The sufficiency analysis of Bloque B found the same gap from the other
// side. Gamma_0(c) is what sigma(c) = { kind_{K1/K2}(g) : g in Gamma_0(c) }
// is computed from, so DiagnosticGain is not computable from the bundle at
// all unless the registry travels with it, identified.
//
// --- Why the hash and not a copy ------------------------------------------
//
// Duplicating Gamma_0 into every result would make the bundle self-contained
// and would also create a second, independently writable statement of what a
// class's causal ground truth is. sigma(c) is evidence-independent (proved in
// M3-H11.3b), so the registry can be pinned once and referenced, and a
// mismatch is then detectable rather than absorbed:
//
//     EvidenceBundle --registryEntryHash--> FrozenRegistry --> Gamma_0(c) --> sigma(c)
//
// The per-entry hash, not only a whole-registry one, so a result can be
// checked against ITS OWN class without requiring the entire registry to be
// byte-identical -- a class added later must not invalidate results that
// never referred to it.

import { contentHash } from '../hashing/canonical-hash.js';
import { MUTATION_REGISTRY } from '../registry/mutations.js';
import type { MutationRegistryEntry } from '../schema/registry-types.js';

export class RegistryBindingError extends Error {}

/**
 * The semantic payload a frozen result is bound to. Deliberately NOT the
 * whole registry entry: expectedSpectrum is a prediction, and stimulus
 * descriptions are prose. What must not change under a frozen result is the
 * class's identity, its operation, its causal ground truth and the stimulus
 * set that was scored.
 */
export function registryEntryPayload(entry: MutationRegistryEntry): unknown {
  return {
    mutationId: entry.mutationId,
    operation: entry.operation,
    gamma0: [...entry.gamma0].sort(),
    mechanism: entry.mechanism,
    stimulusInstanceIds: entry.stimulusInstances.map((s) => s.stimulusInstanceId).sort(),
  };
}

export function registryEntryHash(mutationId: string): string {
  const entry = MUTATION_REGISTRY.find((e) => e.mutationId === mutationId);
  if (entry === undefined) {
    throw new RegistryBindingError(`No frozen registry entry for '${mutationId}'; a result cannot be bound to nothing.`);
  }
  return contentHash(registryEntryPayload(entry));
}

/**
 * Verifies a frozen result against the registry it claims to have been
 * produced under. Fail-closed on both directions of drift: a class that
 * disappeared, and a class whose Gamma_0 changed.
 */
export function verifyRegistryBinding(mutationId: string, expectedHash: string): void {
  const actual = registryEntryHash(mutationId);
  if (actual !== expectedHash) {
    throw new RegistryBindingError(
      `Registry drift for '${mutationId}': the frozen result was bound to ${expectedHash.slice(0, 12)}..., ` +
      `the current registry entry hashes to ${actual.slice(0, 12)}.... Refusing rather than absorbing the change.`,
    );
  }
}

/**
 * Gamma_0(c) recovered through the binding rather than from a name.
 *
 * This is the function M5 needs for sigma(c), and it is deliberately the only
 * route: it cannot return a class's clauses without first proving that the
 * registry still says what the result was bound to.
 */
export function resolveGamma0(mutationId: string, boundHash: string): readonly string[] {
  verifyRegistryBinding(mutationId, boundHash);
  const entry = MUTATION_REGISTRY.find((e) => e.mutationId === mutationId)!;
  return [...entry.gamma0];
}

/** All 79 bindings, for pinning the registry as a whole at freeze time. */
export function allRegistryEntryHashes(): ReadonlyMap<string, string> {
  return new Map(MUTATION_REGISTRY.map((e) => [e.mutationId, contentHash(registryEntryPayload(e))]));
}
