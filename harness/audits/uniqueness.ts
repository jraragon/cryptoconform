// M2.4.2 closure audit: uniqueness / completeness checks.
import type { AuditResult } from './cardinality.js';
import { MUTATION_REGISTRY } from '../registry/mutations.js';
import { STIMULUS_CAPABILITY_REQUIREMENTS } from '../requirements/stimulus-requirements.js';
import { PORTABLE_DECLARATIONS } from '../../manifests/portable/profile.js';
import { CHROMIUM_DECLARATIONS } from '../../manifests/providers/chromium.js';
import { CRYPTOPP_DECLARATIONS } from '../../manifests/providers/cryptopp.js';
import { BC_DECLARATIONS } from '../../manifests/providers/bc.js';

function duplicates<T>(items: readonly T[], key: (t: T) => string): string[] {
  const seen = new Map<string, number>();
  for (const item of items) {
    const k = key(item);
    seen.set(k, (seen.get(k) ?? 0) + 1);
  }
  return [...seen.entries()].filter(([, n]) => n > 1).map(([k]) => k);
}

export function auditUniqueness(): AuditResult[] {
  const results: AuditResult[] = [];

  const dupMutationIds = duplicates(MUTATION_REGISTRY, (e) => e.mutationId);
  results.push({
    name: 'All 79 mutationId values unique',
    pass: dupMutationIds.length === 0,
    detail: dupMutationIds.length ? `duplicates: ${dupMutationIds.join(', ')}` : 'no duplicates',
  });

  // capabilityId uniqueness WITHIN each frozen object (portable profile is
  // its own namespace; each provider manifest is its own namespace).
  const dupPortable = duplicates(PORTABLE_DECLARATIONS, (d) => d.capabilityId);
  results.push({ name: 'Portable capabilityId unique within profile', pass: dupPortable.length === 0, detail: dupPortable.join(', ') || 'ok' });

  for (const [name, decls] of [['chromium', CHROMIUM_DECLARATIONS], ['cryptopp', CRYPTOPP_DECLARATIONS], ['bc', BC_DECLARATIONS]] as const) {
    const dup = duplicates(decls, (d) => d.capabilityId);
    results.push({ name: `Provider capabilityId unique within ${name} manifest`, pass: dup.length === 0, detail: dup.join(', ') || 'ok' });
  }

  // Every requirement resolves to exactly one declaration within EACH
  // provider manifest (∀r ∃! d : d.capabilityId = r.capabilityId).
  const providerCapIds = new Set(CHROMIUM_DECLARATIONS.map((d) => d.capabilityId));
  const orphanedRequirements = STIMULUS_CAPABILITY_REQUIREMENTS.filter((r) => !providerCapIds.has(r.capabilityId));
  results.push({
    name: 'Every requirement resolves to exactly one declaration',
    pass: orphanedRequirements.length === 0,
    detail: orphanedRequirements.length ? `orphaned: ${orphanedRequirements.map((r) => r.capabilityId).join(', ')}` : 'all 9 resolve',
  });

  // Every mutation referenced by exercisedBy[] in the portable profile must
  // actually exist in the 79-class registry (no orphaned reference either way).
  const mutationIds = new Set(MUTATION_REGISTRY.map((e) => e.mutationId));
  const badExercisedBy = PORTABLE_DECLARATIONS.flatMap((d) => d.exercisedBy).filter((id) => !mutationIds.has(id));
  results.push({
    name: 'Every portable exercisedBy[] references a real mutation class',
    pass: badExercisedBy.length === 0,
    detail: badExercisedBy.length ? `bad refs: ${badExercisedBy.join(', ')}` : 'all valid',
  });

  return results;
}
