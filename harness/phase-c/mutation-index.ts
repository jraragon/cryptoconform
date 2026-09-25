// M3.2.4b -- global mutation index.
//
// Closes the most basic structural gap found in M3.2.4's own inspection:
// the 79 MutationImplementations exist as loose named exports across six
// modules, with no mutationId -> implementation lookup anywhere. The
// orchestrator's ExecutionPlan needs exactly that lookup.
//
// Collection is STRUCTURAL, not name-based. The six modules export their
// implementations under heterogeneous shapes -- bare consts, readonly
// arrays (HKDF_MUTATIONS, GCM_REQUEST_MUTATIONS, ...) and plain object
// groupings (GCM_ARTIFACT_MUTATIONS, ...) -- so this walks every exported
// value and collects anything that IS a MutationImplementation, rather than
// depending on a naming convention that was never contractual.
//
// The index is verified against the frozen registry at construction:
//     RegistryMutationIDs == IndexedMutationIDs        (equality, not subset)
// Neither a missing implementation nor an orphan implementation can pass.

import type { MutationImplementation } from '../mutations/framework.js';
import { MUTATION_REGISTRY } from '../registry/mutations.js';

import * as hkdf from '../mutations/hkdf.js';
import * as gcm from '../mutations/gcm.js';
import * as oaep from '../mutations/oaep.js';
import * as pss from '../mutations/pss.js';
import * as rsaSer from '../mutations/rsa-ser.js';
import * as ecSer from '../mutations/ec-ser.js';

export class MutationIndexError extends Error {}

// eslint-disable-next-line @typescript-eslint/no-explicit-any
type AnyMutationImplementation = MutationImplementation<any>;

function isMutationImplementation(v: unknown): v is AnyMutationImplementation {
  if (v === null || typeof v !== 'object') return false;
  const c = v as Record<string, unknown>;
  return typeof c['mutationId'] === 'string'
    && typeof c['mutate'] === 'function'
    && Array.isArray(c['directInterventionTargets']);
}

// Walks an exported value, collecting implementations from bare values,
// arrays and plain-object groupings alike. Duplicates are refused rather
// than silently deduplicated: the same implementation reachable twice under
// different export names is an ambiguity the index must not paper over.
function collectInto(target: Map<string, AnyMutationImplementation>, value: unknown, seen: Set<unknown>): void {
  if (value === null || typeof value !== 'object') return;
  if (seen.has(value)) return;
  seen.add(value);

  if (isMutationImplementation(value)) {
    const existing = target.get(value.mutationId);
    if (existing !== undefined && existing !== value) {
      throw new MutationIndexError(
        `Two distinct implementations share mutationId '${value.mutationId}'. ` +
        'Mutation identity must be unique across the corpus.',
      );
    }
    target.set(value.mutationId, value);
    return;
  }

  if (Array.isArray(value)) {
    for (const item of value) collectInto(target, item, seen);
    return;
  }

  for (const item of Object.values(value as Record<string, unknown>)) {
    collectInto(target, item, seen);
  }
}

function buildIndex(): ReadonlyMap<string, AnyMutationImplementation> {
  const index = new Map<string, AnyMutationImplementation>();
  const seen = new Set<unknown>();
  for (const module of [hkdf, gcm, oaep, pss, rsaSer, ecSer]) {
    collectInto(index, module, seen);
  }

  // Exactness against the frozen registry: equality, never containment.
  const registryIds = new Set(MUTATION_REGISTRY.map((e) => e.mutationId));
  const missing = [...registryIds].filter((id) => !index.has(id)).sort();
  const orphans = [...index.keys()].filter((id) => !registryIds.has(id)).sort();

  if (missing.length > 0) {
    throw new MutationIndexError(
      `${missing.length} registry class(es) have no implementation: ${missing.join(', ')}.`,
    );
  }
  if (orphans.length > 0) {
    throw new MutationIndexError(
      `${orphans.length} implementation(s) have no registry entry: ${orphans.join(', ')}. ` +
      'An unregistered mutation could never be scored, so it must not exist.',
    );
  }

  return index;
}

export const MUTATION_INDEX: ReadonlyMap<string, AnyMutationImplementation> = buildIndex();

export function getMutationImplementation(mutationId: string): AnyMutationImplementation {
  const impl = MUTATION_INDEX.get(mutationId);
  if (impl === undefined) {
    throw new MutationIndexError(`No implementation indexed for mutationId '${mutationId}'.`);
  }
  return impl;
}

export function indexedMutationIds(): readonly string[] {
  return [...MUTATION_INDEX.keys()].sort();
}
