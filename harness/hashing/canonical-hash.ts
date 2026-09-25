// M2.4.2 -- static materialization only.
// Source: Paper_4_Experimental_Harness v0.21, §12.2.
// contentHash = SHA256(Canonicalize(FrozenSemanticPayload))
// Excludes volatile fields (createdAt, generation-time metadata) deliberately.

import { createHash } from 'node:crypto';

// Deterministic, stable-key-order JSON serialization. Recursively sorts
// object keys; arrays keep their own order (order is semantically meaningful
// for declarations[] arrays, so it is never reordered).
export function canonicalize(value: unknown): string {
  return JSON.stringify(sortKeysDeep(value));
}

function sortKeysDeep(value: unknown): unknown {
  if (Array.isArray(value)) {
    return value.map(sortKeysDeep);
  }
  if (value !== null && typeof value === 'object') {
    const sorted: Record<string, unknown> = {};
    for (const key of Object.keys(value as Record<string, unknown>).sort()) {
      sorted[key] = sortKeysDeep((value as Record<string, unknown>)[key]);
    }
    return sorted;
  }
  return value;
}

export function contentHash(frozenSemanticPayload: unknown): string {
  return createHash('sha256').update(canonicalize(frozenSemanticPayload), 'utf8').digest('hex');
}
