// M2.4.2 closure audit: compute contentHash for the 4 frozen objects and
// confirm the canonicalization is deterministic (same payload -> same hash,
// createdAt-style volatility excluded by construction since none of these
// payloads carry a timestamp field at all).
import type { AuditResult } from './cardinality.js';
import { contentHash } from '../hashing/canonical-hash.js';
import { PORTABLE_DECLARATIONS, PORTABLE_PROFILE_ID, PORTABLE_PROFILE_VERSION } from '../../manifests/portable/profile.js';
import { CHROMIUM_DECLARATIONS, CHROMIUM_MANIFEST_ID, CHROMIUM_MANIFEST_VERSION } from '../../manifests/providers/chromium.js';
import { CRYPTOPP_DECLARATIONS, CRYPTOPP_MANIFEST_ID, CRYPTOPP_MANIFEST_VERSION } from '../../manifests/providers/cryptopp.js';
import { BC_DECLARATIONS, BC_MANIFEST_ID, BC_MANIFEST_VERSION } from '../../manifests/providers/bc.js';
import { CHROMIUM_WEBCRYPTO, CRYPTOPP, BOUNCY_CASTLE } from '../schema/backend-identity.js';

export function computeFrozenHashes(): Record<string, string> {
  return {
    [PORTABLE_PROFILE_ID]: contentHash({ id: PORTABLE_PROFILE_ID, version: PORTABLE_PROFILE_VERSION, declarations: PORTABLE_DECLARATIONS }),
    [CHROMIUM_MANIFEST_ID]: contentHash({ id: CHROMIUM_MANIFEST_ID, version: CHROMIUM_MANIFEST_VERSION, backend: CHROMIUM_WEBCRYPTO, declarations: CHROMIUM_DECLARATIONS }),
    [CRYPTOPP_MANIFEST_ID]: contentHash({ id: CRYPTOPP_MANIFEST_ID, version: CRYPTOPP_MANIFEST_VERSION, backend: CRYPTOPP, declarations: CRYPTOPP_DECLARATIONS }),
    [BC_MANIFEST_ID]: contentHash({ id: BC_MANIFEST_ID, version: BC_MANIFEST_VERSION, backend: BOUNCY_CASTLE, declarations: BC_DECLARATIONS }),
  };
}

export function auditHashes(): AuditResult[] {
  const first = computeFrozenHashes();
  const second = computeFrozenHashes(); // recompute -- must be byte-identical (determinism check)
  const results: AuditResult[] = [];

  const names = Object.keys(first);
  results.push({
    name: '4 frozen objects each produce a contentHash',
    pass: names.length === 4 && Object.values(first).every((h) => h.length === 64),
    detail: JSON.stringify(first, null, 0),
  });

  const stable = names.every((n) => first[n] === second[n]);
  results.push({
    name: 'contentHash is deterministic across repeated computation',
    pass: stable,
    detail: stable ? 'stable' : 'MISMATCH between two computations of the same payload',
  });

  return results;
}
