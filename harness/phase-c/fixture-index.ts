// M3.2.4b-3.5 -- global fixture index.
//
//     FIXTURE_INDEX: (mutationId, stimulusInstanceId) -> FixtureResolver
//
// The 32 typed resolvers live in 15 group modules, each exposing its own
// entry point and its own *_STIMULUS_PAIRS inventory -- but nothing related
// a (mutationId, stimulusInstanceId) pair to the resolver that serves it.
// This closes that gap the same way MUTATION_INDEX closed its own in
// M3.2.4b-1: BY COMPOSITION of the existing inventories, never by a manual
// table of 90 identifiers.
//
// Each group already derives its pairs from the frozen registry, so the
// index inherits that derivation rather than restating it. The exactness
// checks below are therefore bidirectional and fail-closed:
//     Keys(FIXTURE_INDEX) = RegistryPairs,   |Keys| = 90
//     RegistryPairs \ IndexedPairs = empty
//     IndexedPairs \ RegistryPairs = empty
//     forall (c,s): #Resolver(c,s) = 1
// Absence and duplication are both refused; neither can be papered over.

import type { FrozenMaterialPool } from './material/pool.js';
import { MUTATION_REGISTRY } from '../registry/mutations.js';

import { HKDF_REQUEST_STIMULUS_PAIRS, resolveHkdfRequestFixture } from './fixtures/hkdf-request.js';
import { HKDF_ADAPTER_STIMULUS_PAIRS, resolveHkdfAdapterFixture } from './fixtures/hkdf-adapter.js';
import { GCM_REQUEST_STIMULUS_PAIRS, resolveGcmRequestFixture } from './fixtures/gcm-request.js';
import { GCM_ADAPTER_STIMULUS_PAIRS, resolveGcmAdapterFixture } from './fixtures/gcm-adapter.js';
import { GCM_ARTIFACT_STIMULUS_PAIRS, resolveGcmArtifactFixture } from './fixtures/gcm-artifact.js';
import { OAEP_REQUEST_STIMULUS_PAIRS, resolveOaepRequestFixture } from './fixtures/oaep-request.js';
import { OAEP_ADAPTER_STIMULUS_PAIRS, resolveOaepAdapterFixture } from './fixtures/oaep-adapter.js';
import { PSS_REQUEST_STIMULUS_PAIRS, resolvePssRequestFixture } from './fixtures/pss-request.js';
import { PSS_ADAPTER_STIMULUS_PAIRS, resolvePssAdapterFixture } from './fixtures/pss-adapter.js';
import { PSS_ARTIFACT_STIMULUS_PAIRS, resolvePssArtifactFixture } from './fixtures/pss-artifact.js';
import { RSA_SER_ADAPTER_STIMULUS_PAIRS, resolveRsaSerAdapterFixture } from './fixtures/rsa-ser-adapter.js';
import { RSA_ARTIFACT_STIMULUS_PAIRS, resolveRsaArtifactFixture } from './fixtures/rsa-ser-artifact.js';
import { EC_SER_ADAPTER_STIMULUS_PAIRS, resolveEcSerAdapterFixture } from './fixtures/ec-ser-adapter.js';
import { EC_ARTIFACT_STIMULUS_PAIRS, resolveEcArtifactFixture } from './fixtures/ec-ser-artifact.js';
import { CAPABILITY_STIMULUS_PAIRS, resolveCapabilityFixture } from './fixtures/capability.js';

export class FixtureIndexError extends Error {}

// Every group entry point shares one shape: the fixture TYPE varies, but the
// way a fixture is obtained does not.
export type FixtureResolver = (
  mutationId: string,
  stimulusInstanceId: string,
  pool: FrozenMaterialPool,
) => unknown;

interface GroupRegistration {
  readonly label: string;
  readonly pairs: readonly (readonly [string, string])[];
  readonly resolver: FixtureResolver;
}

// The 15 group inventories. Each contributes its own derived pairs; no
// identifier is written here.
const GROUPS: readonly GroupRegistration[] = [
  { label: 'hkdf x request', pairs: HKDF_REQUEST_STIMULUS_PAIRS, resolver: resolveHkdfRequestFixture },
  { label: 'hkdf x adapter', pairs: HKDF_ADAPTER_STIMULUS_PAIRS, resolver: resolveHkdfAdapterFixture },
  { label: 'gcm x request', pairs: GCM_REQUEST_STIMULUS_PAIRS, resolver: resolveGcmRequestFixture },
  { label: 'gcm x adapter', pairs: GCM_ADAPTER_STIMULUS_PAIRS, resolver: resolveGcmAdapterFixture },
  { label: 'gcm x artifact', pairs: GCM_ARTIFACT_STIMULUS_PAIRS, resolver: resolveGcmArtifactFixture },
  { label: 'oaep x request', pairs: OAEP_REQUEST_STIMULUS_PAIRS, resolver: resolveOaepRequestFixture },
  { label: 'oaep x adapter', pairs: OAEP_ADAPTER_STIMULUS_PAIRS, resolver: resolveOaepAdapterFixture },
  { label: 'pss x request', pairs: PSS_REQUEST_STIMULUS_PAIRS, resolver: resolvePssRequestFixture },
  { label: 'pss x adapter', pairs: PSS_ADAPTER_STIMULUS_PAIRS, resolver: resolvePssAdapterFixture },
  { label: 'pss x artifact', pairs: PSS_ARTIFACT_STIMULUS_PAIRS, resolver: resolvePssArtifactFixture },
  { label: 'rsa-ser x adapter', pairs: RSA_SER_ADAPTER_STIMULUS_PAIRS, resolver: resolveRsaSerAdapterFixture },
  { label: 'rsa-ser x artifact', pairs: RSA_ARTIFACT_STIMULUS_PAIRS, resolver: resolveRsaArtifactFixture },
  { label: 'ec-ser x adapter', pairs: EC_SER_ADAPTER_STIMULUS_PAIRS, resolver: resolveEcSerAdapterFixture },
  { label: 'ec-ser x artifact', pairs: EC_ARTIFACT_STIMULUS_PAIRS, resolver: resolveEcArtifactFixture },
  // One registration for the six capability-transform groups, which share a
  // single parameterized resolver (the nG -> 1R case from M3.2.4b-2.9).
  { label: 'capability (6 groups)', pairs: CAPABILITY_STIMULUS_PAIRS, resolver: resolveCapabilityFixture },
];

export function pairKey(mutationId: string, stimulusInstanceId: string): string {
  return `${mutationId}::${stimulusInstanceId}`;
}

function registryPairKeys(): ReadonlySet<string> {
  const keys = new Set<string>();
  for (const e of MUTATION_REGISTRY) {
    for (const si of e.stimulusInstances) keys.add(pairKey(e.mutationId, si.stimulusInstanceId));
  }
  return keys;
}

function buildIndex(): ReadonlyMap<string, FixtureResolver> {
  const index = new Map<string, FixtureResolver>();
  const owner = new Map<string, string>();

  for (const group of GROUPS) {
    for (const [mutationId, stimulusInstanceId] of group.pairs) {
      const key = pairKey(mutationId, stimulusInstanceId);
      if (index.has(key)) {
        throw new FixtureIndexError(
          `Pair ${key} is claimed by both '${owner.get(key)}' and '${group.label}'; ` +
          'exactly one resolver must serve each pair.',
        );
      }
      index.set(key, group.resolver);
      owner.set(key, group.label);
    }
  }

  const registry = registryPairKeys();
  const missing = [...registry].filter((k) => !index.has(k)).sort();
  const orphans = [...index.keys()].filter((k) => !registry.has(k)).sort();

  if (missing.length > 0) {
    throw new FixtureIndexError(
      `${missing.length} registry pair(s) have no resolver: ${missing.slice(0, 5).join(', ')}${missing.length > 5 ? ', ...' : ''}.`,
    );
  }
  if (orphans.length > 0) {
    throw new FixtureIndexError(
      `${orphans.length} indexed pair(s) have no registry entry: ${orphans.slice(0, 5).join(', ')}${orphans.length > 5 ? ', ...' : ''}. ` +
      'A pair that cannot be scored must not be resolvable.',
    );
  }
  return index;
}

export const FIXTURE_INDEX: ReadonlyMap<string, FixtureResolver> = buildIndex();

export function getFixtureResolver(mutationId: string, stimulusInstanceId: string): FixtureResolver {
  const resolver = FIXTURE_INDEX.get(pairKey(mutationId, stimulusInstanceId));
  if (resolver === undefined) {
    throw new FixtureIndexError(`No fixture resolver indexed for ${pairKey(mutationId, stimulusInstanceId)}.`);
  }
  return resolver;
}

export function indexedPairKeys(): readonly string[] {
  return [...FIXTURE_INDEX.keys()].sort();
}
