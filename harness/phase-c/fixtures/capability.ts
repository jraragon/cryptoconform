// M3.2.4b-2.9 -- capability-transform fixture resolver.
//
// ONE resolver serving SIX groups (hkdf, gcm, oaep, pss, rsa-ser, ec-ser
// x capability-transform), 6 classes, 6 pairs. This is the third
// group/resolver relationship the binding work has produced:
//     1 group  -> 1 resolver   (HKDF x request, GCM x request/adapter)
//     1 group  -> N resolvers  (OAEP x request, PSS x request, ...)
//     N groups -> 1 resolver   (here)
//
// Universality was DEMONSTRATED before being relied on, not assumed from
// the shared type name:
//
//   Same TYPE?  Yes, but with a caveat worth recording:
//     CapabilityDeclarationExperimentalView is declared SIX SEPARATE TIMES,
//     once per mutation module -- not one shared declaration. All six are
//     textually identical, and TypeScript unifies them structurally, so the
//     single resolver is sound. But it is six declarations, not one.
//
//   Same SEMANTICS?  Yes. All six mutate() bodies flip `support`, and all
//     six declare directInterventionTargets: ['support']. HKDF's differs
//     only in line formatting.
//
//   Same Gamma_0?  NO -- and it does not matter here. The six carry four
//     different clause shapes ('ec-ser.cap', 'gcm.cap.provider', a bare
//     'cap' for rsa-ser, and three clauses for hkdf). Gamma_0 is used
//     elsewhere to DISCRIMINATE between shapes within a group; with a
//     single shape there is nothing to discriminate, so the heterogeneity
//     is real but inert for this resolver.
//
// --- Parameterized, not operation-blind ---
//
// The one field carrying operation-specific content is capabilityId, and it
// is DERIVED from the frozen provider manifests rather than fixed:
//     forall op:  exists! c in Manifest(op) with kind = 'provider-support'
//                 and capabilityId = '<op>.provider.support'
// So the operation enters as DATA, never as a branch. There is no
// per-operation branch anywhere below, and a test asserts as much.
//
// Note the portable profile could NOT have supplied this: it declares 14
// capabilities covering only gcm/oaep/pss, and has nothing at all for
// hkdf, rsa-ser or ec-ser -- all three of which nonetheless have a
// capability-transform class. Reaching for the portable profile first
// would have failed for exactly half the groups.

import type { OperationId } from '../../schema/capability.js';
import type { CapabilityDeclarationExperimentalView } from '../../mutations/pss.js';
import type { FrozenMaterialPool } from '../material/pool.js';
import { MUTATION_REGISTRY } from '../../registry/mutations.js';
import { CHROMIUM_DECLARATIONS } from '../../../manifests/providers/chromium.js';
import { FixtureResolutionError } from './hkdf-request.js';

const CAPABILITY_ENTRIES = MUTATION_REGISTRY.filter((e) => e.mechanism === 'capability-transform');

export const CAPABILITY_MUTATION_IDS: readonly string[] =
  CAPABILITY_ENTRIES.map((e) => e.mutationId).sort();

export const CAPABILITY_STIMULUS_PAIRS: readonly (readonly [string, string])[] =
  CAPABILITY_ENTRIES
    .flatMap((e) => e.stimulusInstances.map((s) => [e.mutationId, s.stimulusInstanceId] as const))
    .sort((a, b) => (a[0] === b[0] ? a[1].localeCompare(b[1]) : a[0].localeCompare(b[0])));

// Resolves the unique provider-support capability of an operation from the
// frozen manifest. Fail-closed on zero or on more than one: an ambiguous
// declaration must never be silently disambiguated by picking the first.
export function providerSupportCapabilityId(operation: OperationId): string {
  const matches = CHROMIUM_DECLARATIONS.filter(
    (d) => d.kind === 'provider-support' && d.capabilityId === `${operation}.provider.support`,
  );
  if (matches.length === 0) {
    throw new FixtureResolutionError(
      `No provider-support capability declared for operation '${operation}' in the frozen manifest.`,
    );
  }
  if (matches.length > 1) {
    throw new FixtureResolutionError(
      `Operation '${operation}' declares ${matches.length} provider-support capabilities under the same id; ` +
      'refusing to choose one arbitrarily.',
    );
  }
  return matches[0]!.capabilityId;
}

// The baseline declares the CORRECT support state, so that mutate() -- which
// flips it -- produces a genuine misdeclaration. All three pinned providers
// declare 'supported' for all six operations (verified before this constant
// was fixed), so the correct baseline is unambiguous without the resolver
// needing to know which provider is in play.
export const CAPABILITY_BASELINE_SUPPORT = 'supported' as const;

export function resolveCapabilityFixture(
  mutationId: string,
  stimulusInstanceId: string,
  _pool: FrozenMaterialPool, // capability declarations are not cryptographic material
): CapabilityDeclarationExperimentalView {
  const entry = CAPABILITY_ENTRIES.find((e) => e.mutationId === mutationId);
  const known = entry !== undefined
    && entry.stimulusInstances.some((s) => s.stimulusInstanceId === stimulusInstanceId);
  if (!known) {
    throw new FixtureResolutionError(
      `(${mutationId}, ${stimulusInstanceId}) is not a registered capability-transform stimulus pair.`,
    );
  }

  return {
    capabilityId: providerSupportCapabilityId(entry.operation),
    kind: 'provider-support',
    support: CAPABILITY_BASELINE_SUPPORT,
  };
}
