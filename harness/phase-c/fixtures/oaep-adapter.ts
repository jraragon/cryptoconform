// M3.2.4b-2.5 -- OAEP x adapter-transform fixture resolvers.
//
// Ordered to hold the OPERATION fixed while changing the MECHANISM, the
// same isolation used for GCM. It produced two findings that the GCM
// adapter group could not have predicted:
//
//   GCM_adapter shape  =/=>  OAEP_adapter shape
//
// --- Finding 1: this group is TWO shapes, and one COMPOSES the request ---
//
//   OaepErrorMappingIntervention  { triggeringCondition, declaredErrorClass }
//   OaepAdapterInvocation         { request: OaepEncryptRequest,
//                                   externalRandomnessProvided: boolean }
//
// The second one WRAPS an OaepEncryptRequest. That is a genuinely new
// relationship: for GCM, AdapterFixture and RequestFixture were
// structurally disjoint and a test asserted the adapter resolver must NOT
// delegate to the request resolver. Here delegation is not merely allowed
// but REQUIRED -- the type literally embeds the request, and rebuilding it
// independently would create a second source of truth for the same object.
// The GCM rule was not a general law about adapter fixtures; it was the
// correct rule for a disjoint pair.
//
// --- Finding 2: the correct error-mapping baseline differs from GCM's ---
//
// For GCM the contractually correct class was NEITHER of the two values
// mutate() toggles between, so the mutation necessarily departed from
// correct behaviour. Here the opposite holds by design: the frozen contract
// collapses several native causes to a single generic class (RFC 8017
// Sec.7.1.2's anti-oracle rule, D-034), and the intervention reports a MORE
// SPECIFIC -- therefore oracle-leaking -- class instead. So the correct
// baseline IS one of the two toggled values, and the mutation moves away
// from it. Assuming GCM's shape of argument here would have inverted the
// experiment.

import type { OaepEncryptRequest } from '../../../src/contract/oaep.js';
import type { OaepErrorMappingIntervention, OaepAdapterInvocation } from '../../mutations/oaep.js';
import type { FrozenMaterialPool } from '../material/pool.js';
import { MUTATION_REGISTRY } from '../../registry/mutations.js';
import { FixtureResolutionError } from './hkdf-request.js';
import { resolveOaepEncryptRequestFixture } from './oaep-request.js';

// The generic class the frozen contract collapses OAEP decryption failures
// to, per D-034 / RFC 8017 Sec.7.1.2. A correct adapter reports exactly
// this and nothing more specific, so it is what the unmutated baseline
// declares; mutate() then replaces it with a narrower class, which is the
// oracle leak under test.
export const OAEP_BASELINE_DECLARED_ERROR_CLASS = 'decryption_error';

// The condition whose native causes the contract deliberately refuses to
// distinguish -- naming it makes explicit that the baseline's correctness
// depends on NOT disclosing which cause occurred.
export const OAEP_BASELINE_TRIGGERING_CONDITION = 'decrypt-failure-cause-indistinguishable';

// The portable OAEP request carries no randomness-injection control at all;
// the unmutated adapter invocation therefore provides none, and mutate()
// flips the flag to expose a native interface the portable profile hides.
export const OAEP_BASELINE_EXTERNAL_RANDOMNESS_PROVIDED = false;

const OAEP_ADAPTER_ENTRIES = MUTATION_REGISTRY.filter(
  (e) => e.operation === 'oaep' && e.mechanism === 'adapter-transform',
);

export const OAEP_ADAPTER_MUTATION_IDS: readonly string[] =
  OAEP_ADAPTER_ENTRIES.map((e) => e.mutationId).sort();

export const OAEP_ADAPTER_STIMULUS_PAIRS: readonly (readonly [string, string])[] =
  OAEP_ADAPTER_ENTRIES
    .flatMap((e) => e.stimulusInstances.map((s) => [e.mutationId, s.stimulusInstanceId] as const))
    .sort((a, b) => (a[0] === b[0] ? a[1].localeCompare(b[1]) : a[0].localeCompare(b[0])));

// Which of the two shapes a class uses is derived from its own frozen
// Gamma_0 rather than from a hard-coded id: the randomness-leak class is
// the one whose intervened clauses concern randomness.
function usesAdapterInvocation(mutationId: string): boolean {
  const entry = OAEP_ADAPTER_ENTRIES.find((e) => e.mutationId === mutationId);
  return entry !== undefined && entry.gamma0.some((c) => c.includes('randomness'));
}

export function isOaepAdapterInvocationClass(mutationId: string): boolean {
  return usesAdapterInvocation(mutationId);
}

function assertRegistered(mutationId: string, stimulusInstanceId: string): void {
  const known = OAEP_ADAPTER_STIMULUS_PAIRS.some(([m, s]) => m === mutationId && s === stimulusInstanceId);
  if (!known) {
    throw new FixtureResolutionError(
      `(${mutationId}, ${stimulusInstanceId}) is not a registered oaep x adapter-transform stimulus pair.`,
    );
  }
}

// ---------------------------------------------------------------------
// Resolver A: OaepErrorMappingIntervention -- no material, pure adapter
// configuration, exactly as in the GCM adapter group.
// ---------------------------------------------------------------------

export function resolveOaepErrorMappingFixture(
  mutationId: string,
  stimulusInstanceId: string,
  _pool: FrozenMaterialPool,
): OaepErrorMappingIntervention {
  assertRegistered(mutationId, stimulusInstanceId);
  if (usesAdapterInvocation(mutationId)) {
    throw new FixtureResolutionError(`${mutationId} uses OaepAdapterInvocation, not OaepErrorMappingIntervention.`);
  }
  return {
    triggeringCondition: OAEP_BASELINE_TRIGGERING_CONDITION,
    declaredErrorClass: OAEP_BASELINE_DECLARED_ERROR_CLASS,
  };
}

// ---------------------------------------------------------------------
// Resolver B: OaepAdapterInvocation -- COMPOSES the request fixture.
//
// The embedded request is obtained from the request-transform resolver
// rather than rebuilt here, so both groups share one definition of what an
// unmutated OAEP encrypt request is. A local reconstruction would drift.
// ---------------------------------------------------------------------

export function resolveOaepAdapterInvocationFixture(
  mutationId: string,
  stimulusInstanceId: string,
  pool: FrozenMaterialPool,
): OaepAdapterInvocation {
  assertRegistered(mutationId, stimulusInstanceId);
  if (!usesAdapterInvocation(mutationId)) {
    throw new FixtureResolutionError(`${mutationId} does not use OaepAdapterInvocation.`);
  }
  // Borrows a request-transform class's own baseline request: the embedded
  // object is the same experimental input, and this group intervenes only
  // on the surrounding invocation flag.
  const carrierId = MUTATION_REGISTRY.find(
    (e) => e.operation === 'oaep' && e.mechanism === 'request-transform' && e.stimulusInstances.length === 1,
  )?.mutationId;
  if (carrierId === undefined) {
    throw new FixtureResolutionError('No single-stimulus oaep request-transform class available to supply the embedded request.');
  }
  const request = resolveOaepEncryptRequestFixture(carrierId, 'default', pool) as OaepEncryptRequest;

  return { request, externalRandomnessProvided: OAEP_BASELINE_EXTERNAL_RANDOMNESS_PROVIDED };
}

export function resolveOaepAdapterFixture(
  mutationId: string,
  stimulusInstanceId: string,
  pool: FrozenMaterialPool,
): OaepErrorMappingIntervention | OaepAdapterInvocation {
  return usesAdapterInvocation(mutationId)
    ? resolveOaepAdapterInvocationFixture(mutationId, stimulusInstanceId, pool)
    : resolveOaepErrorMappingFixture(mutationId, stimulusInstanceId, pool);
}
