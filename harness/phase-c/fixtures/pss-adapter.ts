// M3.2.4b-2.7 -- PSS x adapter-transform fixture resolvers.
//
// 3 classes, 3 pairs, TWO shapes -- but with a distribution not seen
// before: two classes SHARE one shape, each intervening on a different
// field of it.
//
//   PssAdapterInvocation         2 classes  { request, externalRandomnessProvided,
//                                             explicitSaltBytesProvided }
//   PssErrorMappingIntervention  1 class    { triggeringCondition, declaredErrorClass }
//
// --- Finding: a fourth distribution pattern ---
//
// Every earlier group had at most one class per shape:
//   GCM adapter   one shape, one class, disjoint from the request
//   OAEP adapter  two shapes, one class each; one composed the request
//   PSS request   three shapes, one class each (7/1/1)
// Here PssAdapterInvocation carries THREE fields and is shared by two
// classes -- PSS-RNG-INTERFACE-LEAK targets externalRandomnessProvided,
// PSS-SALT-BYTES-INTERFACE-LEAK targets explicitSaltBytesProvided -- so one
// resolver legitimately serves both, and the two interventions remain
// distinct because their directInterventionTargets differ, not because
// their fixtures do. OAEP's own adapter invocation had only two fields and
// a single class; assuming the same arity here would have dropped a field.
//
// --- Composition, per the settled rule ---
//
// PssAdapterInvocation embeds a PssSignRequest, so the embedded object is
// borrowed from the request-transform resolver rather than rebuilt:
//     delegate(F_A, F_B)  <=>  T_A structurally contains the same canonical F_B
// The error-mapping shape, by contrast, remains disjoint -- both
// relationships coexist in this group, exactly as they did for OAEP.

import type { PssSignRequest } from '../../../src/contract/pss.js';
import type { PssAdapterInvocation, PssErrorMappingIntervention } from '../../mutations/pss.js';
import type { FrozenMaterialPool } from '../material/pool.js';
import { MUTATION_REGISTRY } from '../../registry/mutations.js';
import { FixtureResolutionError } from './hkdf-request.js';
import { resolvePssSignRequestFixture, isPssKeyRoleBypass, isPssVerifyRequestClass } from './pss-request.js';

// The portable PSS request exposes neither an RNG-injection control nor an
// explicit-salt-bytes control; both are native surfaces the portable
// profile hides. The unmutated invocation therefore provides neither, and
// each class's own mutate() flips exactly one of them.
export const PSS_BASELINE_EXTERNAL_RANDOMNESS_PROVIDED = false;
export const PSS_BASELINE_EXPLICIT_SALT_BYTES_PROVIDED = false;

// Derived from the frozen contract: validatePssSignRequest raises
// 'invalid_key' when signing is attempted with a non-private key. That is
// what a correct adapter reports for this condition, so it is what the
// unmutated baseline declares. mutate() then reports 'invalid_parameter'
// instead -- a real misclassification, since a key-role failure is not a
// parameter failure.
//
// Note this is the OAEP-shaped argument, not the GCM-shaped one: here the
// correct class IS one of the two values mutate() toggles between, and the
// mutation moves away from it. E_PSS^SDK has only three classes at all
// (D-047: unsupported, invalid_key, invalid_parameter), and 'unsupported'
// is never raised by the request-validation path, so it could not have
// served as a derivable third baseline.
export const PSS_BASELINE_TRIGGERING_CONDITION = 'sign-with-public-key';
export const PSS_BASELINE_DECLARED_ERROR_CLASS = 'invalid_key';

const PSS_ADAPTER_ENTRIES = MUTATION_REGISTRY.filter(
  (e) => e.operation === 'pss' && e.mechanism === 'adapter-transform',
);

export const PSS_ADAPTER_MUTATION_IDS: readonly string[] =
  PSS_ADAPTER_ENTRIES.map((e) => e.mutationId).sort();

export const PSS_ADAPTER_STIMULUS_PAIRS: readonly (readonly [string, string])[] =
  PSS_ADAPTER_ENTRIES
    .flatMap((e) => e.stimulusInstances.map((s) => [e.mutationId, s.stimulusInstanceId] as const))
    .sort((a, b) => (a[0] === b[0] ? a[1].localeCompare(b[1]) : a[0].localeCompare(b[0])));

// Shape selection derived from each class's own frozen Gamma_0: the
// error-mapping class is the one intervening on pss.error; the other two
// intervene on native control surfaces.
function gamma0Of(mutationId: string): readonly string[] {
  return PSS_ADAPTER_ENTRIES.find((e) => e.mutationId === mutationId)?.gamma0 ?? [];
}

export function isPssErrorMappingClass(mutationId: string): boolean {
  return gamma0Of(mutationId).some((c) => c.endsWith('.error'));
}

function assertRegistered(mutationId: string, stimulusInstanceId: string): void {
  const known = PSS_ADAPTER_STIMULUS_PAIRS.some(([m, s]) => m === mutationId && s === stimulusInstanceId);
  if (!known) {
    throw new FixtureResolutionError(
      `(${mutationId}, ${stimulusInstanceId}) is not a registered pss x adapter-transform stimulus pair.`,
    );
  }
}

// ---------------------------------------------------------------------
// Resolver A: PssAdapterInvocation -- shared by TWO classes
// ---------------------------------------------------------------------

export function resolvePssAdapterInvocationFixture(
  mutationId: string,
  stimulusInstanceId: string,
  pool: FrozenMaterialPool,
): PssAdapterInvocation {
  assertRegistered(mutationId, stimulusInstanceId);
  if (isPssErrorMappingClass(mutationId)) {
    throw new FixtureResolutionError(`${mutationId} uses PssErrorMappingIntervention, not PssAdapterInvocation.`);
  }

  // Borrow a plain sign-request class's own baseline, so both groups share
  // one definition of an unmutated PSS sign request.
  const carrierId = MUTATION_REGISTRY.find(
    (e) => e.operation === 'pss' && e.mechanism === 'request-transform'
      && !isPssKeyRoleBypass(e.mutationId) && !isPssVerifyRequestClass(e.mutationId),
  )?.mutationId;
  if (carrierId === undefined) {
    throw new FixtureResolutionError('No plain pss request-transform class available to supply the embedded request.');
  }
  const request: PssSignRequest = resolvePssSignRequestFixture(carrierId, 'default', pool);

  return {
    request,
    externalRandomnessProvided: PSS_BASELINE_EXTERNAL_RANDOMNESS_PROVIDED,
    explicitSaltBytesProvided: PSS_BASELINE_EXPLICIT_SALT_BYTES_PROVIDED,
  };
}

// ---------------------------------------------------------------------
// Resolver B: PssErrorMappingIntervention -- disjoint, no material
// ---------------------------------------------------------------------

export function resolvePssErrorMappingFixture(
  mutationId: string,
  stimulusInstanceId: string,
  _pool: FrozenMaterialPool,
): PssErrorMappingIntervention {
  assertRegistered(mutationId, stimulusInstanceId);
  if (!isPssErrorMappingClass(mutationId)) {
    throw new FixtureResolutionError(`${mutationId} does not use PssErrorMappingIntervention.`);
  }
  return {
    triggeringCondition: PSS_BASELINE_TRIGGERING_CONDITION,
    declaredErrorClass: PSS_BASELINE_DECLARED_ERROR_CLASS,
  };
}

export function resolvePssAdapterFixture(
  mutationId: string,
  stimulusInstanceId: string,
  pool: FrozenMaterialPool,
): PssAdapterInvocation | PssErrorMappingIntervention {
  return isPssErrorMappingClass(mutationId)
    ? resolvePssErrorMappingFixture(mutationId, stimulusInstanceId, pool)
    : resolvePssAdapterInvocationFixture(mutationId, stimulusInstanceId, pool);
}
