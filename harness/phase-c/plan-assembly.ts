// M3.2.4b-3.5 -- structural ExecutionPlan assembly.
//
//     assembleStructuralPlan(pool) -> StructuralExecutionPlan
//
// Deterministic composition of already-normative sources. It CONSUMES and
// never reinvents: the frozen registry, APPLICABILITY_MATRIX, MUTATION_INDEX,
// FIXTURE_INDEX, planObservations, decideExecutability and the provider
// manifests. No cryptography, no generation, no new scientific semantics.
//
// --- Why the type omits `resolve` ---
//
// PlanEntry (the executable form) carries a resolve callback that must
// return a RelationObservation, which means calling the frozen evaluator for
// its relation. That wiring is b-3.6's own work. Rather than filling the
// field with a stub -- which could produce apparently valid observations --
// the structural types simply DO NOT HAVE it:
//
//     FixtureResolver  : (c, s, pool)  -> F_0
//     RelationEvaluator: Evidence      -> RelationObservation
//
// so a fake resolve is not merely discouraged here, it is unconstructible.
// The property this step delivers is precisely
//     plan structurally complete  AND  NOT scientifically executable yet
// and b-3.6 turns that into a wired plan.

import type { OperationId } from '../schema/capability.js';
import type { BackendIdentity } from '../schema/backend-identity.js';
import { CHROMIUM_WEBCRYPTO, CRYPTOPP, BOUNCY_CASTLE } from '../schema/backend-identity.js';
import type { RelationApplicability, MutationRegistryEntry } from '../schema/registry-types.js';
import type { PlannedObservation, PlannedExecutability, NonExecutionReason } from '../evidence/mutation-instance-result.js';
import type { MutationImplementation } from '../mutations/framework.js';
import { MUTATION_REGISTRY } from '../registry/mutations.js';
import { APPLICABILITY_MATRIX } from '../applicability/matrix.js';
import { planObservations } from '../capability/observation-planner.js';
import { decideExecutability } from '../capability/executability.js';
import { STIMULUS_CAPABILITY_REQUIREMENTS } from '../requirements/stimulus-requirements.js';
import { CHROMIUM_DECLARATIONS } from '../../manifests/providers/chromium.js';
import { CRYPTOPP_DECLARATIONS } from '../../manifests/providers/cryptopp.js';
import { BC_DECLARATIONS } from '../../manifests/providers/bc.js';
import { getMutationImplementation } from './mutation-index.js';
import { getFixtureResolver } from './fixture-index.js';
import type { FrozenMaterialPool } from './material/pool.js';
import { resolveInteropEligibility, computeEntryHash } from './interop-eligibility/resolve.js';
import { registryEntryHash } from '../evidence/registry-binding.js';
import type { InstanceInteropEligibility } from '../evidence/mutation-instance-result.js';

export class PlanAssemblyError extends Error {}

// --- Structural types (no resolve, by construction) -----------------------

export interface StructuralPlanEntry {
  readonly relation: PlannedObservation['relation'];
  readonly scope: PlannedObservation['scope'];
}

export interface StructuralStimulusInstance {
  readonly stimulusInstanceId: string;
  readonly baseFixture: unknown;
  // M3-H9.3a-3.2.5c, connection 2 of 4 -- resolved from the pre-derived
  // registry, never derived here. The assembler CONSUMES: it does not run
  // mutate(), does not call a contractual validator, and does not inspect
  // the fixture. Present only when Applicability(o, R_interop) = 1, so
  // HKDF's own instances carry nothing.
  //
  // Deliberately a SIBLING of executability, never a member of it:
  //     Eligibility  = Eligibility(c,s)
  //     Executability = Executability(c,s,scope)
  // M3-H9.3a-3.2.3 measured what collapsing them costs -- 24 of 71 classes
  // would lose their entire r(c) because a normative exclusion was routed
  // through a mechanism built for an environmental one.
  readonly interopEligibility?: InstanceInteropEligibility;
  // M3-H6: one decision per structural entry, for THIS stimulus.
  readonly executability: readonly {
    readonly relation: PlannedObservation['relation'];
    readonly scope: PlannedObservation['scope'];
    readonly state: PlannedObservation['executability'];
  }[];
}

export interface StructuralClassPlan {
  readonly mutationId: string;
  readonly operation: OperationId;
  readonly gamma0Ref: string;
  readonly registryEntryHash: string;
  readonly applicability: RelationApplicability;
  readonly expectedSpectrum: MutationRegistryEntry['expectedSpectrum'];
  readonly mutation: MutationImplementation<unknown>;
  readonly entries: readonly StructuralPlanEntry[];
  readonly stimulusInstances: readonly StructuralStimulusInstance[];
}

export interface StructuralExecutionPlan {
  readonly classes: readonly StructuralClassPlan[];
}

// --- The pinned backend set ------------------------------------------------

export const PLAN_BACKENDS: readonly BackendIdentity[] = Object.freeze([
  CHROMIUM_WEBCRYPTO, CRYPTOPP, BOUNCY_CASTLE,
]);

const DECLARATIONS_BY_PIN = new Map([
  [CHROMIUM_WEBCRYPTO.sourcePin, CHROMIUM_DECLARATIONS],
  [CRYPTOPP.sourcePin, CRYPTOPP_DECLARATIONS],
  [BOUNCY_CASTLE.sourcePin, BC_DECLARATIONS],
]);

// Every backend a scope names must be executable for the observation to be
// required. The rule was fixed in M3-H6 and is applied once, here.
//
// M3-H8: cross-backend-set is expressed as the general conjunction over its
// members rather than as backends[0] && backends[1]. R_byte uses sets of
// exactly two today, but the variant IS a set, and hard-coding two members
// would silently mis-handle any future set of another size instead of
// failing visibly.
//     required({p,q,...}) <=> AND over p in backends of Exec(p, s)
function stateForScope(
  scope: PlannedObservation['scope'],
  executable: ReadonlyMap<string, boolean>,
  // M3-H9.3a-3.1: the reason a scope is not executable is part of the PLAN,
  // not something the run discovers. Defaults to the capability cause, which
  // is what a backend-level executability decision means.
  notExecutableReason: NonExecutionReason = 'backend-capability-absent',
): PlannedExecutability {
  let ok: boolean;
  switch (scope.kind) {
    case 'backend-pair':
      ok = executable.get(scope.from.sourcePin) === true && executable.get(scope.to.sourcePin) === true;
      break;
    case 'cross-backend-set':
      ok = scope.backends.length > 0
        && scope.backends.every((b) => executable.get(b.sourcePin) === true);
      break;
    case 'single-backend':
    case 'manifest':
      ok = executable.get(scope.backend.sourcePin) === true;
      break;
  }
  return ok
    ? { kind: 'required' }
    : { kind: 'structurally-not-executable', reason: notExecutableReason };
}

// --- Assembly ---------------------------------------------------------------

export function assembleStructuralPlan(pool: FrozenMaterialPool): StructuralExecutionPlan {
  const classes: StructuralClassPlan[] = [];

  for (const entry of MUTATION_REGISTRY) {
    const applicability = APPLICABILITY_MATRIX[entry.operation];
    if (applicability === undefined) {
      throw new PlanAssemblyError(`No normative applicability row for operation '${entry.operation}'.`);
    }

    // Scopes are class-invariant: derived once per class, shared by every
    // stimulus. This is the half of the original design M3-H6 preserved.
    const { planned } = planObservations(entry.operation, applicability, PLAN_BACKENDS);

    // M3-H8: Phase C structural guard, enforced at assembly rather than left
    // to a test. R_byte must be an unordered PAIR of distinct providers; a
    // three-provider R_byte set would preserve the expected cardinality by
    // accident while measuring something else entirely. R_interop must stay
    // directed, so a silent swap of the two kinds is refused too.
    for (const p of planned) {
      if (p.relation === 'R_byte') {
        if (p.scope.kind !== 'cross-backend-set') {
          throw new PlanAssemblyError(
            `${entry.mutationId}: R_byte scope is '${p.scope.kind}'; Phase C requires cross-backend-set ` +
            '(single-backend is Phase A own scope, per the frozen design).',
          );
        }
        if (p.scope.backends.length !== 2) {
          throw new PlanAssemblyError(
            `${entry.mutationId}: R_byte scope names ${p.scope.backends.length} providers; exactly 2 are required.`,
          );
        }
      }
      if (p.relation === 'R_interop' && p.scope.kind !== 'backend-pair') {
        throw new PlanAssemblyError(
          `${entry.mutationId}: R_interop scope is '${p.scope.kind}'; its direction is part of the observation identity.`,
        );
      }
    }

    const entries: StructuralPlanEntry[] = planned.map((p) => ({ relation: p.relation, scope: p.scope }));

    const stimulusInstances: StructuralStimulusInstance[] = entry.stimulusInstances.map((si) => {
      // Executability is resolved per (class, stimulus, backend) -- M3-H6.
      const executable = new Map<string, boolean>();
      for (const backend of PLAN_BACKENDS) {
        const declarations = DECLARATIONS_BY_PIN.get(backend.sourcePin);
        if (declarations === undefined) {
          throw new PlanAssemblyError(`No manifest for backend '${backend.family}'.`);
        }
        const decision = decideExecutability(
          entry.mutationId, si.stimulusInstanceId, backend, declarations, STIMULUS_CAPABILITY_REQUIREMENTS,
        );
        executable.set(backend.sourcePin, decision.status === 'executable');
      }

      const resolver = getFixtureResolver(entry.mutationId, si.stimulusInstanceId);
      const baseFixture = resolver(entry.mutationId, si.stimulusInstanceId, pool);

      // Resolved once per (c,s), at assembly time, because the plan is
      // pre-registered before M4: the run must never decide what should
      // have been evaluated.
      let interopEligibility: InstanceInteropEligibility | undefined;
      if (applicability.R_interop) {
        const resolved = resolveInteropEligibility(entry.mutationId, si.stimulusInstanceId);
        interopEligibility = {
          value: resolved.eligibility,
          source: resolved.source,
          entryHash: computeEntryHash(resolved),
        };
      }

      return {
        stimulusInstanceId: si.stimulusInstanceId,
        baseFixture,
        ...(interopEligibility !== undefined ? { interopEligibility } : {}),
        // Keys(ExecMap_{c,s}) = Entries_c, by construction: one decision per
        // structural entry, in the same order, never fewer and never more.
        executability: entries.map((e) => {
          // M3-reopen-v5: OAEP-KEY-ROLE-BYPASS::decrypt-with-public is
          // contractually eligible for R_interop, but its directed transfer
          // cannot be materialized from the frozen corpus: the mutated
          // consumer requires a nominal OAEP producer artifact that this
          // stimulus does not provide. Preserve Eligibility=1 and classify
          // only the six directed R_interop scopes as structurally
          // non-executable.
          const directionNotMaterializable =
            entry.mutationId === 'OAEP-KEY-ROLE-BYPASS' &&
            si.stimulusInstanceId === 'decrypt-with-public' &&
            e.relation === 'R_interop';

          // M3-reopen-v5: the Chromium RSA serialization production import
          // bridge returns native WebCrypto error text but does not expose the
          // SDK error class required by R_err. Keep the Crypto++ and
          // Bouncy Castle import scopes, which do expose errorClass, and mark
          // only the Chromium single-backend R_err scope non-executable.
          const serializationChromiumErrClassNotExposed =
            (entry.operation === 'rsa-ser' || entry.operation === 'ec-ser') &&
            e.relation === 'R_err' &&
            e.scope.kind === 'single-backend' &&
            e.scope.backend.sourcePin === CHROMIUM_WEBCRYPTO.sourcePin;

          return {
            relation: e.relation,
            scope: e.scope,
            state: directionNotMaterializable
              ? { kind: 'structurally-not-executable', reason: 'direction-not-materializable' }
              : serializationChromiumErrClassNotExposed
                ? { kind: 'structurally-not-executable', reason: 'stimulus-not-expressible' }
                : stateForScope(e.scope, executable),
          };
        }),
      };
    });

    classes.push({
      mutationId: entry.mutationId,
      operation: entry.operation,
      // M3.3: bound to the entry's CONTENT, not to its name. A name survives
      // a change of content; this does not.
      gamma0Ref: `registry:${entry.mutationId}`,
      registryEntryHash: registryEntryHash(entry.mutationId),
      applicability,
      expectedSpectrum: entry.expectedSpectrum,
      mutation: getMutationImplementation(entry.mutationId),
      entries,
      stimulusInstances,
    });
  }

  return { classes };
}

// --- Derived cardinalities, computed from a plan rather than restated -----

export interface PlanCardinality {
  readonly classes: number;
  readonly stimulusInstances: number;
  readonly plannedObservations: number;
  readonly required: number;
  readonly notExecutable: number;
}

export function planCardinality(plan: StructuralExecutionPlan): PlanCardinality {
  let stimulusInstances = 0, plannedObservations = 0, required = 0, notExecutable = 0;
  for (const c of plan.classes) {
    for (const si of c.stimulusInstances) {
      stimulusInstances += 1;
      plannedObservations += si.executability.length;
      for (const x of si.executability) {
        if (x.state.kind === 'required') required += 1; else notExecutable += 1;
      }
    }
  }
  return { classes: plan.classes.length, stimulusInstances, plannedObservations, required, notExecutable };
}

// M3-H7: two DIFFERENT states, deliberately reported separately because
// conflating them would misstate the instrument.
//
//   instance-level:  |required(c,s,R)| = 0  -- this stimulus is outside
//                    S_R(c) and does not vote. Benign: other stimuli of the
//                    same class may still carry the relation.
//   class-level:     |S_R(c)| = 0           -- NO stimulus supports it, so
//                    r_R(c) is unscorable and must never be a vacuous pass.
//
// Every class-level case is also an instance-level one, but not conversely:
// GCM-TAGLENGTH-PROFILE-BOUNDARY-BYPASS has two unsupported stimuli and one
// supported, so it is instance-level twice and class-level never.
export function zeroSupportInstances(
  plan: StructuralExecutionPlan,
): readonly { readonly mutationId: string; readonly stimulusInstanceId: string; readonly relation: string }[] {
  const out: { mutationId: string; stimulusInstanceId: string; relation: string }[] = [];
  for (const c of plan.classes) {
    const relations = new Set(c.entries.map((e) => e.relation));
    for (const si of c.stimulusInstances) {
      for (const relation of relations) {
        const supported = si.executability.some((x) => x.relation === relation && x.state.kind === 'required');
        if (!supported) out.push({ mutationId: c.mutationId, stimulusInstanceId: si.stimulusInstanceId, relation });
      }
    }
  }
  return out.sort((a, b) => `${a.mutationId}${a.stimulusInstanceId}${a.relation}`
    .localeCompare(`${b.mutationId}${b.stimulusInstanceId}${b.relation}`));
}

// The class-level subset: applicable yet with zero executable scope in EVERY
// stimulus -- so r(c) cannot be scored for them.
// Reported from the assembled plan so a future refactor cannot quietly turn
// one of them back into a scorable pass.
export function zeroSupportRelations(
  plan: StructuralExecutionPlan,
): readonly { readonly mutationId: string; readonly relation: string }[] {
  const out: { mutationId: string; relation: string }[] = [];
  for (const c of plan.classes) {
    const relations = new Set(c.entries.map((e) => e.relation));
    for (const relation of relations) {
      const anySupport = c.stimulusInstances.some((si) =>
        si.executability.some((x) => x.relation === relation && x.state.kind === 'required'));
      if (!anySupport) out.push({ mutationId: c.mutationId, relation });
    }
  }
  return out.sort((a, b) => (a.mutationId === b.mutationId
    ? a.relation.localeCompare(b.relation) : a.mutationId.localeCompare(b.mutationId)));
}
