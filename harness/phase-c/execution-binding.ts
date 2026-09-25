// M3.7.2 -- the executable-plan binder.
//
// The transition M4.0 found missing: turning the frozen structural plan into
// an ExecutionPlan whose entries can actually be resolved.
//
//     assembleStructuralPlan  ->  [ THIS ]  ->  runPhaseC
//
// --- The selection rule, and why it is the only one -----------------------
//
// Obligations are selected observation by observation through
// isRequiredEvidence(), the SAME predicate completeness uses. Nothing else is
// admissible, and D13 is why: recountPlan held a second copy of Required and
// drifted from it for a whole milestone. So this module must not select via
// planCardinality.required, via any precomputed figure, via
// PlannedExecutability as a proxy, or via a hardcoded list.
//
// 1264 is a CONSEQUENCE of walking the plan, never a target to program
// against. If the predicate changes, this binder changes with it and no test
// asserting a bare number can hide the difference.
//
// --- Discriminated by execution SHAPE, not by relation --------------------
//
// The binding is discriminated by how many backends an observation needs and
// in what roles -- not by which relation it serves. Relation-based dispatch
// would put scientific knowledge back into the plumbing, which M2.4.4's own
// restriction forbids and which C3 removed from the projection layer.
//
//     single-backend     one adapter
//     backend-set        two adapters, symmetric, no roles     (R_byte)
//     directed-transfer  producer + consumer + direction       (R_interop)
//
// PlanEntry and PhaseCOrchestrator are UNCHANGED: the runner still sees only
// { relation, scope, resolve }, and resolve closes over the binding. The role
// therefore lives in inspectable DATA rather than in a closure, which is what
// makes it auditable and what stops M3.7.3 from having to redo the shape.
//
// --- What this module may not decide --------------------------------------
//
// Backends come from the frozen SCOPE, which already names them. Key material
// comes from the frozen NOMINAL identities, never from searching the corpus
// for a compatible record: the corpus happening to hold exactly one RSA-3072
// key is an accident of its contents, and binding by uniqueness would turn
// that accident into a rule. Serialization reuses the transformation validated
// in M3.5 without change.

import { isRequiredEvidence, type PlannedObservation } from '../evidence/mutation-instance-result.js';
import type { ObservationScope } from '../evidence/observation-scope.js';
import type { BackendIdentity } from '../schema/backend-identity.js';
import type { OperationId } from '../schema/capability.js';
import type { RelationId } from '../schema/registry-types.js';
import { MUTATION_REGISTRY } from '../registry/mutations.js';
import { structurallyNonComparableRelations } from './structural-comparability.js';
import { getFixtureResolver } from './fixture-index.js';
import { getMutationImplementation } from './mutation-index.js';
import { consumerRole, producerRole, ROLES_BY_OPERATION, type ExecutionRole } from '../orchestration/dispatch.js';
import { materializeDispatch, type MaterializedDispatch } from '../orchestration/dispatch-materialization.js';
import { PHASE_C_MATERIAL_IDS } from './material/load.js';
import type { FrozenMaterialPool } from './material/pool.js';
import type { MaterialType, MaterialValue } from './material/schema.js';
import type { StructuralExecutionPlan } from './plan-assembly.js';

export class BindingError extends Error {}

/**
 * The key material an operation's adapter factories need, identified by the
 * frozen NOMINAL id and nothing else.
 *
 * Fail-closed on absence and on type. No search, no first-candidate, no
 * inference from uniqueness, no fallback: if the named record is missing or
 * is not of the expected type, binding refuses rather than finding something
 * that would work.
 */
export interface BoundMaterial {
  readonly materialId: string;
  readonly materialType: MaterialType;
  readonly value: MaterialValue;
}

const MATERIAL_BY_OPERATION: Readonly<Partial<Record<OperationId, { id: string; type: MaterialType }>>> = Object.freeze({
  // GCM binds the AES Phase-C record because an ARTIFACT-SIDE obligation needs
  // the producer's own inputs -- key, iv, plaintext and aad, all four frozen
  // there. Request-side GCM obligations take theirs from the fixture and
  // simply ignore this.
  gcm: { id: PHASE_C_MATERIAL_IDS.aes, type: 'aes-base-material' },
  oaep: { id: PHASE_C_MATERIAL_IDS.rsa, type: 'rsa-3072-keypair' },
  pss: { id: PHASE_C_MATERIAL_IDS.rsa, type: 'rsa-3072-keypair' },
  'rsa-ser': { id: PHASE_C_MATERIAL_IDS.rsa, type: 'rsa-3072-keypair' },
  'ec-ser': { id: PHASE_C_MATERIAL_IDS.ec, type: 'ec-p256-keypair' },
});

export function bindMaterial(operation: OperationId, pool: FrozenMaterialPool): BoundMaterial | undefined {
  const named = MATERIAL_BY_OPERATION[operation];
  if (named === undefined) return undefined; // HKDF and GCM bind none here
  let value: MaterialValue;
  try {
    value = pool.valueOf<MaterialValue>(named.id, named.type);
  } catch (e) {
    throw new BindingError(
      `Operation '${operation}' requires frozen material '${named.id}' of type '${named.type}', which the pool ` +
      `refused: ${(e as Error).message}. Refusing rather than binding a different record.`,
    );
  }
  return { materialId: named.id, materialType: named.type, value };
}

// ---------------------------------------------------------------------
// The binding, discriminated by execution shape
// ---------------------------------------------------------------------

export type FixtureRealization =
  | 'gcm-artifact-decrypt'
  | 'oaep-key-role-request'
  | 'pss-key-role-request'
  | 'pss-artifact-verify'
  | 'serialization-artifact-import'
  | 'rsa-material-export'
  | 'ec-material-export';

export interface SingleBackendBinding {
  readonly kind: 'single-backend';
  readonly backend: BackendIdentity;
  readonly role: ExecutionRole;
  readonly dispatch: MaterializedDispatch;
  readonly material?: BoundMaterial;
  readonly fixtureRealization?: FixtureRealization;
}

export interface BackendSetBinding {
  readonly kind: 'backend-set';
  /** Symmetric: no producer or consumer, and none may be inferred. */
  readonly backends: readonly BackendIdentity[];
  readonly role: ExecutionRole;
  readonly dispatch: readonly MaterializedDispatch[];
  readonly material?: BoundMaterial;
  readonly fixtureRealization?: FixtureRealization;
}

export interface DirectedTransferBinding {
  readonly kind: 'directed-transfer';
  readonly from: BackendIdentity;
  readonly to: BackendIdentity;
  readonly producerRole: ExecutionRole;
  readonly consumerRole: ExecutionRole;
  readonly producer: MaterializedDispatch;
  readonly consumer: MaterializedDispatch;
  readonly material?: BoundMaterial;
}

/**
 * M3.8.2 -- a capability MANIFEST observation.
 *
 * Deliberately carries NO execution role and NO materialized dispatch. A
 * manifest scope is a declaration, not a cryptographic call: the frozen model
 * has always distinguished it from single-backend -- scopeEquals treats them
 * as different variants -- and M3.7.2 collapsed the two, which gave every
 * R_cap obligation an execution role its relation does not have.
 *
 * The absence of `role` is the repair. A manifest binding that carried one
 * would preserve the defect under a new name.
 *
 * This does NOT mean R_cap executes nothing: the frozen contract requires
 * E_declaration and E_scored with distinct identities, and makeResolve
 * obtains them through runDeclarationProbe and runMutation. What it means is
 * that neither is obtained by inventing a cryptographic role.
 */
export interface ManifestBinding {
  readonly kind: 'manifest';
  readonly backend: BackendIdentity;
  readonly material?: BoundMaterial;
}

export type ExecutionBinding =
  | SingleBackendBinding | BackendSetBinding | DirectedTransferBinding | ManifestBinding;

export interface BoundObligation {
  readonly mutationId: string;
  readonly stimulusInstanceId: string;
  readonly operation: OperationId;
  readonly relation: RelationId;
  readonly scope: ObservationScope;
  readonly binding: ExecutionBinding;
}

/**
 * The role an observation's executions play, derived from the OPERATION's own
 * frozen role list -- never from the relation, and never chosen here.
 *
 * An operation with a producer/consumer split uses its producer role for the
 * single-backend and backend-set shapes, because that is the role that
 * generates the output those shapes compare. HKDF, whose only role is
 * 'derive', uses that.
 */
function primaryRole(operation: OperationId): ExecutionRole {
  const roles = ROLES_BY_OPERATION[operation];
  if (roles === undefined || roles.length === 0) {
    throw new BindingError(`Operation '${operation}' exposes no execution role.`);
  }
  return roles[0]!;
}

/**
 * Binds one required observation. Backends come from the SCOPE, which already
 * names them; this function never picks one.
 */
export function bindObservation(params: {
  readonly operation: OperationId;
  readonly relation: RelationId;
  readonly scope: ObservationScope;
  readonly pool: FrozenMaterialPool;
  readonly mechanism?: string;
  /**
   * Pre-experimental direction for rsa-ser/ec-ser, derived from the frozen
   * resolver + mutation implementation before execution. True means the
   * mutated stimulus carries an artifact and therefore exercises import.
   */
  readonly serializationArtifactInput?: boolean;
  /**
   * OAEP-KEY-ROLE-BYPASS is a discriminated request union.  Its frozen
   * stimulus determines whether the observation exercises encrypt or decrypt.
   */
  readonly oaepKeyRoleDirection?: 'encrypt' | 'decrypt';
  /**
   * PSS-KEY-ROLE-BYPASS is a discriminated request envelope whose frozen
   * instance is sign-with-public. The execution adapter consumes the
   * enclosed PssSignRequest, not the envelope itself.
   */
  readonly pssKeyRoleRequest?: boolean;
  /**
   * PSS artifact-transform fixtures carry message/signature state, while the
   * actual execution is verify-side under the frozen portable PSS profile.
   */
  readonly pssArtifactVerify?: boolean;
}): ExecutionBinding {
  const {
    operation, relation, scope, pool, mechanism, serializationArtifactInput,
    oaepKeyRoleDirection, pssKeyRoleRequest, pssArtifactVerify,
  } = params;
  const material = bindMaterial(operation, pool);

  if (relation === 'R_interop') {
    if (scope.kind !== 'backend-pair') {
      throw new BindingError(
        `R_interop requires a backend-pair scope; got '${scope.kind}'. A directional observation cannot be bound ` +
        'from a scope that does not name both ends.',
      );
    }
    const pRole = producerRole(operation);
    const cRole = consumerRole(operation);
    return {
      kind: 'directed-transfer',
      from: scope.from, to: scope.to,
      producerRole: pRole, consumerRole: cRole,
      producer: materializeDispatch(operation, scope.from, pRole),
      consumer: materializeDispatch(operation, scope.to, cRole),
      ...(material === undefined ? {} : { material }),
    };
  }



  // Direction comes from the frozen stimulus shape, never from the relation.
  //
  // GCM artifact-transform state is decrypt-side.
  // RSA/EC serialization is more specific: artifact-transform is NOT enough
  // because those families contain both material-side and artifact-side
  // stimuli. Only a mutated fixture that actually carries `artifact` is an
  // import-side serialization observation.
  const gcmArtifactDecrypt =
    operation === 'gcm' && mechanism === 'artifact-transform';

  const serializationArtifactImport =
    (operation === 'rsa-ser' || operation === 'ec-ser')
    && serializationArtifactInput === true;

  const rsaMaterialExport =
    operation === 'rsa-ser'
    && mechanism === 'artifact-transform'
    && serializationArtifactInput === false;

  const ecMaterialExport =
    operation === 'ec-ser'
    && mechanism === 'artifact-transform'
    && serializationArtifactInput === false;

  const role =
    oaepKeyRoleDirection !== undefined
      ? oaepKeyRoleDirection
      : gcmArtifactDecrypt || serializationArtifactImport || pssArtifactVerify === true
        ? consumerRole(operation)
        : primaryRole(operation);

  const fixtureRealization: FixtureRealization | undefined =
    oaepKeyRoleDirection !== undefined
      ? 'oaep-key-role-request'
      : pssKeyRoleRequest === true
        ? 'pss-key-role-request'
        : pssArtifactVerify === true
          ? 'pss-artifact-verify'
          : gcmArtifactDecrypt
          ? 'gcm-artifact-decrypt'
          : serializationArtifactImport
            ? 'serialization-artifact-import'
            : rsaMaterialExport
              ? 'rsa-material-export'
              : ecMaterialExport
                ? 'ec-material-export'
                : undefined;

  if (scope.kind === 'cross-backend-set') {
    if (scope.backends.length !== 2) {
      throw new BindingError(
        `A cross-backend-set scope must name exactly two backends; got ${scope.backends.length}.`,
      );
    }
    return {
      kind: 'backend-set',
      backends: scope.backends,
      role,
      dispatch: scope.backends.map((b) => materializeDispatch(operation, b, role)),
      ...(material === undefined ? {} : { material }),
      ...(fixtureRealization === undefined ? {} : { fixtureRealization }),
    };
  }

  if (scope.kind === 'manifest') {
    // No role, no dispatch: a declaration is not a call.
    return {
      kind: 'manifest',
      backend: scope.backend,
      ...(material === undefined ? {} : { material }),
    };
  }

  if (scope.kind === 'single-backend') {
    return {
      kind: 'single-backend',
      backend: scope.backend,
      role,
      dispatch: materializeDispatch(operation, scope.backend, role),
      ...(material === undefined ? {} : { material }),
      ...(fixtureRealization === undefined ? {} : { fixtureRealization }),
    };
  }

  throw new BindingError(`Relation ${relation} cannot be bound from a '${scope.kind}' scope.`);
}

/**
 * Walks the whole structural plan and binds every NORMATIVE OBLIGATION.
 *
 * The selection is the predicate itself, called per observation. Nothing is
 * filtered by name, by state literal or by a precomputed set, and the returned
 * count is whatever the walk produces.
 */
export function bindRequiredObligations(
  plan: StructuralExecutionPlan, pool: FrozenMaterialPool,
): readonly BoundObligation[] {
  const out: BoundObligation[] = [];
  for (const c of plan.classes) {
    const entry = MUTATION_REGISTRY.find((e) => e.mutationId === c.mutationId);
    if (entry === undefined) throw new BindingError(`Plan class '${c.mutationId}' is not in the frozen registry.`);
    for (const si of c.stimulusInstances) {
      const barriers = new Set(structurallyNonComparableRelations(c.mutationId, si.stimulusInstanceId).keys());

      // Serialization direction is frozen before execution from the exact
      // stimulus shape after applying its registered mutation. This is the
      // same distinction class-wiring already makes: a fixture containing an
      // artifact is consumer/import-side; a material fixture is producer/
      // export-side. No backend result participates in this decision.
      let serializationArtifactInput: boolean | undefined;
      if (entry.operation === 'rsa-ser' || entry.operation === 'ec-ser') {
        const baseFixture = getFixtureResolver(
          c.mutationId,
          si.stimulusInstanceId,
        )(c.mutationId, si.stimulusInstanceId, pool);

        const mutated = (getMutationImplementation(c.mutationId) as {
          mutate: (fixture: unknown, stimulusInstanceId: string) => unknown;
        }).mutate(baseFixture, si.stimulusInstanceId);

        serializationArtifactInput =
          mutated !== null
          && typeof mutated === 'object'
          && (mutated as { artifact?: unknown }).artifact instanceof Uint8Array;
      }

      const oaepKeyRoleDirection: 'encrypt' | 'decrypt' | undefined =
        c.mutationId === 'OAEP-KEY-ROLE-BYPASS'
          ? si.stimulusInstanceId === 'encrypt-with-private'
            ? 'encrypt'
            : si.stimulusInstanceId === 'decrypt-with-public'
              ? 'decrypt'
              : undefined
          : undefined;

      const pssKeyRoleRequest =
        c.mutationId === 'PSS-KEY-ROLE-BYPASS'
        && si.stimulusInstanceId === 'default';

      const pssArtifactVerify =
        entry.operation === 'pss'
        && entry.mechanism === 'artifact-transform';

      for (const x of si.executability) {
        const planned: PlannedObservation = { relation: x.relation, scope: x.scope, executability: x.state };
        if (!isRequiredEvidence(planned, si.interopEligibility, barriers)) continue;
        out.push({
          mutationId: c.mutationId,
          stimulusInstanceId: si.stimulusInstanceId,
          operation: entry.operation,
          relation: x.relation,
          scope: x.scope,
          binding: bindObservation({
            operation: entry.operation,
            relation: x.relation,
            scope: x.scope,
            pool,
            mechanism: entry.mechanism,
            ...(serializationArtifactInput === undefined
              ? {}
              : { serializationArtifactInput }),
            ...(x.relation === 'R_interop' || oaepKeyRoleDirection === undefined
              ? {}
              : { oaepKeyRoleDirection }),
            ...(x.relation === 'R_interop' || !pssKeyRoleRequest
              ? {}
              : { pssKeyRoleRequest: true }),
            ...(x.relation === 'R_interop' || !pssArtifactVerify
              ? {}
              : { pssArtifactVerify: true }),
          }),
        });
      }
    }
  }
  return out;
}

/** Obligations whose resolver M3.7.2 completes. */
export function nonInteropObligations(all: readonly BoundObligation[]): readonly BoundObligation[] {
  return all.filter((o) => o.binding.kind !== 'directed-transfer');
}

/**
 * Obligations bound but deliberately NOT resolvable until M3.7.3.
 *
 * Kept as its own query rather than folded into a total, so no count can
 * present a bound-but-unresolved obligation as an executable one -- which is
 * the ambiguity D13 was.
 */
export function directedTransferObligations(all: readonly BoundObligation[]): readonly BoundObligation[] {
  return all.filter((o) => o.binding.kind === 'directed-transfer');
}
