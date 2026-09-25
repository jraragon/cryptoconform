// M3.8.2 -- the scored execution driver.
//
// The morphism M4.0 found missing:
//
//     FrozenPolicy  ->  ExecutableScoredRun
//
// M3.7.4 decided how a scored run executes and M3.7.5 how it attests. Both
// were verified as primitives and neither was ever composed into something M4
// could invoke: every path through them ran from a test that assembled the
// plan by hand. That is why the readiness gate failed, and it is the same
// architectural shape as D11 -- components implemented, composition absent.
//
// --- What this driver is -------------------------------------------------
//
//     scoredOrder -> blockOf -> isRequiredEvidence -> bindRequiredObligations
//       -> realizeAdapter -> makeResolve -> runPhaseC -> BlockCommit
//       -> assessCompletion -> assertRunComplete -> attestScoredRun
//
// A COORDINATOR and nothing else. It contains no cryptography and no
// operation-specific logic: no branch on hkdf, gcm, oaep, pss or either
// serialization operation appears in it, and a gate greps for exactly that.
// Every question it could have answered -- which provider, which pair, which
// material, which role, which order -- was answered by a frozen component
// before this file existed.
//
// --- Validation mode -----------------------------------------------------
//
// The driver runs in one of two modes, and the difference is ONLY whether an
// attestation is issued. Validation drives the identical path, so what M3.8.3
// exercises is the same code used for scored acquisition, preserving
// consistency between validation and evidence generation.
//
//     'scored'      issues an attestation; the artifact is M4 evidence
//     'validation'  issues none; assertIsScoredArtifact refuses the result
//
// There is no third mode and no flag that alters ordering, selection, retries
// or completion. D14 forbids adaptive inspection, and a mode that changed any
// of those would be exactly that.

import type { OperationId } from '../schema/capability.js';
import type { RelationId } from '../schema/registry-types.js';
import { scopeEquals } from '../evidence/observation-scope.js';
import { MUTATION_REGISTRY } from '../registry/mutations.js';
import { APPLICABILITY_MATRIX } from '../applicability/matrix.js';
import { assembleStructuralPlan, type StructuralExecutionPlan } from '../phase-c/plan-assembly.js';
import type { FrozenMaterialPool } from '../phase-c/material/pool.js';
import { getFixtureResolver } from '../phase-c/fixture-index.js';
import {
  bindRequiredObligations, type BoundObligation, type ExecutionBinding,
} from '../phase-c/execution-binding.js';
import { makeResolve } from '../phase-c/resolve-glue.js';
import { ecSerializationRole } from '../phase-c/fixtures/ec-ser-artifact.js';
import { rsaSerializationRole } from '../phase-c/fixtures/rsa-ser-artifact.js';
import { gcmConsumedArtifactId } from '../phase-c/fixtures/gcm-artifact.js';
import { realizeAdapter, serializationFixture } from './serialization-adapter.js';
import { capabilityProbeInput } from './capability-probe-input.js';
import { materializeDispatch } from './dispatch-materialization.js';
import { resolveClaims } from '../capability/capability-acquisition.js';
import { ROLES_BY_OPERATION } from './dispatch.js';

/** The operation's own primary role, used only to PROBE. */
function primaryRoleOf(operation: OperationId) {
  const roles = ROLES_BY_OPERATION[operation];
  if (roles === undefined || roles.length === 0) throw new ScoredDriverError(`No role for '${operation}'.`);
  return roles[0]!;
}
import { runPhaseC, type ExecutionPlan, type PhaseCRunResult } from './phase-c-orchestrator.js';
import {
  assertCommitConsistent, assertRunComplete, assessCompletion, blockOf, digestOf, scoredOrder,
  SCORED_EXECUTION_POLICY_VERSION, type BlockCommit, type OrderableObligation, type ScoredRunIdentity,
} from './scored-execution-policy.js';
import { attestScoredRun, type ScoredAttestation } from './scored-attestation.js';

export class ScoredDriverError extends Error {}

export type DriverMode = 'scored' | 'validation';

export interface ScoredRunResult {
  readonly mode: DriverMode;
  readonly blocks: readonly {
    readonly blockId: string;
    readonly operation: OperationId;
    readonly obligations: number;
    readonly classes: number;
    readonly result: PhaseCRunResult;
    readonly commit: BlockCommit;
  }[];
  readonly requiredKeys: readonly string[];
  readonly committedKeys: readonly string[];
  /** Present only in 'scored' mode. */
  readonly attestation?: ScoredAttestation;
  /** Which obligations were routed through the serialization adapter. */
  readonly serializationRouted: readonly string[];
}

const keyOf = (o: BoundObligation): string =>
  `${o.mutationId}|${o.stimulusInstanceId}|${o.relation}|${JSON.stringify(o.scope)}`;

const orderableOf = (o: BoundObligation): OrderableObligation => ({
  operation: o.operation, mutationId: o.mutationId, stimulusInstanceId: o.stimulusInstanceId,
  relation: o.relation, scopeKey: JSON.stringify(o.scope),
});

/**
 * The artifact role for a serialization obligation, PROPAGATED from the frozen
 * resolver's own selection. The driver does not compute it; it asks the module
 * that already decided.
 */
function artifactRoleFor(o: BoundObligation, pool: FrozenMaterialPool): 'public' | 'private' | undefined {
  if (o.operation === 'rsa-ser') {
    const entry = MUTATION_REGISTRY.find((e) => e.mutationId === o.mutationId);
    return entry?.mechanism === 'artifact-transform'
      ? rsaSerializationRole(o.mutationId, o.stimulusInstanceId, pool)
      : undefined;
  }
  if (o.operation === 'ec-ser') {
    const entry = MUTATION_REGISTRY.find((e) => e.mutationId === o.mutationId);
    return entry?.mechanism === 'artifact-transform'
      ? ecSerializationRole(o.mutationId, o.stimulusInstanceId, pool)
      : undefined;
  }
  return undefined;
}

/**
 * Propagates the artifact identity already selected by the frozen GCM fixture
 * resolver. This is metadata propagation only: no new selection is made here.
 */
function consumedArtifactIdFor(o: BoundObligation, pool: FrozenMaterialPool): string | undefined {
  if (o.operation !== 'gcm') return undefined;

  const entry = MUTATION_REGISTRY.find((e) => e.mutationId === o.mutationId);
  if (entry?.mechanism !== 'artifact-transform') return undefined;

  return gcmConsumedArtifactId(o.mutationId, pool);
}

/* eslint-disable @typescript-eslint/no-explicit-any */

/** The adapters one obligation needs, realized from its own binding. */
function adaptersFor(o: BoundObligation, pool: FrozenMaterialPool): {
  readonly adapter: any; readonly counterpart?: any; readonly transfer?: any;
  readonly capability?: any;
  readonly routedThroughSerializationAdapter: boolean;
} {
  const b: ExecutionBinding = o.binding;
  const artifactRole = artifactRoleFor(o, pool);
  const isSer = (o.operation === 'rsa-ser' || o.operation === 'ec-ser') && b.kind !== 'manifest';
  const fixtureRealization =
    'fixtureRealization' in b ? b.fixtureRealization : undefined;

  const realize = (d: { entry: { shape: string } }) => realizeAdapter({
    dispatch: d as never,
    ...(b.material === undefined ? {} : { material: b.material }),
    ...(artifactRole === undefined ? {} : { artifactRole }),
    ...(fixtureRealization === undefined ? {} : { fixtureRealization }),
  });

  if (b.kind === 'single-backend') {
    return { adapter: realize(b.dispatch), routedThroughSerializationAdapter: isSer };
  }
  if (b.kind === 'manifest') {
    // A manifest observation has no cryptographic role, so it gets no adapter
    // from one. What it does need is the frozen claim it contrasts and a probe
    // adapter for the scored side -- the probe's role is the operation's own
    // primary role, used to PROBE the backend, never to give the manifest
    // scope an execution role it does not have.
    const claims = resolveClaims(o.operation, b.backend);
    const claim = claims.find((c) => c.capabilityId === `${o.operation}.provider.support`) ?? claims[0];
    if (claim === undefined) {
      throw new ScoredDriverError(`${o.mutationId}: no frozen capability claim for ${o.operation}/${b.backend.family}.`);
    }
    const probeAdapter = realizeAdapter({
      dispatch: materializeDispatch(o.operation, b.backend, primaryRoleOf(o.operation)) as never,
      ...(b.material === undefined ? {} : { material: b.material }),
      ...(artifactRoleFor(o, pool) === undefined ? {} : { artifactRole: artifactRoleFor(o, pool)! }),
    });
    const probeInput = capabilityProbeInput({
      operation: o.operation,
      pool,
      ...(b.material === undefined ? {} : { material: b.material }),
    });
    return {
      adapter: probeAdapter,
      capability: {
        claim,
        declarationEvidenceIds: [`manifest:${claim.cell.basisKind}:${claim.capabilityId}`],
        probeAdapter,
        probeInput,
      },
      routedThroughSerializationAdapter: false,
    };
  }
  if (b.kind === 'backend-set') {
    const [left, right] = b.dispatch;
    if (left === undefined || right === undefined) {
      throw new ScoredDriverError(`${o.mutationId}: a backend-set binding must materialize two dispatch entries.`);
    }
    return { adapter: realize(left), counterpart: realize(right), routedThroughSerializationAdapter: isSer };
  }
  const consumesArtifactId = consumedArtifactIdFor(o, pool);
  if (o.operation === 'rsa-ser') {
    if (artifactRole === undefined) {
      throw new ScoredDriverError(
        `${o.mutationId}: RSA-ser R_interop has no frozen serialization role.`,
      );
    }

    const realizeTransferEnd = (
      d: { entry: { shape: string } },
      endRealization: 'rsa-material-export' | 'serialization-artifact-import',
    ) => realizeAdapter({
      dispatch: d as never,
      ...(b.material === undefined ? {} : { material: b.material }),
      artifactRole,
      fixtureRealization: endRealization,
    });

    const producerAdapter =
      realizeTransferEnd(b.producer, 'rsa-material-export');
    const consumerAdapter =
      realizeTransferEnd(b.consumer, 'serialization-artifact-import');

    return {
      adapter: producerAdapter,
      transfer: {
        operation: o.operation, from: b.from, to: b.to,
        producerAdapter, consumerAdapter,
        serializationRole: artifactRole,
        ...(b.material === undefined ? {} : { material: b.material }),
        ...(consumesArtifactId === undefined ? {} : { consumesArtifactId }),
      },
      routedThroughSerializationAdapter: true,
    };
  }

  if (o.operation === 'ec-ser') {
    if (artifactRole === undefined) {
      throw new ScoredDriverError(
        `${o.mutationId}: EC-ser R_interop has no frozen serialization role.`,
      );
    }

    // EC R_interop is artifact-side at this point. resolve-glue builds the
    // producer input from nominal frozen material via producerInputFor(),
    // already in the serialization wiring's {role,xHex,yHex[,dHex]} shape.
    // Therefore the producer must use the normal export adapter; applying
    // ec-material-export here would incorrectly reinterpret that realized
    // input as a mutated {role,q:{x,y},d} fixture.
    const producerAdapter = realizeAdapter({
      dispatch: b.producer as never,
      ...(b.material === undefined ? {} : { material: b.material }),
      artifactRole,
      fixtureRealization: 'ec-material-export',
    });

    const consumerAdapter = realizeAdapter({
      dispatch: b.consumer as never,
      ...(b.material === undefined ? {} : { material: b.material }),
      artifactRole,
      fixtureRealization: 'serialization-artifact-import',
    });

    return {
      adapter: producerAdapter,
      transfer: {
        operation: o.operation, from: b.from, to: b.to,
        producerAdapter, consumerAdapter,
        serializationRole: artifactRole,
        ...(b.material === undefined ? {} : { material: b.material }),
        ...(consumesArtifactId === undefined ? {} : { consumesArtifactId }),
      },
      routedThroughSerializationAdapter: true,
    };
  }

  return {
    adapter: realize(b.producer),
    transfer: {
      operation: o.operation, from: b.from, to: b.to,
      producerAdapter: realize(b.producer), consumerAdapter: realize(b.consumer),
      ...(b.material === undefined ? {} : { material: b.material }),
      ...(consumesArtifactId === undefined ? {} : { consumesArtifactId }),
    },
    routedThroughSerializationAdapter: isSer,
  };
}

/**
 * Builds one block's ExecutionPlan from the STRUCTURAL plan.
 *
 * The plan is not pruned to the obligations: Planned = Applicability, and an
 * applicable relation keeps its planned scope even where it carries no
 * obligation. Pruning it is what M3.7.6's own first draft did, and the
 * aggregator refused -- correctly.
 */
function buildBlockPlan(
  operation: OperationId, structural: StructuralExecutionPlan, obligations: readonly BoundObligation[],
  pool: FrozenMaterialPool,
): ExecutionPlan {
  const classIds = new Set(obligations.map((o) => o.mutationId));
  const classes = structural.classes.filter((c) => classIds.has(c.mutationId)).map((c) => {
    if (!MUTATION_REGISTRY.some((e) => e.mutationId === c.mutationId)) {
      throw new ScoredDriverError(`Plan class '${c.mutationId}' is not in the frozen registry.`);
    }
    return {
      // The structural plan already carries the frozen implementation.
      mutation: c.mutation,
      operation,
      gamma0Ref: c.gamma0Ref,
      registryEntryHash: c.registryEntryHash,
      applicability: APPLICABILITY_MATRIX[operation],
      expectedSpectrum: c.expectedSpectrum,
      stimulusInstances: c.stimulusInstances.map((si) => ({
        stimulusInstanceId: si.stimulusInstanceId,
        baseFixture: getFixtureResolver(c.mutationId, si.stimulusInstanceId)(c.mutationId, si.stimulusInstanceId, pool),
        ...(si.interopEligibility === undefined ? {} : { interopEligibility: si.interopEligibility }),
        executability: si.executability.map((x) => ({ relation: x.relation, scope: x.scope, state: x.state })),
      })),
      entries: c.stimulusInstances[0]!.executability.map((x) => ({
        relation: x.relation as RelationId,
        scope: x.scope,
        resolve: async (ctx: any) => {
          const own = obligations.find(
            (o) =>
              o.mutationId === c.mutationId
              && o.stimulusInstanceId === ctx.stimulusInstanceId
              && o.relation === x.relation
              && scopeEquals(o.scope, x.scope),
          );

          if (own === undefined) {
            // Planned-but-non-required entries are skipped by runPhaseC before
            // resolve(). Reaching this point without the exact obligation is
            // therefore an inconsistent production-plan binding.
            throw new ScoredDriverError(
              `${c.mutationId}::${ctx.stimulusInstanceId}: no exact bound obligation for `
              + `${x.relation} / ${JSON.stringify(x.scope)}.`,
            );
          }

          const deps = adaptersFor(own, pool);

          return makeResolve(
            x.relation as RelationId,
            x.scope,
            deps as never,
          )(ctx);
        },
      })),
    };
  });
  return { classes } as unknown as ExecutionPlan;
}

/* eslint-enable @typescript-eslint/no-explicit-any */

/**
 * The entry point M4 invokes.
 *
 * Walks the six frozen blocks in policy order, commits each whole, then
 * asserts completion over the required population and -- in scored mode only
 * -- attests the result. Nothing here inspects a result to decide anything.
 */
export async function runScoredExecution(params: {
  readonly mode: DriverMode;
  readonly pool: FrozenMaterialPool;
  readonly runId: string;
  readonly instrumentCommit: string;
  readonly environmentDigest: string;
  /** Restricts the run to these blocks. Validation only; scored runs take all six. */
  readonly onlyOperations?: readonly OperationId[];
}): Promise<ScoredRunResult> {
  const structural = assembleStructuralPlan(params.pool);
  const required = bindRequiredObligations(structural, params.pool);

  // The order is the policy's, computed once from normative identities.
  const ordered = scoredOrder(required.map(orderableOf));
  const blockOrder: OperationId[] = [];
  for (const o of ordered) if (!blockOrder.includes(o.operation)) blockOrder.push(o.operation);
  const selected = params.onlyOperations === undefined
    ? blockOrder
    : blockOrder.filter((op) => params.onlyOperations!.includes(op));
  if (params.mode === 'scored' && params.onlyOperations !== undefined) {
    throw new ScoredDriverError(
      'A scored run executes the whole required population. Restricting it to some blocks would be a selection, ' +
      'which D14 forbids.',
    );
  }

  const blocks: ScoredRunResult['blocks'][number][] = [];
  const committedKeys: string[] = [];
  const serializationRouted: string[] = [];
  const commits: BlockCommit[] = [];

  for (const operation of selected) {
    const mine = required.filter((o) => o.operation === operation);
    for (const o of mine) {
      if (adaptersFor(o, params.pool).routedThroughSerializationAdapter) serializationRouted.push(keyOf(o));
    }
    const result = await runPhaseC(buildBlockPlan(operation, structural, mine, params.pool));
    const commit: BlockCommit = {
      blockId: blockOf(operation),
      runId: params.runId,
      policyVersion: SCORED_EXECUTION_POLICY_VERSION,
      obligationCount: mine.length,
      digest: digestOf(JSON.stringify(result.scientificResults.map((r) => r.mutationId).sort())),
      attempt: 1,
    };
    commits.push(commit);
    assertCommitConsistent(commits);
    for (const o of mine) committedKeys.push(keyOf(o));
    blocks.push({
      blockId: commit.blockId, operation, obligations: mine.length,
      classes: new Set(mine.map((o) => o.mutationId)).size, result, commit,
    });
  }

  const requiredKeys = (params.onlyOperations === undefined ? required
    : required.filter((o) => selected.includes(o.operation))).map(keyOf);
  assertRunComplete(assessCompletion(requiredKeys, committedKeys));

  if (params.mode === 'validation') {
    return { mode: params.mode, blocks, requiredKeys, committedKeys, serializationRouted };
  }

  const identity: ScoredRunIdentity = {
    runId: params.runId,
    policyVersion: SCORED_EXECUTION_POLICY_VERSION,
    instrumentCommit: params.instrumentCommit,
    plannedObligations: structural.classes
      .flatMap((c) => c.stimulusInstances).flatMap((si) => si.executability).length,
    requiredObligations: required.length,
    environmentDigest: params.environmentDigest,
  };
  const attestation = attestScoredRun({
    identity,
    serializedContent: JSON.stringify(blocks.map((b) => b.commit)),
  });
  return { mode: params.mode, blocks, requiredKeys, committedKeys, serializationRouted, attestation };
}
