// Bloque D / M3.5.2 -- populating PlanEntry.resolve().
//
// The last cable. Everything it needs already exists and is frozen: dispatch,
// the projection layer, the wired evaluators, the ground-truth table. What was
// missing is the callback that lets runPhaseC drive them, so that the runner
// M4 will actually use has itself conducted the instrument end to end.
//
//     All components work together  !=  PhaseCOrchestrator drives them together
//
// The bound applies in one direction only:
//
//     resolve = ORCHESTRATION GLUE      resolve != SCIENTIFIC POLICY
//
// It may obtain executions, use the frozen dispatch, bind a factory, wrap a
// serialization call, build a projector's input and call evaluateRelation. It
// may NOT decide an expectation, reinterpret a clause, recompute normative
// eligibility, change Required, or invent a result where evidence is absent.
// The expectation is READ from the pre-registered ground-truth table by key;
// there is no code path here that could derive one, and the gate greps for
// contract imports.

import { makeRelationObservation, type RelationObservation } from '../evidence/relation-observation.js';
import type { ExecutionAdapter } from '../orchestration/engine.js';
import type { PlanEntryContext } from '../orchestration/phase-c-orchestrator.js';
import type { PlannedObservation } from '../evidence/mutation-instance-result.js';
import { evaluateRelation } from './relation-wiring.js';
import { resolveGroundTruth } from './ground-truth/resolve.js';
import { assembleConsumerInput } from './consumer-input.js';
import { contrastClaim, type ResolvedClaim } from '../capability/capability-acquisition.js';
import { isArtifactBearing } from './producer-stimulus-identity.js';
import { mutateFreshArtifact, producerInputFor, realizeConsumerMaterial } from './artifact-side-producer.js';
import { realizeMutatedRsaSerMaterial, realizeRsaSerMaterial } from './wiring-realization.js';
import type { BoundMaterial } from './execution-binding.js';
import { runTransfer } from '../orchestration/interop-transfer.js';
import type { BackendIdentity } from '../schema/backend-identity.js';
import type { OperationId } from '../schema/capability.js';
import { observeSerialization } from './serialization-observer.js';
import { materializeDispatch } from '../orchestration/dispatch-materialization.js';

export class ResolveGlueError extends Error {}

export interface ResolveDeps<TFixture, TNativeRecord> {
  /** The adapter this relation's evidence comes from, already dispatched. */
  readonly adapter: ExecutionAdapter<TFixture, TNativeRecord>;
  /** A second, independent adapter, for the relations that need two. */
  readonly counterpart?: ExecutionAdapter<TFixture, TNativeRecord>;
  /**
   * The directed-transfer binding, for R_interop only. Its presence is what
   * makes the relation resolvable; its ABSENCE is what the old refusal
   * protected. Direction and roles are carried, never inferred.
   */
  /**
   * R_cap's own inputs. The claim and its declaration evidence come from the
   * frozen manifest; the probe adapter produces the scored side.
   */
  readonly capability?: {
    readonly claim: ResolvedClaim;
    readonly declarationEvidenceIds: readonly string[];
    readonly probeAdapter: ExecutionAdapter<TFixture, TNativeRecord>;
    readonly probeInput: TFixture;
  };
  readonly transfer?: {
    readonly operation: OperationId;
    readonly from: BackendIdentity;
    readonly to: BackendIdentity;
    readonly producerAdapter: ExecutionAdapter<TFixture, TNativeRecord>;
    readonly consumerAdapter: ExecutionAdapter<TFixture, TNativeRecord>;
    /** Frozen producer material, for artifact-side obligations. */
    readonly material?: BoundMaterial;
    /** Which frozen artifact record the class consumes, for D17. */
    readonly consumesArtifactId?: string;
    /** Frozen/pre-experimental serialization role propagated by the binding. */
    readonly serializationRole?: 'public' | 'private';
  };
}

/**
 * Builds a resolve() for one (relation, scope) entry.
 *
 * Deliberately per RELATION, because which executions an observation needs is
 * a property of the relation and nothing else -- the same dispatch rule
 * Bloque C3 established for projectors and evaluators. There is no mutationId
 * branching here, and no way to introduce one: the mutation arrives already
 * selected in the context.
 */
export function makeResolve<TFixture, TNativeRecord>(
  relation: PlannedObservation['relation'],
  scope: PlannedObservation['scope'],
  deps: ResolveDeps<TFixture, TNativeRecord>,
): (ctx: PlanEntryContext<TFixture, TNativeRecord>) => Promise<RelationObservation> {
  return async (ctx) => {
    // The expectation is READ, never derived. A missing row is a refusal:
    // an unstated normative premise is not an empty one.
    const gt = resolveGroundTruth(ctx.mutationId, ctx.stimulusInstanceId).row;

    const observationContext = {
      kind: 'mutation' as const, phase: 'C' as const,
      mutationId: ctx.mutationId, stimulusInstanceId: ctx.stimulusInstanceId,
    };
    const participants: string[] = [];
    let declarationBasisRef: string | undefined;
    let state;

    switch (relation) {
      case 'R_byte': {
        // Phase C's R_byte is CROSS-PROVIDER (M3-H8): the mutation is the
        // common stimulus both sides receive, never one side of the pair.
        if (deps.counterpart === undefined) {
          throw new ResolveGlueError('R_byte needs a second backend; a same-backend pair is Phase A\'s own scope.');
        }
        const left = await ctx.runMutation(deps.adapter);
        const right = await ctx.runMutation(deps.counterpart);
        participants.push(left.executionId, right.executionId);
        state = evaluateRelation('R_byte', { left, right, outputKind: 'raw-output' });
        break;
      }
      case 'R_val': {
        if (gt.expectedValidation === undefined) {
          throw new ResolveGlueError(`${ctx.mutationId}: R_val is planned but no expected decision is pre-registered.`);
        }
        const execution = await ctx.runMutation(deps.adapter);
        participants.push(execution.executionId);
        state = evaluateRelation('R_val', {
          expected: gt.expectedValidation.decision, execution,
          observed: execution.outcome.kind === 'accept' ? { kind: 'accept' } : { kind: 'reject' },
        });
        break;
      }
      case 'R_err': {
        const execution = await ctx.runMutation(deps.adapter);
        participants.push(execution.executionId);
        const expected = gt.errorExpectation?.kind === 'error-expected' ? gt.errorExpectation.errorClass : undefined;
        state = evaluateRelation('R_err', {
          execution,
          rejectionOccurred: execution.outcome.kind === 'reject',
          ...(expected === undefined ? {} : { expectedErrorClass: expected }),
          // From the SDK layer only, never from nativeObservation.
          ...(execution.outcome.detail === undefined ? {} : { observedErrorClass: execution.outcome.detail }),
        });
        break;
      }
      case 'R_ser': {
        if (gt.checksRequired === undefined) {
          throw new ResolveGlueError(`${ctx.mutationId}: R_ser is planned but no basis is pre-registered.`);
        }

        const execution = await ctx.runMutation(deps.adapter);
        participants.push(execution.executionId);

        // Reconstruct the same deterministic intervention for observation.
        // This does not execute a backend and does not decide policy; it only
        // exposes the actual artifact/request bytes whose execution was just
        // recorded by runMutation().
        const mutatedFixture = ctx.mutation.mutate(ctx.baseFixture, ctx.stimulusInstanceId);

        const operation = deps.adapter.operation;
        if (operation !== 'gcm' && operation !== 'rsa-ser' && operation !== 'ec-ser') {
          throw new ResolveGlueError(
            `${ctx.mutationId}: R_ser reached non-serialization operation '${operation}'.`,
          );
        }

        const observed = await observeSerialization({
          operation,
          direction: execution.subject.direction,
          baseFixture: ctx.baseFixture,
          mutatedFixture,
          ...(execution.output?.bytes === undefined ? {} : { outputHex: execution.output.bytes }),
          ...(operation !== 'gcm' || execution.subject.direction !== 'encrypt' ? {} : {
            runGcmDecrypt: async (input) => {
              // Material preservation for a produced GCM artifact is observed
              // by consuming that exact artifact on the SAME backend and
              // checking recovery of the mutated request's plaintext.
              // The auxiliary execution is evidence, not R_interop policy.
              const dispatch = materializeDispatch('gcm', deps.adapter.backend, 'decrypt');
              if (dispatch.entry.shape !== 'execution-adapter') {
                throw new ResolveGlueError(
                  `${ctx.mutationId}: GCM decrypt did not materialize as an execution adapter.`,
                );
              }
              const aux = await (ctx.runOnInput as any)(
                dispatch.wiring as any,
                input,
                'r-ser-gcm-material-preservation',
              );
              return aux;
            },
          }),
        });

        if (observed.auxiliaryExecutionId !== undefined) {
          participants.push(observed.auxiliaryExecutionId);
        }

        state = evaluateRelation('R_ser', {
          basis: gt.checksRequired.basis,
          execution,
          ...(observed.repOK === undefined ? {} : { repOK: observed.repOK }),
          ...(observed.materialOK === undefined ? {} : { materialOK: observed.materialOK }),
        });
        break;
      }
      case 'R_cap': {
        // M3.9-B wired. The two sides come from DIFFERENT places, which is the
        // whole point of the relation:
        //
        //   declared  READ from the frozen manifest cell. Never probed.
        //   scored    a fresh execution on this backend.
        //
        // The scored side's meaning is grounded in how the declarations
        // themselves were grounded: M2.3.3b-II's own bases are of the form
        // "v0.13 SS15, HKDF x WebCrypto closed" -- a provider is declared to
        // support an operation because an execution of it closed. The
        // symmetric M4 probe is therefore an execution of the same operation
        // on the same backend, and its observed state is whether that
        // execution completes. Nothing new is decided here: the scored side
        // reads the declaration's own evidentiary form forward.
        //
        // Independence holds over IDENTITY, which the freeze states is the
        // only sense that applies: the declaration rests on M1 evidence
        // recorded in v0.13, the probe on a fresh M4 ExecutionID. Sharing the
        // mechanism is explicitly not a violation.
        if (deps.capability === undefined) {
          throw new ResolveGlueError(
            `${ctx.mutationId}: R_cap needs its frozen manifest claim and a probe adapter. Refusing rather than ` +
            'observing a declaration against itself.',
          );
        }
        const { claim, declarationEvidenceIds, probeAdapter } = deps.capability;
        declarationBasisRef = declarationEvidenceIds[0];
        const scoredExecution = await ctx.runDeclarationProbe(
        probeAdapter,
        deps.capability.probeInput,
      );
        participants.push(scoredExecution.executionId);
        const observedState = scoredExecution.executionStatus === 'completed'
          && scoredExecution.outcome.kind !== 'reject' ? 'supported' : 'unsupported';
        const verdict = contrastClaim({
          claim,
          declarationEvidenceIds,
          scored: {
            executionId: scoredExecution.executionId,
            backend: claim.backend,
            observed: { kind: 'provider-support', state: observedState },
            probeKind: claim.probeKind,
          },
        });
        state = verdict === 'pass' ? 'conformant' : 'divergent';
        break;
      }
      case 'R_interop': {
        // M3.7.3 -- the direction is EXECUTED, never constructed. from, to
        // and both roles come from the M3.7.2 binding; nothing here is
        // recomputed from backend names, array order or heuristics.
        const t = deps.transfer;
        if (t === undefined) {
          throw new ResolveGlueError(
            'R_interop needs a directed-transfer binding supplying producer and consumer. Refusing rather than ' +
            'assembling an interoperability claim from one execution.',
          );
        }
        const record = await runTransfer({
          operation: t.operation,
          from: t.from,
          to: t.to,
          produce: async () => {
            // Two routes, chosen by the SHAPE of the stimulus, never by class.
            //
            // Request-side: the fixture IS the producer's input, so the
            // mutation runs on it and the producer's output is the artifact.
            //
            // Artifact-side: the fixture carries an artifact, which is not
            // enough for R_interop's directional claim. The producer executes
            // from NOMINAL FROZEN MATERIAL, and mutate(A_0, s) is applied to
            // what it actually produced -- by the same frozen intervention,
            // never a second implementation of it.
            const mutated = ctx.mutation.mutate(ctx.baseFixture, ctx.stimulusInstanceId);
            if (!isArtifactBearing(mutated)) {
              const execution = await ctx.runMutation(t.producerAdapter);
              const bytesHex = (execution.output as { bytes?: string } | undefined)?.bytes;
              if (bytesHex === undefined) {
                throw new ResolveGlueError(
                  `${ctx.mutationId}: the producer emitted no artifact, so nothing can be transferred.`,
                );
              }
              return { bytesHex, execution };
            }
            if (t.material === undefined) {
              throw new ResolveGlueError(
                `${ctx.mutationId}: an artifact-side obligation needs frozen producer material, and the binding ` +
                'supplied none. Refusing rather than taking the artifact from the fixture, whose producer is not ' +
                'scope.from.',
              );
            }
            const execution = await ctx.runOnInput(
              t.producerAdapter,
              producerInputFor({
                operation: t.operation, material: t.material,
                ...(t.consumesArtifactId === undefined ? {} : { consumesArtifactId: t.consumesArtifactId }),
                ...(t.serializationRole === undefined ? {} : { producerRole: t.serializationRole }),
              }) as never,
              'interop-produce',
            );
            const a0 = (execution.output as { bytes?: string } | undefined)?.bytes;
            if (a0 === undefined) {
              throw new ResolveGlueError(`${ctx.mutationId}: the producer emitted no A_0.`);
            }
            const transformed = mutateFreshArtifact({
              operation: t.operation, baseFixture: ctx.baseFixture, freshArtifactHex: a0,
              stimulusInstanceId: ctx.stimulusInstanceId,
              mutate: (f, s) => ctx.mutation.mutate(f as never, s),
            }) as Record<string, unknown>;
            const out = transformed['artifact'];
            const bytesHex = out instanceof Uint8Array ? Buffer.from(out).toString('hex') : String(out);
            return { bytesHex, execution };
          },
          consume: async (artifact) => {
            // The consumer input is ASSEMBLED explicitly, with per-field
            // provenance, and executed through the context so the evidence
            // reaches executions[] and the transfer stays reconstructible
            // from the bundle alone.
            const producerFixture =
              ctx.mutation.mutate(ctx.baseFixture, ctx.stimulusInstanceId);

            const rsaExpectedMaterial =
              t.operation === 'rsa-ser' && t.serializationRole !== undefined
                ? isArtifactBearing(producerFixture)
                  ? t.material === undefined
                    ? undefined
                    : realizeRsaSerMaterial(t.material, t.serializationRole)
                  : realizeMutatedRsaSerMaterial(producerFixture)
                : undefined;

            const assembled = assembleConsumerInput({
              operation: t.operation,
              producerFixture,
              artifactHex: artifact.bytesHex,
              // The SAME material the producer executed from. An artifact-side
              // fixture carries no key or role, and taking them from anywhere
              // else would be a second decision.
              ...(t.material === undefined ? {} : { boundMaterial: realizeConsumerMaterial(t.operation, t.material) }),
              ...(rsaExpectedMaterial === undefined ? {} : { expectedMaterial: rsaExpectedMaterial }),
            });
            return ctx.runOnInput(t.consumerAdapter, assembled.input as never, 'interop-consume');
          },
        });
        participants.push(record.producerExecution.executionId, record.consumerExecution.executionId);
        state = evaluateRelation('R_interop', {
          transfer: record,
          expectedOutcome: gt.expectedOutcome?.kind === 'reject'
            ? { kind: 'reject' }
            : { kind: 'normal' },
          observedOutcome: {
            kind: record.consumerExecution.outcome.kind === 'accept' ? 'accepted' : 'rejection',
            value: (record.consumerExecution.output as { bytes?: string } | undefined)?.bytes ?? null,
          },
        });
        break;
      }
      default:
        throw new ResolveGlueError(`No resolve glue for relation '${String(relation)}'.`);
    }

    return makeRelationObservation({
      applicable: true, relation, scope, context: observationContext,
      // I5': R_cap's declared side is identified, not executed.
      ...(declarationBasisRef === undefined ? {} : { declarationBasisRef }),
      status: state === 'conformant' ? 'pass' : state === 'divergent' ? 'fail' : 'insufficient-evidence',
      participants, evaluatorId: relation, basis: 'M3.5.2 orchestrator-driven resolution',
    });
  };
}
