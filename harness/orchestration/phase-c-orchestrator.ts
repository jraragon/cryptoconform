// M3.2.3 -- Phase C end-to-end orchestrator. Coordinates; introduces zero
// new scientific semantics (I4). Materializes evidence the plan says is
// needed, invokes the ALREADY-FROZEN evaluators the plan references, builds
// MutationInstanceResult/MutationResult via the ALREADY-FROZEN factories
// and aggregator -- never reimplements mutate(), applicability, evaluator
// logic, or aggregation itself.
//
// Contract (M3.2.2, CLOSED):
//   PhaseCOrchestrator: ExecutionPlan -> PhaseCRunResult
// Invariants:
//   I1: exactly one MutationInstanceResult per stimulusInstanceId
//   I2: every PlannedObservation resolves to exactly one structural state
//   I3: incomplete coverage => no MutationResult
//   I4: the orchestrator introduces no new scientific semantics
//   I5: R_cap => declarationExecutionId != scoredExecutionId, enforced here,
//       fail-closed, never merely trusted to the plan's own wiring.

import type { OperationId } from '../schema/capability.js';
import type { RelationApplicability } from '../schema/registry-types.js';
import type { ExecutionEvidence } from '../evidence/execution-evidence.js';
import type { RelationObservation } from '../evidence/relation-observation.js';
import type { MutationInstanceResult, PlannedObservation, InstanceInteropEligibility } from '../evidence/mutation-instance-result.js';
import { makeMutationInstanceResult } from '../evidence/mutation-instance-result.js';
import type { MutationResult } from '../evidence/mutation-result.js';
import type { OmittedClass } from '../evidence/class-omission.js';
import { makeMutationResult } from '../evidence/mutation-result.js';
import { aggregateMutationClass } from '../aggregation/aggregator.js';
import { structurallyNonComparableRelations } from '../phase-c/structural-comparability.js';
import {
  isFullyScoreable, makePhaseCScientificResult, toRelationSpectrum,
  type PhaseCScientificMutationResult,
} from '../evidence/phase-c-scientific-result.js';
import { canonicalEncode } from '../canonical/canonical-encode.js';
import { scopeEquals } from '../evidence/observation-scope.js';
import type { MutationImplementation } from '../mutations/framework.js';
import type { ExecutionAdapter } from './engine.js';
import { executeBaseline, executeMutation } from './engine.js';

// ---------------------------------------------------------------------
// ExecutionPlan
// ---------------------------------------------------------------------

// One planned relation/scope within one stimulus instance, carrying its
// OWN resolve() -- supplied by whoever wires this specific mutation class,
// never invented here. resolve() receives the materialization primitives
// (baseline-getter, mutation-executor) and returns the real
// RelationObservation for this exact (relation,scope) -- how to build the
// relation-specific evaluator input from real evidence is inherently
// relation/operation-specific knowledge the generic orchestrator must
// never contain (I4).
export interface PlanEntry<TFixture, TNativeRecord> {
  readonly relation: PlannedObservation['relation'];
  readonly scope: PlannedObservation['scope'];
  readonly resolve: (ctx: PlanEntryContext<TFixture, TNativeRecord>) => Promise<RelationObservation>;
}

// M3-H6 -- executability is per (class, stimulus, relation, scope), NOT per
// class. A PlanEntry carries only the STRUCTURAL part, which the original
// design correctly identified as class-invariant:
//     StructuralEntry(c) = (relation, scope, resolve)
//     Executability      = Exec(c, s, relation, scope)
//
// The evidence that forced the split: GCM-TAGLENGTH-PROFILE-BOUNDARY-BYPASS
// has three stimuli that are NOT equally executable, because Bouncy Castle
// admits an 80-bit tag (inside its declared range) but rejects lengths below
// the floor. Any single class-level value would be wrong -- 'required'
// everywhere would fabricate incompleteness for two stimuli, and
// 'structurally-not-executable' would discard genuinely executable evidence
// for the third.
//
// It is materialised as DATA at assembly time rather than computed by the
// runner, because the ExecutionPlan is pre-registered before M4:
//     M3 assembly -> Exec(c,s,e) materialised -> M4 runner only consumes
// A callback such as `executability: (stimulusInstanceId) => ...` would be
// more compact but would keep executability as LOGIC, letting the runner
// decide during execution what should have been executed. Deterministic or
// not, that turns a protocol decision into a runner decision.
export interface EntryExecutability {
  readonly relation: PlannedObservation['relation'];
  readonly scope: PlannedObservation['scope'];
  readonly state: PlannedObservation['executability'];
}

export interface PlanEntryContext<TFixture, TNativeRecord> {
  readonly mutationId: string;
  readonly stimulusInstanceId: string;
  readonly baseFixture: TFixture;
  readonly mutation: MutationImplementation<TFixture>;
  // Resolves (and caches, per NeedBaseline(i,p) <=> p.relation='R_byte')
  // the unmutated baseline execution for a given adapter -- never called
  // by the orchestrator itself for entries that do not need it.
  readonly getBaseline: (adapter: ExecutionAdapter<TFixture, TNativeRecord>) => Promise<ExecutionEvidence>;
  // Executes the mutation itself against a given adapter -- always a REAL
  // execution, never cached (unlike the baseline, a mutation's own
  // identity already varies per instance, so there is nothing to reuse).
  readonly runMutation: (adapter: ExecutionAdapter<TFixture, TNativeRecord>) => Promise<ExecutionEvidence>;
  // R_cap's own declaration-role evidence (E_declaration). DELIBERATELY a
  // separate primitive from getBaseline: the contract distinguishes
  //   R_byte: E_baseline + E_mutated
  //   R_cap:  E_declaration + E_scored,  id(E_decl) != id(E_score)
  // E_declaration is NOT a baseline, and must NOT come from the baseline
  // cache -- serving it from there would put a REUSED execution into
  // scored evidence, precisely the risk the R_byte-only cache policy
  // exists to prevent. This always performs a fresh, uncached execution.
  // Available to R_cap entries only; fail-closed for any other relation.
  readonly runDeclarationProbe: (
    adapter: ExecutionAdapter<TFixture, TNativeRecord>,
    input: TFixture,
  ) => Promise<ExecutionEvidence>;

  /**
   * M3.7.3 -- executes an adapter on an EXPLICIT input and registers the
   * evidence, exactly as the other three primitives do.
   *
   * Strictly additive: the three above are unchanged and keep their own
   * refusals. This one exists because R_interop's consumer must receive the
   * artifact the PRODUCER emitted, which is by definition not baseFixture,
   * and none of the other primitives can express that.
   *
   * It is deliberately relation-agnostic: it carries no policy about who may
   * call it, because the direction, the roles and the input are all decided
   * by the binding before this is reached. What it guarantees is the one
   * thing bypassing the context would lose -- the execution reaches
   * `executions[]`, so an observation can never reference an executionId the
   * bundle does not contain, and the transfer stays reconstructible from the
   * dataset alone.
   */
  readonly runOnInput: (
    adapter: ExecutionAdapter<TFixture, TNativeRecord>,
    input: TFixture,
    label: string,
  ) => Promise<ExecutionEvidence>;
}

export interface StimulusInstancePlan<TFixture> {
  readonly stimulusInstanceId: string;
  readonly baseFixture: TFixture;
  // M3-H9.3a-3.2.5c, connection 3 of 4. Carried by the plan, copied
  // verbatim into the MutationInstanceResult below. The runner has no
  // resolver, no registry import and no way to recompute it -- that is the
  // point: a run that could derive the decision could disagree with the
  // pre-registration, and the disagreement would be invisible.
  readonly interopEligibility?: InstanceInteropEligibility;
  // Exactly one decision per structural entry of the owning class:
  //     Keys(ExecMap_{c,s}) = Entries_c
  // neither fewer nor more. Verified fail-closed at run time.
  readonly executability: readonly EntryExecutability[];
}

export interface MutationClassPlan<TFixture, TNativeRecord> {
  readonly mutation: MutationImplementation<TFixture>;
  readonly operation: OperationId;
  readonly gamma0Ref: string;
  // Optional on the RUNNER's own view so a hand-built plan in a test is not
  // forced to invent a binding it has no registry entry for; the assembler
  // always supplies it, and the M3.3 gate asserts that.
  readonly registryEntryHash?: string;
  readonly applicability: RelationApplicability;
  readonly expectedSpectrum: MutationResult['expectedSpectrum'];
  readonly stimulusInstances: readonly StimulusInstancePlan<TFixture>[];
  // Same PlanEntry set applies to every stimulus instance of this class --
  // what varies per instance is the baseFixture/mutated evidence, never
  // the SET of planned (relation,scope) requirements themselves.
  readonly entries: readonly PlanEntry<TFixture, TNativeRecord>[];
}

// Deliberately type-erased at the top level (classes span different
// TFixture/TNativeRecord per operation) -- each MutationClassPlan stays
// internally type-safe; only the plan-level container needs to hold
// heterogeneous classes side by side, exactly as EvidenceBundle already
// holds type-erased ExecutionEvidence regardless of which operation
// produced it.
// eslint-disable-next-line @typescript-eslint/no-explicit-any
export interface ExecutionPlan {
  readonly classes: readonly MutationClassPlan<any, any>[];
}

export interface PhaseCRunResult {
  readonly executions: readonly ExecutionEvidence[];
  readonly observations: readonly RelationObservation[];
  readonly instances: readonly MutationInstanceResult[];
  readonly mutations: readonly MutationResult[];
  // M3-H7: classes for which no complete r(c) could be scored because some
  // applicable relation had zero executable support anywhere. Their
  // instances and observations ARE present above; only the class-level
  // scientific result is withheld. Recorded explicitly so a missing
  // MutationResult can never be mistaken for an oversight.
  // Every class, partial or not. `mutations` remains the M2-shaped subset
  // with a complete six-cell vector; this is the full record.
  readonly scientificResults: readonly PhaseCScientificMutationResult[];
  /**
   * Structured, and now genuinely rare: after Bloque A a relation's own
   * unscoreability is a NonScoreableCell, not a reason to omit the class.
   * What lands here is a class that produced nothing at all.
   */
  readonly omittedClasses: readonly OmittedClass[];
}

// ---------------------------------------------------------------------
// R_cap's own independence invariant (I5) -- enforced structurally on
// every resolved observation, never merely trusted to a PlanEntry's own
// resolve() implementation.
// ---------------------------------------------------------------------

export class CapabilityIndependenceViolationError extends Error {}

// ---------------------------------------------------------------------
// Baseline eligibility (M3.2.2's own policy), enforced STRUCTURALLY rather
// than merely documented:
//   NeedBaseline(i,p) <=> p.relation = 'R_byte'
// The cache's own safety argument rests entirely on this restriction:
// R_byte is applicable only to deterministic operations, so memoizing a
// baseline is indistinguishable from re-executing it. Any OTHER relation
// obtaining a cached baseline would silently break that argument -- a
// probabilistic operation (OAEP/PSS) would receive a baseline reused
// across stimulus instances, which is scientifically wrong. Previously the
// policy lived only in a comment, and a non-R_byte resolve() could call
// getBaseline() freely; confirmed by direct probe before this fix.
// ---------------------------------------------------------------------

export class BaselinePolicyViolationError extends Error {}

// M3-H6: a plan whose per-stimulus executability does not correspond exactly
// to its class's structural entries is refused outright.
export class ExecutabilityPlanMismatchError extends Error {}

function enforceCapIndependence(observation: RelationObservation): void {
  if (observation.relation !== 'R_cap') return;

  // I5' -- M3.8.2. The original I5 required at least two DISTINCT
  // participants, and that requirement was OURS, not the freeze's: 'I5' does
  // not appear in Harness v0.26, nor does any demand for two executions.
  //
  // It encoded the only implementation conceivable when it was written --
  // runDeclarationProbe and runMutation on the SAME adapter -- and that
  // implementation was tautological: two identities of one mechanism, which
  // M3.8.2 found and M3.9 replaced. I5 passed while the instrument was
  // tautological and failed once it stopped being so, which is the signature
  // of an invariant checking the wrong property.
  //
  // The frozen rule (M2.3.4) is DISJOINTNESS over concrete evidence identity,
  // never a cardinality:
  //
  //     Evidence_declaration(k,p)  n  Evidence_scored(k,p)  =  {}
  //
  // The declaration is grounded in M1 evidence recorded in v0.13 and is not
  // an M4 execution, so it is identified by declarationBasisRef rather than
  // carried as a participant. What must hold, and what is now checked, is
  // that the scored side is not that basis.
  const participants = new Set(observation.participants);
  if (participants.size === 0) {
    throw new CapabilityIndependenceViolationError(
      `R_cap observation ${observation.observationId} references no scored execution.`,
    );
  }
  const basis = observation.declarationBasisRef;
  if (basis === undefined) {
    throw new CapabilityIndependenceViolationError(
      `R_cap observation ${observation.observationId} names no declaration basis. A scored observation with no ` +
      'declared side to contrast is not an R_cap observation.',
    );
  }
  if (participants.has(basis)) {
    throw new CapabilityIndependenceViolationError(
      `R_cap observation ${observation.observationId}: the declaration basis '${basis}' is also a scored ` +
      'participant. The same evidence may never satisfy both roles.',
    );
  }
}

// ---------------------------------------------------------------------
// Baseline cache -- BaselineCacheKey = (operation, backend, canonical(baseFixture)).
// Scoped to a single orchestrator run; never shared across runs, fixtures,
// operations, or backends. NeedBaseline(i,p) <=> p.relation='R_byte':
// eligibility is governed by the frozen applicability/protocol -- this
// cache never independently decides a case is "probably deterministic," it
// only ever memoizes a baseline the PLAN itself already required.
// ---------------------------------------------------------------------

class BaselineCache<TFixture, TNativeRecord> {
  private readonly cache = new Map<string, Promise<ExecutionEvidence>>();

  private key(operation: OperationId, adapter: ExecutionAdapter<TFixture, TNativeRecord>, fixture: TFixture): string {
    return `${operation}::${adapter.backend.sourcePin}::${canonicalEncode(fixture)}`;
  }

  // `onFirstExecution` fires exactly once per distinct cache key -- so a
  // reused baseline is recorded into the run's own executions[] exactly
  // once, never once per PlanEntry that happens to reuse it, and never
  // silently omitted either.
  get(
    operation: OperationId,
    adapter: ExecutionAdapter<TFixture, TNativeRecord>,
    baselineInstanceId: string,
    fixture: TFixture,
    onFirstExecution: (evidence: ExecutionEvidence) => void,
  ): Promise<ExecutionEvidence> {
    const k = this.key(operation, adapter, fixture);
    let hit = this.cache.get(k);
    if (hit === undefined) {
      hit = executeBaseline('B', baselineInstanceId, fixture, adapter).then((evidence) => {
        onFirstExecution(evidence);
        return evidence;
      });
      this.cache.set(k, hit);
    }
    return hit;
  }
}

// ---------------------------------------------------------------------
// The orchestrator itself.
// ---------------------------------------------------------------------

export async function runPhaseC(plan: ExecutionPlan): Promise<PhaseCRunResult> {
  const executions: ExecutionEvidence[] = [];
  const observations: RelationObservation[] = [];
  const instances: MutationInstanceResult[] = [];
  const mutations: MutationResult[] = [];
  const omittedClasses: OmittedClass[] = [];
  const scientificResults: PhaseCScientificMutationResult[] = [];

  for (const classPlan of plan.classes) {
    const baselineCache = new BaselineCache<unknown, unknown>();
    const classInstances: MutationInstanceResult[] = [];

    for (const stimulus of classPlan.stimulusInstances) {
      // M3-H6: resolve executability for THIS stimulus, fail-closed on any
      // mismatch. A missing decision would silently drop a planned
      // observation; a surplus one would describe an entry that does not
      // exist. Both are refused rather than reconciled.
      const execFor = (entry: PlanEntry<unknown, unknown>): PlannedObservation['executability'] => {
        const matches = stimulus.executability.filter(
          (x) => x.relation === entry.relation && scopeEquals(x.scope, entry.scope),
        );
        if (matches.length !== 1) {
          throw new ExecutabilityPlanMismatchError(
            `${classPlan.mutation.mutationId}::${stimulus.stimulusInstanceId}: ${matches.length} executability ` +
            `decisions for (${entry.relation}, scope) -- exactly one is required (Keys(ExecMap) = Entries).`,
          );
        }
        return matches[0]!.state;
      };

      if (stimulus.executability.length !== classPlan.entries.length) {
        throw new ExecutabilityPlanMismatchError(
          `${classPlan.mutation.mutationId}::${stimulus.stimulusInstanceId}: ` +
          `${stimulus.executability.length} executability decisions for ${classPlan.entries.length} entries.`,
        );
      }

      const plannedObservations: PlannedObservation[] = classPlan.entries.map((e) => ({
        relation: e.relation, scope: e.scope, executability: execFor(e),
      }));

      // The context is built PER ENTRY, not once per stimulus, so that
      // getBaseline can enforce NeedBaseline(i,p) <=> p.relation='R_byte'
      // against the relation of the entry actually invoking it. A single
      // shared context could not distinguish which entry made the call.
      const makeCtx = (relation: PlannedObservation['relation']): PlanEntryContext<unknown, unknown> => ({
        mutationId: classPlan.mutation.mutationId,
        stimulusInstanceId: stimulus.stimulusInstanceId,
        baseFixture: stimulus.baseFixture,
        mutation: classPlan.mutation,
        getBaseline: (adapter) => {
          if (relation !== 'R_byte') {
            return Promise.reject(new BaselinePolicyViolationError(
              `A '${relation}' entry requested a baseline. NeedBaseline(i,p) <=> p.relation='R_byte': ` +
              'only R_byte compares a mutated execution against the unmutated baseline, and the baseline ' +
              "cache's own safety argument depends on that restriction. Refusing fail-closed rather than " +
              'silently serving a (possibly reused) baseline to a relation that must not have one.',
            ));
          }
          return baselineCache.get(
            classPlan.operation, adapter,
            `baseline-${classPlan.mutation.mutationId}-${stimulus.stimulusInstanceId}`,
            stimulus.baseFixture,
            (evidence) => executions.push(evidence),
          );
        },
        runMutation: async (adapter) => {
          const evidence = await executeMutation(classPlan.mutation, stimulus.stimulusInstanceId, stimulus.baseFixture, adapter);
          executions.push(evidence); // always a fresh real execution, never cached -- always recorded
          return evidence;
        },
        runOnInput: async (adapter, input, label) => {
          // Fresh and uncached by construction: a transferred artifact is
          // never the same input twice, and the baseline cache is scoped to
          // baseFixture alone.
          const evidence = await executeBaseline(
            'B', `${label}-${classPlan.mutation.mutationId}-${stimulus.stimulusInstanceId}`,
            input, adapter,
          );
          executions.push(evidence);
          return evidence;
        },
        runDeclarationProbe: async (adapter, input) => {
          if (relation !== 'R_cap') {
            throw new BaselinePolicyViolationError(
              `A '${relation}' entry requested a declaration probe. Only R_cap has a declaration-role ` +
              'evidence requirement (E_declaration + E_scored, with distinct execution identities).',
            );
          }
          // Fresh and UNCACHED by construction. The operational probe input
          // is supplied explicitly by the frozen binding/assembly layer and
          // is independent of the mutation fixture. This prevents request-,
          // adapter-, artifact- or capability-transform state from being
          // misused as the neutral provider-support probe input.
          const evidence = await executeBaseline(
            'B', `declaration-${classPlan.mutation.mutationId}-${stimulus.stimulusInstanceId}`,
            input, adapter,
          );
          executions.push(evidence);
          return evidence;
        },
      });

      const structuralBarriers = structurallyNonComparableRelations(
        classPlan.mutation.mutationId, stimulus.stimulusInstanceId);
      const instanceObservations: RelationObservation[] = [];
      for (const entry of classPlan.entries) {
        if (execFor(entry).kind === 'structurally-not-executable') continue;
        // A relation with a pre-registered structural barrier is never
        // resolved: there is no comparable object to observe, and running it
        // would only manufacture an insufficient-evidence that blocks a
        // completeness gate it was never an obligation for.
        if (structuralBarriers.has(entry.relation)) continue; // never resolved, never blocks completeness (M3-H1a)
        const observation = await entry.resolve(makeCtx(entry.relation));
        enforceCapIndependence(observation); // I5, fail-closed
        instanceObservations.push(observation);
        observations.push(observation);
      }

      const instanceResult = makeMutationInstanceResult({
        mutationId: classPlan.mutation.mutationId,
        stimulusInstanceId: stimulus.stimulusInstanceId,
        operation: classPlan.operation,
        planned: plannedObservations,
        observations: instanceObservations,
        // Verbatim. Not `?? something`, not recomputed, not defaulted: the
        // plan decided, the evidence records.
        ...(stimulus.interopEligibility !== undefined
          ? { interopEligibility: stimulus.interopEligibility } : {}),
        // M3-H13: pre-experimental, so it is resolved here from frozen
        // information rather than from anything the run observed.
        structurallyNonComparable: [
          ...structurallyNonComparableRelations(
            classPlan.mutation.mutationId, stimulus.stimulusInstanceId).keys(),
        ],
      });
      classInstances.push(instanceResult); // I1: exactly one per stimulusInstanceId, by construction of this loop
      instances.push(instanceResult);
    }

    // I3: aggregateMutationClass itself refuses (throws) if coverage is
    // incomplete anywhere -- never silently promoted to a MutationResult.
    //
    // M3-H11.4-Core.2: aggregation no longer throws, and a relation's own
    // unscoreability no longer decides the fate of the class.
    //
    // The reasoning that motivated the old behaviour was right about the
    // cell -- a vacuous 'pass' must never be fabricated to fill the vector --
    // and wrong about the blast radius. Withholding the whole MutationResult
    // discarded R_val/R_err/R_cap evidence that was perfectly good, for 24 of
    // 71 classes, because one relation they never had an obligation to
    // observe could not be scored.
    //
    // Now every class produces a Phase C scientific result. Classes with a
    // complete vector additionally reduce, losslessly, to the frozen M2
    // MutationResult; partial ones deliberately do not, and are carried in
    // their own collection rather than reported as an absence.
    const { observedSpectrum, nonScoreable, detectionSupport } =
      aggregateMutationClass(classPlan.applicability, classInstances, observations);

    const scientificResult = makePhaseCScientificResult({
      mutationId: classPlan.mutation.mutationId,
      operation: classPlan.operation,
      gamma0Ref: classPlan.gamma0Ref,
      ...(classPlan.registryEntryHash !== undefined ? { registryEntryHash: classPlan.registryEntryHash } : {}),
      applicability: classPlan.applicability,
      observedSpectrum,
      nonScoreable: nonScoreable.map((n) => ({
        mutationId: classPlan.mutation.mutationId,
        operation: classPlan.operation,
        relation: n.relation,
        cause: n.cause,
        stimulusInstanceIds: n.stimulusInstanceIds,
      })),
      instanceResults: classInstances,
      detectionSupport,
    });
    scientificResults.push(scientificResult);

    if (!isFullyScoreable(scientificResult)) continue;

    const mutationResult = makeMutationResult({
      mutationId: classPlan.mutation.mutationId,
      operation: classPlan.operation,
      gamma0Ref: classPlan.gamma0Ref,
      ...(classPlan.registryEntryHash !== undefined ? { registryEntryHash: classPlan.registryEntryHash } : {}),
      applicability: classPlan.applicability,
      expectedSpectrum: classPlan.expectedSpectrum,
      instanceResults: classInstances,
      // Strict bridge: refuses on any NonScoreableCell and never fills an
      // absent cell. Reached only when nonScoreable is empty.
      observedSpectrum: toRelationSpectrum(scientificResult),
      detectionSupport,
    });
    mutations.push(mutationResult);
  }

  // Coverage invariant: no class may silently vanish between the plan and
  // the result. Every planned class either produced a scientific result or
  // is recorded as omitted, with a structured cause.
  const accountedFor = new Set([
    ...scientificResults.map((r) => r.mutationId),
    ...omittedClasses.map((o) => o.mutationId),
  ]);
  for (const classPlan of plan.classes) {
    if (!accountedFor.has(classPlan.mutation.mutationId)) {
      omittedClasses.push({
        mutationId: classPlan.mutation.mutationId,
        operation: classPlan.operation,
        reason: 'not-reached',
      });
    }
  }

  return { executions, observations, instances, mutations, scientificResults, omittedClasses };
}
