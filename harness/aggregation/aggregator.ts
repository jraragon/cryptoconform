// M2.4.8 -- aggregation engine. Applies the already-frozen rules; never
// evaluates (that is M2.4.4's own job, already done by the time this runs).

import type { RelationApplicability, RelationId } from '../schema/registry-types.js';
import type { RelationValue, RelationSpectrum } from '../evidence/relation-spectrum.js';
import type { NonScoreableCause } from '../evidence/non-scoreable.js';
import type { PartialRelationSpectrum } from '../evidence/phase-c-scientific-result.js';
import type { RelationObservation } from '../evidence/relation-observation.js';
import type { MutationInstanceResult, PlannedObservation } from '../evidence/mutation-instance-result.js';
import { scopeEquals } from '../evidence/observation-scope.js';
import type { DetectionSupport } from '../evidence/mutation-result.js';

export class AggregationIncompleteError extends Error {}
export class DuplicateObservationError extends Error {}

// M3-H7 -- an applicable relation with zero executable support across the
// whole class. Distinct from AggregationIncompleteError, which signals
// MISSING evidence for a scope that was required; here no scope was ever
// executable, so there is nothing to be missing.
// M3-H11.4-Core.2: retained as a type so no importer breaks, but the
// aggregator no longer throws it. |S_i(c)| = 0 is now REPORTED, not raised:
// it is a fact about ONE relation and must not decide the fate of the class.
export class ZeroExecutableSupportError extends Error {}

/**
 * What aggregating one relation over one class yields.
 *
 * 'scored' carries a frozen RelationValue. 'non-scoreable' carries the cell's
 * own cause, and exists because the frozen three-value domain has no honest
 * member for an applicable relation with no evaluable support anywhere.
 */
export type RelationAggregate =
  | { readonly kind: 'scored'; readonly value: RelationValue }
  | {
      readonly kind: 'non-scoreable';
      readonly relation: RelationId;
      readonly cause: NonScoreableCause;
      readonly stimulusInstanceIds: readonly string[];
    };

const ALL_RELATIONS: readonly RelationId[] = ['R_byte', 'R_interop', 'R_ser', 'R_val', 'R_err', 'R_cap'];

// M3-H1b -- Required(i,R) = { p in i.coverage.planned | p.relation=R, p.executability='required' }.
// i.coverage.planned is the ONLY source of truth for what this instance was
// actually planned to produce -- never re-derived by calling the planner
// again here, per the explicit decision that re-planning at aggregation
// time would let a future planner change retroactively reinterpret
// already-produced evidence.
function requiredForRelation(instance: MutationInstanceResult, relation: RelationId): readonly PlannedObservation[] {
  return instance.coverage.planned.filter((p) => p.relation === relation && p.executability.kind === 'required');
}

// Resolves exactly the one real observation (if any) matching a planned
// (relation, scope) pair, from THIS instance's own observation set --
// never a bare relation-name match. Fail-closed on |Match|>1: two
// observations resolving the identical (relation,scope) is a harness-level
// inconsistency, never resolved arbitrarily.
function resolveObservation(
  instance: MutationInstanceResult,
  p: PlannedObservation,
  observationsById: ReadonlyMap<string, RelationObservation>,
): RelationObservation | undefined {
  const matches = instance.observations
    .map((id) => observationsById.get(id))
    .filter((o): o is RelationObservation => o !== undefined && o.relation === p.relation && scopeEquals(o.scope, p.scope));
  if (matches.length > 1) {
    throw new DuplicateObservationError(
      `Instance ${instance.mutationId}::${instance.stimulusInstanceId} has ${matches.length} observations resolving the same ` +
      `required (relation=${p.relation}, scope) -- harness-level inconsistency, never resolved arbitrarily.`,
    );
  }
  return matches[0];
}

// M3-H1b -- aggregateRelation(R,c) = Reduce_{fail>pass>n/a}( union over i of
// { state(o) | o resolves a Required(i,R) scope } ). Coverage is validated
// BEFORE any scientific reduction happens -- every required (relation,scope)
// pair, across every instance, must resolve to exactly one terminal
// observation before a single state is collected toward the reduction.
// This replaces the prior defect, where a bare `o.relation === relation`
// match let ONE arbitrary observation (of possibly several scopes under
// the same relation) stand in for the whole relation, silently discarding
// every other scope's own evidence -- including a real fail hidden behind
// an earlier-collected pass.
function aggregateRelation(
  relation: RelationId,
  applicable: boolean,
  instanceResults: readonly MutationInstanceResult[],
  observationsById: ReadonlyMap<string, RelationObservation>,
): RelationAggregate {
  if (!applicable) return { kind: 'scored', value: 'n/a' };

  const terminalStates: RelationValue[] = [];
  // M3-H7: S_i(c) -- the instances that carry at least one EXECUTABLE scope
  // for this relation. Aggregation happens over S_i(c) alone, per the frozen
  // Harness v0.26 rule (sec:5.3), never over every instance.
  let supportingInstances = 0;
  // Counted separately so |S_i(c)| = 0 can name WHICH of the two causes
  // produced it, rather than reporting one state for two different facts.
  let nonEligibleInstances = 0;
  let nonComparableInstances = 0;

  for (const instance of instanceResults) {
    // Two distinct states that must NOT be conflated, and which the first
    // H7 draft did conflate:
    //
    //   planned-for-relation is EMPTY  -> the plan itself is malformed. The
    //     relation is applicable, so scopes should have been planned for it;
    //     none were. This is H1b's original guard and it remains correct.
    //
    //   planned-for-relation is non-empty but NONE is 'required' -> a
    //     legitimate configuration: every scope was assessed and found
    //     structurally not executable. The instance is simply outside
    //     S_i(c) and contributes no scientific state. Its scopes remain
    //     recorded as not-executed in its own coverage: excluded from the
    //     vote, never discarded.
    const plannedForRelation = instance.coverage.planned.filter((p) => p.relation === relation);
    if (plannedForRelation.length === 0) {
      throw new AggregationIncompleteError(
        `Instance ${instance.mutationId}::${instance.stimulusInstanceId} has no planned scope at all for applicable relation ${relation} -- cannot aggregate.`,
      );
    }

    // M3-H9.3a-3.2.5c, connection 4 of 4 -- eligibility is read BEFORE
    // Required, and the order is not incidental:
    //
    //     |Planned| = 0            -> THROW   (malformed plan, unchanged)
    //     non-eligible             -> continue (outside S_interop(c))
    //     eligible & |Required| = 0 -> continue (H7, meaning unchanged)
    //
    // The two `continue`s look alike and mean opposite things. H7's says a
    // relation that DID carry a normative obligation found no executable
    // scope -- a real loss of support, which is why it can leave r(c)
    // unscorable. This one says no such obligation ever existed for this
    // stimulus: a capability declaration cannot begin a producer-to-
    // consumer flow, and a producer input the contract rejects produces no
    // artifact for any consumer to receive.
    //
    // Routing the second through the first was measured, not merely
    // disliked: it drives 24 of 71 classes into |S_i(c)| = 0 and the
    // orchestrator withholds their ENTIRE MutationResult, including
    // relations that never involved interoperability at all.
    //
    // Read from the instance's own recorded decision -- never re-resolved
    // against the registry here, for exactly the reason Required is read
    // from coverage.planned rather than by re-invoking the planner: a
    // later registry change must not retroactively reinterpret evidence
    // that has already been produced.
    if (relation === 'R_interop' && instance.interopEligibility?.value.kind === 'non-eligible') {
      nonEligibleInstances += 1;
      continue;
    }

    // M3-H13: a PRE-REGISTERED structural barrier. Read from the instance's
    // own recorded decision, exactly as eligibility is, so a later ground-truth
    // change cannot retroactively reinterpret produced evidence. Distinct from
    // the branch above because the CAUSE differs and both must stay
    // reconstructible.
    if (instance.structurallyNonComparable?.includes(relation) === true) {
      nonComparableInstances += 1;
      continue;
    }

    const required = requiredForRelation(instance, relation);
    if (required.length === 0) continue; // M3-H7: outside S_i(c)
    supportingInstances += 1;

    for (const p of required) {
      const obs = resolveObservation(instance, p, observationsById);
      if (obs === undefined || (obs.status !== 'pass' && obs.status !== 'fail' && obs.status !== 'n/a')) {
        throw new AggregationIncompleteError(
          `Instance ${instance.mutationId}::${instance.stimulusInstanceId}'s own ${relation} observation for one of its ` +
          `required scopes is missing or non-terminal -- refusing to aggregate rather than promoting it to pass.`,
        );
      }
      // n/a at the (instance, scope) level does not itself count as
      // evidence toward pass or fail -- it is scientifically neutral,
      // exactly as at the single-scope case this generalizes.
      if (obs.status !== 'n/a') terminalStates.push(obs.status);
    }
  }

  // M3-H7: |S_i(c)| = 0. The frozen formula's own universal quantifier is
  // vacuously true over the empty set, which would yield 'pass' -- but no
  // interoperability was ever observed, so that would be a fabricated
  // result. Nor is it 'n/a', which the Harness reserves strictly for
  // Applicability = 0, and this relation IS applicable:
  //     NotExecutable(c,s,R)  =/=>  n/a
  // Nor 'insufficient-evidence', which denotes a scope that SHOULD have
  // been executable but whose evidence failed; here no scope was ever
  // materialisable. The relation is simply unscorable, and rather than
  // inventing a fourth member of pass/fail/n/a the caller is stopped from
  // emitting a complete r(c) at all.
  // M3-H11.4-Core.2: this no longer throws.
  //
  // The reasoning above is unchanged and still correct -- the cell cannot be
  // pass, fail, n/a or insufficient-evidence. What changes is the CONSEQUENCE.
  // Throwing propagated a per-relation fact to the whole class: the
  // orchestrator caught it and withheld the entire MutationResult, so a class
  // such as GCM-PROVIDER-CAPABILITY-MISMATCH lost its perfectly good R_cap
  // evidence because a relation it never had an obligation to observe was
  // unscoreable. Measured at 24 of 71 classes.
  //
  // The relation is now reported as non-scoreable, with its cause, and the
  // class's other relations aggregate normally.
  if (supportingInstances === 0) {
    return {
      kind: 'non-scoreable',
      relation,
      // Two causes, never merged. H11's is normative and environment-invariant;
      // H7's is a genuine loss of support where an obligation existed, and a
      // new backend could dissolve it.
      // Three causes now, and the order encodes which explanation is the
      // more informative one: the specialised interop taxonomy first, then
      // the general structural barrier, then the environmental default.
      cause: nonEligibleInstances > 0 && nonEligibleInstances === instanceResults.length
        ? 'contractually-non-eligible'
        : nonComparableInstances > 0 && nonComparableInstances === instanceResults.length
          ? 'structurally-non-comparable'
          : 'zero-executable-support',
      stimulusInstanceIds: instanceResults.map((i) => i.stimulusInstanceId),
    };
  }

  // Reached only once every required (relation,scope) pair, across every
  // CONTRIBUTING instance, resolved to a terminal status -- so an empty
  // terminalStates here can only mean every one of them was 'n/a'.
  if (terminalStates.length === 0) return { kind: 'scored', value: 'n/a' };
  if (terminalStates.includes('fail')) return { kind: 'scored', value: 'fail' }; // existential fail-dominant
  return { kind: 'scored', value: 'pass' };
}

export function aggregateMutationClass(
  applicability: RelationApplicability,
  instanceResults: readonly MutationInstanceResult[],
  allObservations: readonly RelationObservation[],
): {
  readonly observedSpectrum: PartialRelationSpectrum;
  readonly nonScoreable: readonly Extract<RelationAggregate, { kind: 'non-scoreable' }>[];
  readonly detectionSupport: DetectionSupport;
} {
  const observationsById = new Map(allObservations.map((o) => [o.observationId, o]));

  // r~(c) is built key by key: a non-scoreable relation contributes NO key,
  // so a missing key has exactly one meaning. Inapplicable relations still
  // get their 'n/a' -- omission is never shared between the two.
  const observedSpectrum: Partial<Record<RelationId, RelationValue>> = {};
  const nonScoreable: Extract<RelationAggregate, { kind: 'non-scoreable' }>[] = [];
  for (const r of ALL_RELATIONS) {
    const outcome = aggregateRelation(r, applicability[r], instanceResults, observationsById);
    if (outcome.kind === 'scored') observedSpectrum[r] = outcome.value;
    else nonScoreable.push(outcome);
  }

  // M3-H1b -- DetectionSupport, corrected to the SAME (relation,scope)-exact
  // resolution, while deliberately preserving per-INSTANCE counting (never
  // per-scope): Evaluated(i,R) <=> exists scope: state(i,R,scope) in
  // {pass,fail}; Divergent(i,R) <=> exists scope: state(i,R,scope)=fail. A
  // relation with six directions must never carry six times the support
  // weight of a single-scope relation merely because it produced more
  // observations.
  let evaluatedInstances = 0;
  let divergentInstances = 0;
  for (const instance of instanceResults) {
    let instanceEvaluated = false;
    let instanceDivergent = false;
    for (const relation of ALL_RELATIONS) {
      if (!applicability[relation]) continue;
      for (const p of requiredForRelation(instance, relation)) {
        const obs = resolveObservation(instance, p, observationsById);
        if (obs?.status === 'pass' || obs?.status === 'fail') instanceEvaluated = true;
        if (obs?.status === 'fail') instanceDivergent = true;
      }
    }
    if (instanceEvaluated) evaluatedInstances += 1;
    if (instanceDivergent) divergentInstances += 1;
  }

  return { observedSpectrum, nonScoreable, detectionSupport: { divergentInstances, evaluatedInstances } };
}
