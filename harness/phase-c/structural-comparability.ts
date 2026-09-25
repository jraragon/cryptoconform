// M3-H13.2 -- structural comparability.
//
// The third reason an APPLICABLE relation can fail to be scoreable, found by
// runPhaseC when nothing smaller could find it: the execution happens, the
// backend does not fail, and the relation still has no normatively comparable
// object.
//
//     Applicable & Eligible & Executable & Executed & !Comparable_err
//
// Two names, deliberately not one, because conflating them is what made the
// frozen model unable to express this at all:
//
//     StructuralComparable(c,s,R)  !=  Comparable_R(Evidence)
//
// The first is PRE-EXPERIMENTAL. It may read ground truth, eligibility and
// the normative shape of the fixture, and NOTHING else -- no bytes, no
// statuses, no observed results. It is knowable before M4 and no backend can
// decide it.
//
// The second is the evaluator's own full precondition and may depend on what
// actually happened. It stays exactly where it is.
//
// The consequence of each is different, and that difference is the whole
// point:
//
//     StructuralComparable = false  =>  NonScoreable, no obligation
//     StructuralComparable = true & !Comparable_R(E)  =>  insufficient-evidence
//                                                     =>  incomplete
//
// --- 'true' is a bound, not a promise -----------------------------------
//
// StructuralComparable = true means ONLY that no pre-registered structural
// barrier is known. It does NOT promise the evaluator will find the evidence
// comparable. Comparable_ser's "any semantic material needed to check
// preservation is available" and R_byte's inputsEquivalent are runtime
// conditions, so R_ser reading 53/53 here must never be read as "R_ser is
// always comparable". There is deliberately no third 'unknown' value:
// undecidable before execution means the relation stays REQUIRED and resolves
// its comparability at run time, which is what preserves insufficient-evidence.

import type { RelationId } from '../schema/registry-types.js';
import { APPLICABILITY_MATRIX } from '../applicability/matrix.js';
import { MUTATION_REGISTRY } from '../registry/mutations.js';
import { resolveGroundTruth } from './ground-truth/resolve.js';
import { resolveInteropEligibility } from './interop-eligibility/resolve.js';
import type { NonScoreableCause } from '../evidence/non-scoreable.js';
import { producerExecutionPreservesStimulusIdentity } from './producer-stimulus-identity.js';
import {
  adapterTransformObservable, classifyAdapterTransform, isAdapterTransform,
} from './adapter-transform-observability.js';
import { getFixtureResolver } from './fixture-index.js';
import { getMutationImplementation } from './mutation-index.js';
import { loadFrozenMaterialPool } from './material/load.js';
import type { OperationId } from '../schema/capability.js';

// Frozen data only: the fixture and the mutation are deterministic functions
// of the corpus, so resolving them here stays PRE-EXPERIMENTAL. Memoised
// because the predicate is asked per observation.
let poolCache: ReturnType<typeof loadFrozenMaterialPool> | undefined;
const identityCache = new Map<string, boolean>();

/**
 * M3.8.2 -- an adapter-transform class whose intervention cannot be executed.
 *
 * G2 mutates a property of the interface and G3 has no operational input, so
 * executing the wrapped request would run the BASE CASE and the intervention
 * would not occur. Both remain observable through R_cap, which contrasts a
 * frozen declaration against a probe and needs no mutated execution.
 */
function adapterTransformBarrier(
  mutationId: string, stimulusInstanceId: string, relation: RelationId,
): boolean {
  if (!isAdapterTransform(mutationId)) return false;
  try {
    poolCache ??= loadFrozenMaterialPool();
    const f0 = getFixtureResolver(mutationId, stimulusInstanceId)(mutationId, stimulusInstanceId, poolCache);
    const fm = (getMutationImplementation(mutationId) as { mutate: (f: unknown, s: string) => unknown })
      .mutate(f0, stimulusInstanceId);
    return !adapterTransformObservable(classifyAdapterTransform(fm), relation);
  } catch {
    return false;
  }
}

/**
 * A capability-transform fixture is a declaration, not an operational input.
 *
 * R_interop, R_val and R_err already retain their more specific frozen
 * structural barriers below. The missing cases are R_byte and R_ser: both
 * require an executable cryptographic input, which a capability declaration
 * cannot provide. R_cap remains observable through the frozen manifest.
 */
function capabilityTransformExecutionBarrier(
  mutationId: string, relation: RelationId,
): boolean {
  const entry = MUTATION_REGISTRY.find((e) => e.mutationId === mutationId);
  if (entry?.mechanism !== 'capability-transform') return false;
  return relation === 'R_byte' || relation === 'R_ser' || relation === 'R_cap';
}

/**
 * Whether the mutated serialization stimulus already carries the artifact
 * being observed.
 *
 * For import/decrypt, the artifact is INPUT evidence and therefore exists
 * independently of whether the backend accepts or rejects it. For
 * export/encrypt, no artifact field exists in the stimulus: R_ser can only
 * observe an artifact produced by the execution.
 *
 * Undefined means the frozen fixture could not be materialised here, so this
 * pre-experimental layer cannot prove a barrier and must leave comparability
 * to runtime rather than fabricate non-scoreability.
 */
function serializationInputArtifactExists(
  mutationId: string, stimulusInstanceId: string,
): boolean | undefined {
  try {
    poolCache ??= loadFrozenMaterialPool();
    const f0 = getFixtureResolver(mutationId, stimulusInstanceId)(
      mutationId, stimulusInstanceId, poolCache,
    );
    const fm = (getMutationImplementation(mutationId) as {
      mutate: (f: unknown, s: string) => unknown;
    }).mutate(f0, stimulusInstanceId);

    if (fm === null || typeof fm !== 'object') return false;
    return (fm as Record<string, unknown>)['artifact'] !== undefined;
  } catch {
    return undefined;
  }
}

function preservesStimulusIdentity(
  mutationId: string, stimulusInstanceId: string, operation: OperationId,
): boolean {
  const key = `${mutationId}::${stimulusInstanceId}`;
  const hit = identityCache.get(key);
  if (hit !== undefined) return hit;
  let value = true;
  try {
    poolCache ??= loadFrozenMaterialPool();
    const f0 = getFixtureResolver(mutationId, stimulusInstanceId)(mutationId, stimulusInstanceId, poolCache);
    const fm = (getMutationImplementation(mutationId) as { mutate: (f: unknown, s: string) => unknown })
      .mutate(f0, stimulusInstanceId);
    value = producerExecutionPreservesStimulusIdentity(operation, fm);
  } catch {
    // A pair the frozen corpus cannot materialise proves no barrier here.
    value = true;
  }
  identityCache.set(key, value);
  return value;
}

export type StructuralComparability = 'comparable' | 'structurally-non-comparable';

export interface StructuralComparabilityVerdict {
  readonly value: StructuralComparability;
  /** Which frozen premise can never be satisfied. Absent when comparable. */
  readonly premise?: string;
  /** The cause to record if this blocks scoring. */
  readonly cause?: NonScoreableCause;
}

const COMPARABLE: StructuralComparabilityVerdict = Object.freeze({ value: 'comparable' });

/**
 * A pair the frozen registry does not declare has no pre-registered barrier
 * this function can PROVE, so it reports none. Refusing here would make this
 * function police registry membership, which is auditPlanBinding's and the
 * ground-truth resolver's job -- and would turn 'I cannot decide' into
 * 'structurally non-comparable', which is exactly the inversion H13 exists to
 * prevent. There is no third 'unknown' value for the same reason.
 */
function groundTruthOrUndefined(mutationId: string, stimulusInstanceId: string) {
  try { return resolveGroundTruth(mutationId, stimulusInstanceId).row; }
  catch { return undefined; }
}

/**
 * Derived exclusively from pre-registered information.
 *
 * R_err  -- Comparable_err conditions 4 and 5: the contract must determine an
 *           observable SDK error class AND a classifiable rejection must
 *           occur. A class whose ground truth says 'no-error-expected' can
 *           satisfy neither, ever, on any backend.
 * R_val  -- Comparable_val condition 3: an unambiguous expected contractual
 *           decision must EXIST. The eleven declarative fixtures have none.
 * R_interop -- the same question, already answered by a MORE informative and
 *           already-frozen taxonomy. Structural comparability is defined
 *           through it rather than over it, so the specialised provenance
 *           won from H9/H11 is preserved instead of flattened:
 *               StructuralComparable_interop(c,s) <=> Eligibility = eligible
 *           and the recorded cause stays 'contractually-non-eligible'.
 *
 * R_ser  -- Comparable_ser requires the portable artifact itself. For
 *           import/decrypt the mutated stimulus already carries that artifact,
 *           so a contractual rejection does not remove observability. For
 *           export/encrypt, however, a pre-registered rejection means a
 *           conforming execution produces no artifact at all.
 *
 * Any remaining relation without a specific case below has no additional
 * pre-registered barrier, which is a statement about this evidence, not a
 * guarantee about its evaluator.
 */
export function structuralComparability(
  mutationId: string, stimulusInstanceId: string, relation: RelationId,
): StructuralComparabilityVerdict {
  const entry = MUTATION_REGISTRY.find((e) => e.mutationId === mutationId);
  if (entry === undefined) return COMPARABLE; // unknown class: not this function's refusal to make
  if (!APPLICABILITY_MATRIX[entry.operation][relation]) return COMPARABLE; // n/a's own domain

  if (adapterTransformBarrier(mutationId, stimulusInstanceId, relation)) {
    return {
      value: 'structurally-non-comparable',
      premise: 'the class mutates a property of the adapter interface, or has no operational input, so executing '
        + 'the operation would run the base case and the intervention would not occur (M3.8.2)',
      cause: 'structurally-non-comparable',
    };
  }

  if (capabilityTransformExecutionBarrier(mutationId, relation)) {
    return {
      value: 'structurally-non-comparable',
      premise: 'the capability-transform fixture is a declaration with no operational input, so this relation '
        + 'cannot be observed by executing the cryptographic operation',
      cause: 'structurally-non-comparable',
    };
  }

  switch (relation) {
    case 'R_byte': {
      const gt = groundTruthOrUndefined(mutationId, stimulusInstanceId);
      if (gt === undefined) return COMPARABLE;

      // RSA/EC artifact-side serialization stimuli exercise IMPORT. The
      // portable artifact is therefore an INPUT, not an execution output.
      // Comparable_byte requires output bytes from both providers; a
      // successful import recovers key material but does not produce a new
      // serialization artifact. Do not fabricate output bytes by echoing or
      // re-exporting the consumed artifact.
      if (entry.operation === 'rsa-ser' || entry.operation === 'ec-ser') {
        const hasInputArtifact = serializationInputArtifactExists(
          mutationId, stimulusInstanceId,
        );
        if (hasInputArtifact === true) {
          return {
            value: 'structurally-non-comparable',
            premise: 'Comparable_byte requires provider output bytes, but this serialization stimulus is '
              + 'artifact-side/import: the portable artifact is input evidence and a successful import returns '
              + 'material rather than a new serialization artifact',
            cause: 'structurally-non-comparable',
          };
        }
      }

      if (
        gt.expectedValidation?.decision.kind === 'reject'
        || gt.expectedOutcome?.kind === 'reject'
      ) {
        return {
          value: 'structurally-non-comparable',
          premise: 'Comparable_byte requires cryptographic output bytes, but the pre-registered validation decision '
            + 'or operational outcome for this stimulus is rejection, so no comparable output object is expected to exist',
          cause: 'structurally-non-comparable',
        };
      }
      return COMPARABLE;
    }
    case 'R_ser': {
      const gt = groundTruthOrUndefined(mutationId, stimulusInstanceId);
      if (gt === undefined) return COMPARABLE;

      // Comparable_ser requires an actual portable artifact. An import/decrypt
      // stimulus already RECEIVES one, so even a contractual rejection leaves
      // R_ser statically observable. An export/encrypt stimulus has no input
      // artifact: if its pre-registered validation decision is rejection, a
      // conforming execution produces no artifact and there is therefore no
      // R_ser object to compare.
      if (gt.expectedValidation?.decision.kind === 'reject') {
        const hasInputArtifact = serializationInputArtifactExists(
          mutationId, stimulusInstanceId,
        );
        if (hasInputArtifact === false) {
          return {
            value: 'structurally-non-comparable',
            premise: 'Comparable_ser requires a portable artifact, but this is an output-side stimulus whose '
              + 'pre-registered validation decision is rejection, so a conforming execution produces no artifact '
              + 'to evaluate for representation conformance or material preservation',
            cause: 'structurally-non-comparable',
          };
        }
      }
      return COMPARABLE;
    }
    case 'R_err': {
      const gt = groundTruthOrUndefined(mutationId, stimulusInstanceId);
      if (gt === undefined) return COMPARABLE;
      if (gt.errorExpectation?.kind === 'no-error-expected') {
        return {
          value: 'structurally-non-comparable',
          premise: 'Comparable_err(4,5): the contract determines no observable error class, and no classifiable rejection occurs',
          cause: 'structurally-non-comparable',
        };
      }

      // M3-reopen-v5: RSA serialization output-side rejection stimuli are
      // validated before any portable artifact exists. The frozen production
      // export interfaces expose only provider/native error text on rejection,
      // not an SDK error class. R_err therefore has no classifiable SDK
      // rejection object on this path. Do not infer a class from native text.
      if (
        (entry.operation === 'rsa-ser' || entry.operation === 'ec-ser')
        && gt.errorExpectation?.kind === 'error-expected'
      ) {
        const hasInputArtifact = serializationInputArtifactExists(
          mutationId, stimulusInstanceId,
        );
        if (hasInputArtifact === false) {
          return {
            value: 'structurally-non-comparable',
            premise: 'Comparable_err requires a classifiable SDK rejection, but this serialization '
              + 'material-side/output stimulus reaches an export interface that exposes no SDK error class '
              + 'on rejection; native/provider error text is not promoted to SDK evidence',
            cause: 'structurally-non-comparable',
          };
        }
      }

      return COMPARABLE;
    }
    case 'R_val': {
      const gt = groundTruthOrUndefined(mutationId, stimulusInstanceId);
      if (gt === undefined) return COMPARABLE;
      if (gt.expectedValidation === undefined) {
        return {
          value: 'structurally-non-comparable',
          premise: 'Comparable_val(3): no unambiguous expected contractual decision exists',
          cause: 'structurally-non-comparable',
        };
      }
      return COMPARABLE;
    }
    case 'R_interop': {
      let el;
      try { el = resolveInteropEligibility(mutationId, stimulusInstanceId).eligibility; }
      catch { return COMPARABLE; }
      if (el.kind === 'eligible') {
        // M3-reopen-v5: a directed interoperability observation requires an
        // artifact to cross the producer -> consumer boundary. An import-side
        // stimulus already carries that artifact; an output-side stimulus with
        // a pre-registered rejection does not have a transferable producer artifact.
        const gt = groundTruthOrUndefined(mutationId, stimulusInstanceId);
        if (gt?.expectedValidation?.decision.kind === 'reject') {
          const hasInputArtifact = serializationInputArtifactExists(
            mutationId, stimulusInstanceId,
          );
          if (hasInputArtifact === false) {
            return {
              value: 'structurally-non-comparable',
              premise: 'Comparable_interop requires an artifact to cross the producer-to-consumer boundary, but '
                + 'this is a material-side/output stimulus whose pre-registered validation decision is rejection, '
                + 'so a conforming producer emits no artifact to transfer',
              cause: 'structurally-non-comparable',
            };
          }
        }

        // M3.7-D2. An artifact-side obligation is comparable only if the
        // artifact DEFINING the stimulus can be obtained by a real execution
        // of scope.from without changing the stimulus's identity. Evaluated on
        // the shape of the obligation, never on a class name.
        if (!preservesStimulusIdentity(mutationId, stimulusInstanceId, entry.operation)) {
          return {
            value: 'structurally-non-comparable',
            premise: 'the artifact defining the stimulus is pre-established and cannot be reproduced by a real '
              + 'execution of scope.from without changing the stimulus identity (M3.7-D2)',
            cause: 'structurally-non-comparable',
          };
        }
        return COMPARABLE;
      }
      return {
        value: 'structurally-non-comparable',
        premise: 'no producer-to-consumer flow exists for this stimulus',
        // NOT renamed and NOT migrated: the specialised cause is more
        // informative and is already frozen.
        cause: 'contractually-non-eligible',
      };
    }
    default:
      return COMPARABLE;
  }
}

/** The relations of one (c,s) that carry a pre-registered structural barrier. */
export function structurallyNonComparableRelations(
  mutationId: string, stimulusInstanceId: string,
): ReadonlyMap<RelationId, StructuralComparabilityVerdict> {
  const out = new Map<RelationId, StructuralComparabilityVerdict>();
  for (const r of ['R_byte', 'R_interop', 'R_ser', 'R_val', 'R_err', 'R_cap'] as const) {
    const v = structuralComparability(mutationId, stimulusInstanceId, r);
    if (v.value === 'structurally-non-comparable') out.set(r, v);
  }
  return out;
}
