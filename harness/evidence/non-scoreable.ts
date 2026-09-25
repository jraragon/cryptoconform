// M3-H11.4-Core.1 -- structured representation of an applicable relation that
// carries no scoreable result for a class.
//
// This module introduces VOCABULARY ONLY. Nothing here changes aggregation,
// completeness, or any frozen type; the consumers arrive in Core.2 onward.
//
// --- Why a new object exists at all -----------------------------------
//
// M0 defines r(c) as a total vector over six components, with
//     n/a  <=>  Applicability(R_i, o) = 0
// and M2 (Harness v0.26 §5.5) states, as two mutually exclusive and jointly
// exhaustive rules, that not-executed covers the case where a CONCRETE SCOPE
// cannot materialize the stimulus. That pairing works because some other
// scope still can, so S_i(c) is non-empty and the cell still scores.
//
// M3-H9 reached a case the frozen model never contemplated: NO scope can,
// for a contractual rather than an environmental reason. The three frozen
// values cannot express it honestly --
//     pass would fabricate conformance from the absence of a fail,
//     fail would assert a divergence nobody observed,
//     n/a would deny an applicability the matrix asserts.
// -- and the frozen vocabulary of NonExecutionReason describes a SCOPE, not
// a class. So the cell is represented OUTSIDE the spectrum rather than
// inside it, and RelationSpectrum is not modified:
//
//     ScientificResult(c) = ( r~(c), NonScoreable(c) )
//
// where r~(c) is partial over an observable domain D_c and NonScoreable
// records, with cause, exactly the applicable relations absent from D_c.
//
// This is a PROSPECTIVE M3 deviation from the frozen M0/M2 model, not a
// reinterpretation of it. The assumption that failed is precise, and neither
// the applicability matrix nor M2.4.5's planning decision was wrong:
//
//     M0/M2 assumed every APPLICABLE relation would retain at least one
//     scoreable support at CLASS level.

import type { OperationId } from '../schema/capability.js';
import type { RelationId } from '../schema/registry-types.js';

// ---------------------------------------------------------------------
// The two causes
//
// Deliberately NOT NonExecutionReason, and deliberately two values rather
// than one. The frozen vocabulary {backend-capability-absent,
// stimulus-not-expressible, direction-not-materializable} answers "why could
// THIS SCOPE not run" and is environmental; these answer "why does this
// CLASS have no scoreable result for this relation".
//
//     EnvironmentalNonExecution  !=  ContractualNonEligibility
//
// The invariant that separates the two, and the way to test it rather than
// merely assert it: 'contractually-non-eligible' is INVARIANT under adding a
// backend, because the portable contract rejects the mutated producer input
// identically for every provider. 'zero-executable-support' is not: it is a
// property of the current manifests and a new backend can dissolve it.
// ---------------------------------------------------------------------

export type NonScoreableCause =
  // No stimulus of the class defines an evaluable producer->consumer flow:
  // either the contract rejects the mutated producer input (so no artifact is
  // ever produced) or the fixture carries no operational input at all.
  // EligibleSet(c, R) = {} -- pre-registered, environment-invariant.
  | 'contractually-non-eligible'
  // The class HAS eligible stimuli, but no scope of any of them is executable
  // on the currently declared backends. S_i(c) = {} -- this is H7's own
  // cause, kept separate precisely because it is a genuine loss of support
  // where an obligation existed, and may legitimately weigh differently.
  | 'zero-executable-support'
  // M3-H13: the relation is applicable, eligible and executable, the
  // execution happens and the backend does not fail -- and a frozen premise
  // the evaluator needs can NEVER be satisfied for this class:
  // Comparable_err(4,5) for a class the contract gives no error class, and
  // Comparable_val(3) for one with no expected decision. Pre-experimental and
  // environment-invariant: no backend can create an error class the contract
  // does not determine.
  //
  // Deliberately does NOT absorb 'contractually-non-eligible'. That cause is
  // more informative and already frozen, so R_interop keeps it: the general
  // dimension is defined THROUGH the specialised taxonomy, not over it.
  | 'structurally-non-comparable';

// ---------------------------------------------------------------------
// The cell
//
// One record per (class, relation). `operation` is carried explicitly
// because every downstream comparison of spectra is confined to M_o
// (H12.0: M_o and Mut(o) are both per-operation), so a consumer must be able
// to see the operation without re-resolving the registry -- and a
// cross-operation comparison must be refusable by inspection.
//
// `evidence` is a free-form human-readable trace, never a semantic field: no
// consumer may branch on it. That is the M3-H10/H11 lesson from
// unscoredClasses, whose `reason` is an exception message doing duty as
// science.
// ---------------------------------------------------------------------

export interface NonScoreableCell {
  readonly mutationId: string;
  readonly operation: OperationId;
  readonly relation: RelationId;
  readonly cause: NonScoreableCause;
  /** Stimulus instances that carried the relation in the plan, for reconstruction. */
  readonly stimulusInstanceIds: readonly string[];
  /** Human-readable trace only. Never branched on. */
  readonly note?: string;
}

/**
 * S_c, the SCOREABLE APPLICABLE domain: the applicable relations that did
 * yield a pass/fail. Computed as a complement so the two can never disagree.
 *
 *     S_c = { R : Applicability(o,R) = 1 } \ { R : NonScoreable(c,R) }
 *
 * Named precisely, because it is NOT the domain of r~(c). Core.1 originally
 * called this `observableDomain` and the microcontract wrote
 * r~(c) : D_c -> {pass, fail, n/a}; the two together were inconsistent,
 * since R in S_c implies Applicability = 1 while the frozen rule is
 * n/a <=> Applicability = 0, so n/a could never appear. The three states are
 * distinct and all three must remain expressible:
 *
 *     Applicability = 0                  ->  n/a          (in dom(r~), not in S_c)
 *     Applicability = 1, scoreable       ->  pass | fail  (in dom(r~), in S_c)
 *     Applicability = 1, non-scoreable   ->  cell absent  (not in dom(r~))
 */
export function scoreableApplicableDomain(
  applicable: readonly RelationId[],
  nonScoreable: readonly NonScoreableCell[],
): readonly RelationId[] {
  const absent = new Set(nonScoreable.map((n) => n.relation));
  return applicable.filter((r) => !absent.has(r));
}

/**
 * dom(r~(c)) = R \ NonScoreable(c) = S_c u Inapplicable(o).
 *
 * The domain of the partial spectrum itself. A missing key therefore carries
 * exactly ONE meaning -- applicable but non-scoreable -- and is never
 * overloaded with inapplicability, which stays materialised as 'n/a'.
 */
export function spectrumDomain(
  all: readonly RelationId[],
  nonScoreable: readonly NonScoreableCell[],
): readonly RelationId[] {
  const absent = new Set(nonScoreable.map((n) => n.relation));
  return all.filter((r) => !absent.has(r));
}

/**
 * Fail-closed structural check over one class's cells.
 *
 * Refuses rather than tolerates:
 *   - a relation appearing twice, which would make D_c ambiguous
 *   - a cell for a relation the operation does not have applicable, since
 *     that is n/a's own domain and must never be re-labelled as unscoreable
 *   - a cell naming a different class than the one under assembly
 */
export class NonScoreableIntegrityError extends Error {}

export function assertNonScoreableWellFormed(
  mutationId: string,
  applicable: readonly RelationId[],
  cells: readonly NonScoreableCell[],
): void {
  const seen = new Set<RelationId>();
  const applicableSet = new Set(applicable);
  for (const cell of cells) {
    if (cell.mutationId !== mutationId) {
      throw new NonScoreableIntegrityError(
        `NonScoreable cell for '${cell.mutationId}' attached to class '${mutationId}'.`,
      );
    }
    if (seen.has(cell.relation)) {
      throw new NonScoreableIntegrityError(
        `${mutationId}: relation ${cell.relation} is recorded non-scoreable twice; D_c would be ambiguous.`,
      );
    }
    seen.add(cell.relation);
    if (!applicableSet.has(cell.relation)) {
      throw new NonScoreableIntegrityError(
        `${mutationId}: ${cell.relation} is not applicable to operation '${cell.operation}'. ` +
        'An inapplicable relation is n/a by the frozen rule and must never be recorded as unscoreable.',
      );
    }
  }
}

/**
 * True iff the cause cannot change by declaring another backend.
 *
 * Exposed as a function rather than left implicit because it is the
 * operational difference between the two causes, and Core.6 asserts it by
 * actually varying the manifests rather than by reading the label.
 */
export function isEnvironmentInvariant(cause: NonScoreableCause): boolean {
  // Only 'zero-executable-support' can be dissolved by declaring a backend.
  return cause !== 'zero-executable-support';
}
