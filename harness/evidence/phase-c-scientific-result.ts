// M3-H11.4-Core.2 -- the Phase C scientific result.
//
// A SEPARATE M3 type, deliberately not a mutation of MutationResult.
//
// Three routes were possible and two are wrong. Making observedSpectrum
// optional inside MutationResult would change a frozen M2 type, put two
// different scientific semantics under one name, and let code expecting a
// MutationResult receive an object that is not one. Wrapping
// { mutationResult, nonScoreable } is worse: for a partial class there is no
// valid MutationResult to wrap, since constructing one would require
// fabricating exactly the cells H11 forbids.
//
// So M3 gets its own result, and M2's keeps its meaning unchanged:
//
//     NonScoreable(c) = {}    =>  reducible to RelationSpectrum, losslessly
//     NonScoreable(c) != {}   =>  NOT reducible to MutationResult, by design
//
// --- The single meaning of a missing key ------------------------------
//
// An INAPPLICABLE relation is never omitted: it is materialised as 'n/a',
// per the frozen rule n/a <=> Applicability = 0. Omission therefore carries
// exactly one meaning and is never overloaded:
//
//     R not in observedSpectrum  <=>  exists NonScoreableCell(c, R)
//
// That biconditional is asserted, not assumed (assertScientificResultWellFormed).
//
// --- What this module deliberately does NOT do ------------------------
//
// Core.2 answered "what scientific result did aggregation produce"; Core.3
// adds "were all required obligations satisfied", derived from
// RequiredEvidence and NEVER from totalising the vector. The property is
// named requiredEvidenceComplete rather than `complete` on purpose: M2's own
// `complete` still exists on MutationResult with its historical definition,
// and two homonymous booleans with different definitions is exactly the
// confusion this remediation exists to remove.
//
// No cross-operation comparison of any kind: H11.3-6 is blocked by M3-H12,
// which found that 11 of 15 operation pairs cannot produce pattern equality
// by applicability mask alone. `operation` is carried so a later consumer
// can REFUSE such a comparison by inspection rather than assume it away.

import type { OperationId } from '../schema/capability.js';
import type { RelationApplicability, RelationId } from '../schema/registry-types.js';
import type { RelationValue, RelationSpectrum } from './relation-spectrum.js';
import type { MutationInstanceResult } from './mutation-instance-result.js';
import type { DetectionSupport } from './mutation-result.js';
import {
  assertNonScoreableWellFormed,
  spectrumDomain,
  type NonScoreableCell,
} from './non-scoreable.js';

export const ALL_RELATION_IDS: readonly RelationId[] =
  Object.freeze(['R_byte', 'R_interop', 'R_ser', 'R_val', 'R_err', 'R_cap']);

/** r~(c). A key is absent iff that relation is applicable but non-scoreable. */
export type PartialRelationSpectrum = Readonly<Partial<Record<RelationId, RelationValue>>>;

export interface PhaseCScientificMutationResult {
  readonly mutationId: string;
  readonly operation: OperationId;
  readonly gamma0Ref: string;
  /**
   * M3.3 -- binds this result to the CONTENT of its registry entry, so a
   * later registry change cannot be silently absorbed. gamma0Ref names the
   * entry; this proves which entry it was.
   */
  readonly registryEntryHash?: string;
  readonly applicability: RelationApplicability;
  readonly observedSpectrum: PartialRelationSpectrum;
  readonly nonScoreable: readonly NonScoreableCell[];
  readonly instanceResultRefs: readonly string[];
  readonly detectionSupport: DetectionSupport;
  /**
   * Complete(c) <=> Outstanding(c) = {}, over REQUIRED evidence only.
   *
   * A non-scoreable relation therefore cannot make a class incomplete:
   *     NonScoreable(c,R)  =/=>  Incomplete(c)
   * which is the whole of M3-H10 stated as a property.
   */
  readonly requiredEvidenceComplete: boolean;
  /**
   * Which obligations were required and not satisfied. Kept alongside the
   * boolean because it is the scientifically useful half: it can demonstrate
   * WHICH obligation is missing, where the boolean can only assert that one
   * is.
   */
  readonly outstandingRequiredEvidence: readonly OutstandingEvidenceRef[];
}

export interface OutstandingEvidenceRef {
  readonly stimulusInstanceId: string;
  readonly relation: RelationId;
}

export class ScientificResultIntegrityError extends Error {}

/**
 * The representation invariant, in the form that makes a lost cell impossible:
 *
 *     for all R:  XOR( R in dom(r~), R in NonScoreable(c) )
 *     R in NonScoreable(c)  =>  Applicability(o,R) = 1
 *
 * Checked over all six relations rather than over the keys present, so a cell
 * that simply went missing is caught as loudly as one that was mislabelled.
 */
export function assertScientificResultWellFormed(r: PhaseCScientificMutationResult): void {
  const applicable = ALL_RELATION_IDS.filter((rel) => r.applicability[rel]);
  assertNonScoreableWellFormed(r.mutationId, applicable, r.nonScoreable);

  const absent = new Set(r.nonScoreable.map((n) => n.relation));
  for (const rel of ALL_RELATION_IDS) {
    // Applicability is checked FIRST, so an inapplicable relation gets the
    // diagnosis that actually explains it rather than the generic
    // missing-cell one. Both conditions would fire; only one is informative.
    if (!r.applicability[rel] && r.observedSpectrum[rel] !== 'n/a') {
      throw new ScientificResultIntegrityError(
        `${r.mutationId}: ${rel} is inapplicable and must be materialised as 'n/a', not ` +
        `${r.observedSpectrum[rel] === undefined ? 'omitted' : `scored '${r.observedSpectrum[rel]}'`}.`,
      );
    }
    const present = r.observedSpectrum[rel] !== undefined;
    const nonScoreable = absent.has(rel);
    if (present === nonScoreable) {
      throw new ScientificResultIntegrityError(
        present
          ? `${r.mutationId}: ${rel} is both scored and recorded non-scoreable.`
          : `${r.mutationId}: ${rel} has no value and no NonScoreableCell -- a cell cannot simply go missing.`,
      );
    }
  }
  // Cross-invariant between the two mechanisms, so neither becomes a second
  // source of truth for the other. NonScoreableCell explains WHY a relation
  // is absent from dom(r~); completeness only decides required/not-required.
  // The one thing that must hold jointly: a non-scoreable cell can leave no
  // outstanding obligation behind.
  for (const o of r.outstandingRequiredEvidence) {
    if (absent.has(o.relation)) {
      throw new ScientificResultIntegrityError(
        `${r.mutationId}: ${o.relation} is recorded non-scoreable yet still has outstanding required evidence ` +
        `(${o.stimulusInstanceId}) -- completeness and non-scoreability disagree about the same cell.`,
      );
    }
  }

  // Every instance must belong to this class. The intra-M_o boundary
  // (M3-H12.0) is enforced here rather than assumed downstream.
  for (const ref of r.instanceResultRefs) {
    if (!ref.startsWith(`${r.mutationId}::`)) {
      throw new ScientificResultIntegrityError(
        `${r.mutationId}: instance reference '${ref}' belongs to another class.`,
      );
    }
  }
}

export function isFullyScoreable(r: PhaseCScientificMutationResult): boolean {
  return r.nonScoreable.length === 0;
}

/**
 * The bridge back to M2, deliberately strict.
 *
 * Returns a RelationSpectrum ONLY when all six relations are materialised;
 * refuses on any NonScoreableCell; and never fills an absent cell. A partial
 * class has no M2 representation, and that is the point rather than a
 * limitation to work around.
 */
export function toRelationSpectrum(r: PhaseCScientificMutationResult): RelationSpectrum {
  if (r.nonScoreable.length > 0) {
    throw new ScientificResultIntegrityError(
      `${r.mutationId} has ${r.nonScoreable.length} non-scoreable relation(s) ` +
      `(${r.nonScoreable.map((n) => n.relation).join(', ')}); it has no RelationSpectrum, and one must not be fabricated.`,
    );
  }
  const out: Partial<Record<RelationId, RelationValue>> = {};
  for (const rel of ALL_RELATION_IDS) {
    const v = r.observedSpectrum[rel];
    if (v === undefined) {
      throw new ScientificResultIntegrityError(
        `${r.mutationId}: ${rel} is absent with no recorded cause -- refusing to complete the vector.`,
      );
    }
    out[rel] = v;
  }
  return out as RelationSpectrum;
}

/** Assembles and validates in one step, so an invalid result cannot be constructed. */
export function makePhaseCScientificResult(params: {
  readonly mutationId: string;
  readonly operation: OperationId;
  readonly gamma0Ref: string;
  readonly registryEntryHash?: string;
  readonly applicability: RelationApplicability;
  readonly observedSpectrum: PartialRelationSpectrum;
  readonly nonScoreable: readonly NonScoreableCell[];
  readonly instanceResults: readonly MutationInstanceResult[];
  readonly detectionSupport: DetectionSupport;
}): PhaseCScientificMutationResult {
  // Derived from the instances' own outstanding sets, which Core.3 already
  // computed from Required rather than from Planned. Not recomputed here:
  // one definition, one place.
  const outstandingRequiredEvidence: OutstandingEvidenceRef[] = [];
  for (const i of params.instanceResults) {
    for (const o of i.coverage.outstanding) {
      outstandingRequiredEvidence.push({ stimulusInstanceId: i.stimulusInstanceId, relation: o.relation });
    }
  }

  const result: PhaseCScientificMutationResult = {
    mutationId: params.mutationId,
    operation: params.operation,
    gamma0Ref: params.gamma0Ref,
    ...(params.registryEntryHash !== undefined ? { registryEntryHash: params.registryEntryHash } : {}),
    applicability: params.applicability,
    observedSpectrum: params.observedSpectrum,
    nonScoreable: params.nonScoreable,
    instanceResultRefs: params.instanceResults.map((i) => `${i.mutationId}::${i.stimulusInstanceId}`),
    detectionSupport: params.detectionSupport,
    requiredEvidenceComplete: outstandingRequiredEvidence.length === 0,
    outstandingRequiredEvidence,
  };
  assertScientificResultWellFormed(result);
  // Redundant with the XOR check above, and kept because it states the
  // domain identity directly rather than by implication.
  const dom = spectrumDomain(ALL_RELATION_IDS, result.nonScoreable);
  if (dom.length !== Object.keys(result.observedSpectrum).length) {
    throw new ScientificResultIntegrityError(`${params.mutationId}: dom(r~) disagrees with the spectrum's own keys.`);
  }
  return result;
}
