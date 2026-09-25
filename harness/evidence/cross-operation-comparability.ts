// Bloque B / M3-H12 -- cross-operation pattern comparability.
//
// This module is a CONTRACT plus the two primitives Phase C itself needs. It
// deliberately does NOT implement DetectionGain, DiagnosticGain, Keep or
// O_min: those are M5 analysis machinery, Phase C needs none of them to
// produce or validate the EvidenceBundle, and writing them here would be
// implementing the paper's analysis inside the instrument.
//
// ---------------------------------------------------------------------
// The defect, stated exactly
// ---------------------------------------------------------------------
//
// The frozen model compares patterns by literal equality of the total
// vector, r(c_i) = r(c_j), while n/a participates in that equality and
//     n/a  <=>  Applicability(R, o) = 0.
// Applicability is per-operation, so wherever two operations' masks differ
// at any position, one class has n/a there and the other does not, and
//     r(c_i) != r(c_j)
// follows with no observation whatsoever. Measured on the frozen registry:
// 11 of 15 operation pairs, and 1756 of 2577 cross-operation class pairs --
// 68% -- are decided by mask alone.
//
// HKDF is the extreme case. Its mask 100111 is shared with no operation, so
// all 8 of its classes are structurally unique against all 71 foreign
// classes: DetectionGain(HKDF) is non-empty and Keep(HKDF) holds BY
// CONSTRUCTION, before M4. The hypothesis pre-registered as "HKDF could
// legitimately disappear" is, as formalised, irrefutable.
//
// This is inherited from M0 and independent of M3-H11: it would exist
// unchanged if every class had a complete vector. And it is a matter of
// intent not carried over rather than of reasoning -- the design already
// applies the right principle at stages 1-2, where Coverage and Marginal
// compare over the shared K1/K2 taxonomy precisely "so that cross-operation
// comparisons mean the same thing". D(o) and U_D(o) cross operations
// comparing r(c), whose shape is operation-local, without that discipline.
//
// M0 is NOT modified. The correction is prospective.

import type { OperationId } from '../schema/capability.js';
import type { RelationApplicability, RelationId } from '../schema/registry-types.js';
import type { RelationValue } from './relation-spectrum.js';
import type { PhaseCScientificMutationResult } from './phase-c-scientific-result.js';
import { ALL_RELATION_IDS } from './phase-c-scientific-result.js';

/**
 * J(o_i, o_j) -- the jointly applicable relations.
 *
 * The single structural fact that repairs H12: inside J, n/a CANNOT OCCUR.
 * R in J means Applicability(R,o) = 1 on both sides, and the frozen rule
 * makes n/a exclusive to Applicability = 0. So projecting onto J removes
 * the mask from the comparison entirely rather than compensating for it.
 *
 * J is never empty: R_val, R_err and R_cap are applicable to all six
 * operations, so |J| >= 3 always (measured: 3, 4 or 6). The degenerate case
 * the remedy had to survive does not arise in this operation set -- and the
 * contract below does not rely on that, since Same() requires the full J to
 * be observed rather than merely non-empty.
 */
export function jointlyApplicable(a: RelationApplicability, b: RelationApplicability): readonly RelationId[] {
  return ALL_RELATION_IDS.filter((r) => a[r] && b[r]);
}

/**
 * S_c -- the scoreable applicable domain of a class: the relations that
 * actually yielded pass|fail. This is where M3-H11 enters the same
 * comparison, and the two restrictions compose into one set rather than
 * being applied in sequence:
 *
 *     C_ij = S_{c_i} ∩ S_{c_j}   ( ⊆ J(o_i,o_j) by construction )
 *
 * H12 removes dimensions that are not jointly APPLICABLE.
 * H11 removes dimensions that were not jointly OBSERVED.
 * Neither may fabricate an equality or a difference from a dimension that
 * is not comparable.
 */
export function scoreableDomain(r: PhaseCScientificMutationResult): readonly RelationId[] {
  const absent = new Set(r.nonScoreable.map((n) => n.relation));
  return ALL_RELATION_IDS.filter((rel) => r.applicability[rel] && !absent.has(rel));
}

export type PatternComparison = 'same' | 'different' | 'undetermined';

/**
 * The prospective replacement for r(c_i) = r(c_j).
 *
 * ASYMMETRIC ON PURPOSE, and that asymmetry is the whole content:
 *
 *   different  <=  ONE witness inside C_ij suffices. A demonstrated
 *                  difference on a jointly applicable, jointly observed
 *                  relation is real evidence.
 *
 *   same       <=  C_ij must equal the FULL jointly applicable domain J,
 *                  and agree throughout. Anything less is undetermined.
 *
 * Hence the three criteria this had to meet:
 *
 *   ApplicabilityMask alone cannot create uniqueness
 *       -- a difference must be witnessed inside C_ij, and n/a is
 *          structurally absent from J.
 *   Absence of comparable evidence cannot create equality
 *       -- 'same' demands C_ij = J, so a missing cell yields undetermined.
 *   Missing evidence cannot create exclusivity
 *       -- exclusivity consumes 'different' only, and evidence loss can
 *          only turn 'different' into 'undetermined', never the reverse.
 *
 * The last point is the monotonicity that makes the whole thing safe:
 * shrinking either S_c shrinks C_ij, which can only remove witnesses.
 */
export function comparePatterns(
  a: PhaseCScientificMutationResult,
  b: PhaseCScientificMutationResult,
): PatternComparison {
  const j = jointlyApplicable(a.applicability, b.applicability);
  const sa = new Set(scoreableDomain(a));
  const sb = new Set(scoreableDomain(b));
  const c = j.filter((r) => sa.has(r) && sb.has(r));

  for (const r of c) {
    const va = a.observedSpectrum[r] as RelationValue | undefined;
    const vb = b.observedSpectrum[r] as RelationValue | undefined;
    if (va !== undefined && vb !== undefined && va !== vb) return 'different';
  }
  return c.length === j.length ? 'same' : 'undetermined';
}

/**
 * Whether the mask ALONE could decide a comparison. Must be false for every
 * pair, by construction, and is asserted as a property rather than argued:
 * it is the single condition whose failure means H12 is not fixed.
 */
export function decidableByMaskAlone(a: RelationApplicability, b: RelationApplicability): boolean {
  // A mask-only verdict would need a position inside J where one side is
  // n/a and the other is not. J admits no n/a on either side.
  return jointlyApplicable(a, b).some(() => false);
}

/**
 * What M5 needs from the frozen dataset in order to compute the guarded
 * quantities, stated as a checkable list rather than as prose.
 *
 * Present in EvidenceBundle v2.0 for every class:
 *   operation, applicability  -> J(o_i,o_j)
 *   observedSpectrum          -> r~(c) over S_c
 *   nonScoreable              -> S_c, with the cause of every absence
 *   detectionSupport          -> Recall_R(o)
 *
 * NOT present, and required only by DiagnosticGain:
 *   Gamma_0(c)                -> sigma(c) = { kind_{K1/K2}(g) : g in Gamma_0(c) }
 *
 * gamma0Ref is "a reference to the frozen registry entry, never a copy", so
 * the bundle alone does not carry it. That is the same gap M3.1's own
 * closure requirement 3 already names as registryEntryHash, which a grep of
 * the whole tree shows does not exist anywhere yet. Recorded here, resolved
 * in the freeze block: sigma is evidence-independent, so binding the
 * registry by hash alongside the bundle is sufficient and no Gamma_0 needs
 * duplicating into every result.
 */
export const M5_DATASET_REQUIREMENTS = Object.freeze({
  satisfiedByBundle: Object.freeze([
    'operation', 'applicability', 'observedSpectrum', 'nonScoreable', 'detectionSupport',
  ]),
  requiresRegistryBinding: Object.freeze(['gamma0']),
});

export type { OperationId };
