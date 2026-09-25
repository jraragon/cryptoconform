// M2.4.5 -- executability planner, part 3: observation planning.
// Source: Paper_4_Experimental_Harness v0.21, §5.9 (applicability matrix
// operates per-operation, never per-backend), §5.13 (R_interop directionality),
// §5.17 (R_cap's claim resolution, kept separate from evaluation).

import type { OperationId, CapabilityDeclarationSourceRef } from '../schema/capability.js';
import type { BackendIdentity } from '../schema/backend-identity.js';
import type { RelationApplicability, RelationId } from '../schema/registry-types.js';
import type { PlannedObservation } from '../evidence/mutation-instance-result.js';

// Applicability(o, R_i)=0 produces a STRUCTURAL ABSENCE of any planned
// observation for that relation -- never a fabricated 'n/a' entry invented
// by the planner. (n/a is the EVALUATOR's own frozen output for an
// inapplicable relation, per M2.4.4 -- the planner simply never asks.)
const ALL_RELATIONS: readonly RelationId[] = ['R_byte', 'R_interop', 'R_ser', 'R_val', 'R_err', 'R_cap'];

export interface ObservationPlanResult {
  readonly planned: readonly PlannedObservation[];
  // R_cap's own resolved claim, kept separate from evaluation (M2.4.4's
  // boundary preserved): resolution happens HERE; declared===observed does not.
  readonly capabilityClaimResolutions: ReadonlyMap<string, CapabilityDeclarationSourceRef>; // keyed by backend.sourcePin
}

export function planObservations(
  operation: OperationId,
  applicability: RelationApplicability,
  backends: readonly BackendIdentity[],
  resolveCapabilityClaimSource?: (backend: BackendIdentity) => CapabilityDeclarationSourceRef,
): ObservationPlanResult {
  const planned: PlannedObservation[] = [];
  const capabilityClaimResolutions = new Map<string, CapabilityDeclarationSourceRef>();

  for (const relation of ALL_RELATIONS) {
    if (!applicability[relation]) continue; // structural absence, not a fabricated n/a

    if (relation === 'R_interop') {
      // Directional: p->q and q->p are independent planned observations,
      // never collapsed into one -- backend-pair scope, both orderings.
      for (const from of backends) {
        for (const to of backends) {
          if (from.sourcePin === to.sourcePin) continue; // Phase A's own local round-trip, not a scored R_interop observation (§5.13)
          planned.push({ relation, scope: { kind: 'backend-pair', from, to }, executability: { kind: 'required' } });
        }
      }
      continue;
    }

    if (relation === 'R_cap') {
      // 'manifest' scope, one per backend. The CapabilityClaimRef ->
      // DeclarationSource resolution happens here; declared===observed does
      // NOT -- that stays exclusively in the R_cap evaluator (M2.4.4).
      for (const backend of backends) {
        planned.push({ relation, scope: { kind: 'manifest', backend, apiSurface: backend.apiSurface }, executability: { kind: 'required' } });
        if (resolveCapabilityClaimSource) {
          capabilityClaimResolutions.set(backend.sourcePin, resolveCapabilityClaimSource(backend));
        }
      }
      continue;
    }

    // M3-H8: R_byte's Phase C scope is CROSS-PROVIDER, not single-backend.
    //
    // The frozen design (Harness v0.26, sec:5.12) states that R_byte uses one
    // evaluator under two ObservationScope kinds, one per phase:
    //   single-backend -> Phase A: two executions of the SAME backend under
    //                     identical inputs; pure determinism.
    //   backend set    -> Phase B/C: byte equality between two DIFFERENT
    //                     backends under identical controlled inputs.
    // Phase C therefore compares Bytes(y_{p,s}) =? Bytes(y_{q,s}) for the
    // same stimulus instance -- the mutation is the common stimulus BOTH
    // providers receive, never one of the two sides of the comparison.
    //
    // The set is UNORDERED: the same source states that for R_byte direction
    // is discarded/canonicalized, while for R_interop it is part of the
    // observation's identity. Hence C(P,2) unordered sets here versus
    // P*(P-1) directed pairs there. cross-backend-set is used rather than a
    // canonicalized backend-pair because scopeEquals already compares it
    // order-independently, so {A,B} and {B,A} are the SAME scope by type
    // rather than by convention.
    if (relation === 'R_byte') {
      for (let i = 0; i < backends.length; i++) {
        for (let j = i + 1; j < backends.length; j++) {
          planned.push({
            relation,
            scope: { kind: 'cross-backend-set', backends: [backends[i]!, backends[j]!] },
            executability: { kind: 'required' },
          });
        }
      }
      continue;
    }

    // R_ser / R_val / R_err: single-backend scope, one per backend. R_ser's
    // own frozen text is explicit (v0.26 sec:5.15): unlike R_interop, its
    // primary object is a single artifact evaluated against a frozen
    // contract -- one exporter, one representation.
    for (const backend of backends) {
      planned.push({ relation, scope: { kind: 'single-backend', backend }, executability: { kind: 'required' } });
    }
  }

  return { planned, capabilityClaimResolutions };
}
