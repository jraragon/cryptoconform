// M3.9-B -- capability claim resolution and scored acquisition.
//
// The two mechanisms R_cap needed and never had:
//
//   resolveCapabilityClaimSource   planObservations has taken this parameter
//                                  since M2.4.5 and nobody ever supplied it,
//                                  so the branch never ran and the 256 R_cap
//                                  obligations carried no claims at all.
//   acquireObservedCapability      the scored side. D1 fixes the probe kind
//                                  from the claim kind; all thirteen frozen
//                                  declarations are provider-support, so
//                                  'runtime-probe' is the only kind any claim
//                                  exercises.
//
// --- Independence, as the freeze states it -------------------------------
//
//     Evidence_declaration(κ,p) ∩ Evidence_scored(κ,p) = ∅
//
// over CONCRETE EVIDENCE IDENTITY, never over abstract mechanism. A
// declaration grounded in an M1 execution and a probe grounded in a fresh M4
// execution of the same operation are legitimate -- that is the pattern
// M2.3.3b-II practices throughout. What is forbidden is one identical
// ExecutionID on both sides.

import type { BackendIdentity } from '../schema/backend-identity.js';
import type { OperationId } from '../schema/capability.js';
import type { ObservedCapabilityState } from '../schema/capability.js';
import { assertBackendComparability, assertBasisPinCompatible, assertEvidenceDisjoint, probeKindFor, type CapabilityEvidenceKind } from './evidence-contract.js';
import { cellFor, rCapClaimsFor, type FrozenCell, type FrozenDeclaration } from './frozen-manifest.js';

export class AcquisitionError extends Error {}

/** A claim: one frozen declaration, scoped to one backend. */
export interface ResolvedClaim {
  readonly capabilityId: string;
  readonly operation: OperationId;
  readonly backend: BackendIdentity;
  readonly declaration: FrozenDeclaration;
  readonly cell: FrozenCell;
  readonly probeKind: CapabilityEvidenceKind;
}

/**
 * The resolver planObservations has always accepted and never received.
 *
 * Fail-closed by construction: it reads the CLOSED inventory, so a claim that
 * is not in the thirteen cannot be produced, and a backend with no cell
 * refuses rather than defaulting.
 */
export function resolveClaims(operation: OperationId, backend: BackendIdentity): readonly ResolvedClaim[] {
  return rCapClaimsFor(operation).map((declaration) => {
    const cell = cellFor(declaration.capabilityId, backend);
    // Pin compatibility, for the bases that are pin-specific.
    assertBasisPinCompatible({
      basisKind: cell.basisKind,
      basisBackendPin: cell.basisKind === 'backend-documentation' ? backend.sourcePin : undefined,
      manifestSourcePin: backend.sourcePin,
    });
    return {
      capabilityId: declaration.capabilityId,
      operation,
      backend,
      declaration,
      cell,
      // provider-domain is a schema refinement of provider-support for R_cap's
      // own space, so its probe kind is that of the kind R_cap sees.
      probeKind: probeKindFor('provider-support'),
    };
  });
}

/** The declared side, read from the frozen cell. Never probed. */
export function declaredState(claim: ResolvedClaim): ObservedCapabilityState | undefined {
  if (claim.cell.support === undefined) return undefined; // a domain cell has no binary state
  return { kind: 'provider-support', state: claim.cell.support };
}

export interface ScoredCapabilityEvidence {
  readonly executionId: string;
  readonly backend: BackendIdentity;
  readonly observed: ObservedCapabilityState;
  readonly probeKind: CapabilityEvidenceKind;
}

/**
 * Contrasts a claim against a scored observation, enforcing the three frozen
 * rules before comparing anything.
 *
 * The declaration's basis evidence ids are passed in so disjointness is
 * checked over identity -- the only sense the freeze admits.
 */
export function contrastClaim(params: {
  readonly claim: ResolvedClaim;
  readonly declarationEvidenceIds: readonly string[];
  readonly scored: ScoredCapabilityEvidence;
}): 'pass' | 'fail' {
  const { claim, scored } = params;
  assertBackendComparability(claim.backend, scored.backend);
  assertEvidenceDisjoint({
    declarationEvidenceIds: params.declarationEvidenceIds,
    scoredEvidenceIds: [scored.executionId],
  });
  if (scored.probeKind !== claim.probeKind) {
    throw new AcquisitionError(
      `${claim.capabilityId}: the scored evidence was acquired as '${scored.probeKind}' but the claim's kind ` +
      `fixes '${claim.probeKind}'. The probe kind is decided by the claim, never by what was convenient to run.`,
    );
  }
  const declared = declaredState(claim);
  if (declared === undefined) {
    throw new AcquisitionError(
      `${claim.capabilityId}: this cell declares a domain, not a binary state; a domain claim is contrasted by ` +
      'membership, not by state equality.',
    );
  }
  return declared.state === scored.observed.state ? 'pass' : 'fail';
}

/** Every claim of every operation on every backend. For the coverage gate. */
export function allResolvedClaims(
  operations: readonly OperationId[], backends: readonly BackendIdentity[],
): readonly ResolvedClaim[] {
  return operations.flatMap((o) => backends.flatMap((b) => resolveClaims(o, b)));
}
