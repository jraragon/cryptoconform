// M3.9-A -- the capability evidence acquisition contract, in code.
//
// The normative decisions of M3.9-CAPABILITY-EVIDENCE-CONTRACT.md, expressed
// so they are checkable rather than only readable. NO DATA and NO ACQUISITION
// live here: no manifest entry, no probe, no execution. Those are M3.9-B.
//
// The defect this closes was invisible for three milestones because
// makeResolve obtained both evidences from one adapter called twice. That
// satisfies the frozen invariant literally --
//
//     id(E_declaration) != id(E_scored)
//
// -- and not what it exists to protect:
//
//     source(E_declaration) != source(E_scored)
//
// Two identities of one mechanism are not two sources.

import type { CapabilityDomainSpec, ObservedCapabilityState } from '../schema/capability.js';

export class CapabilityContractError extends Error {}

/** The taxonomy M2.2 declared and deferred, materialised here at last. */
export type CapabilityEvidenceKind = 'runtime-probe' | 'api-surface-inspection' | 'operation-execution';

export type CapabilityClaimKind = ObservedCapabilityState['kind'];

/**
 * D1. ADOPTED AS A PROSPECTIVE M3.9 DECISION, not inherited.
 *
 * No frozen artifact states this function. The names suggest it strongly, and
 * semantic naturalness is not a normative rule -- so it is recorded as a
 * decision taken at N_scored = 0, with its reason, rather than presented as
 * something that was always implicit.
 *
 * The unit of decision is the KIND: three rows, not 256 choices.
 */
export const PROBE_KIND_BY_CLAIM_KIND: Readonly<Record<CapabilityClaimKind, {
  readonly probeKind: CapabilityEvidenceKind;
  readonly why: string;
}>> = Object.freeze({
  'interface-exposure': {
    probeKind: 'api-surface-inspection',
    why: 'The claim is that a surface exists; the independent check is whether it is there.',
  },
  'portable-boundary': {
    probeKind: 'operation-execution',
    why: 'The claim is which inputs are admitted; only running the operation reveals admission or refusal.',
  },
  'provider-support': {
    probeKind: 'runtime-probe',
    why: 'The claim is that the provider supports something; the independent check exercises it at run time.',
  },
});

export function probeKindFor(kind: CapabilityClaimKind): CapabilityEvidenceKind {
  const row = PROBE_KIND_BY_CLAIM_KIND[kind];
  if (row === undefined) {
    throw new CapabilityContractError(
      `No probe kind is fixed for claim kind '${kind}'. Refusing rather than choosing one during execution.`,
    );
  }
  return row.probeKind;
}

// ---------------------------------------------------------------------
// D2' -- SUPERSEDED by the frozen rule (M2.3.4)
//
// M3.9-A defined three admissible provenances and excluded 'execution-derived'
// by construction, on the reasoning that a declaration obtained by running the
// backend cannot then be checked against that backend.
//
// THE FROZEN MODEL SAYS THE OPPOSITE, and it is the authority:
//
//     Evidence_declaration(k,p)  ∩  Evidence_scored(k,p)  =  ∅
//
//     "The intersection is over concrete evidence identity, never over
//      abstract mechanism. [...] both 'run HKDF,' and that shared mechanism
//      is not itself a violation."
//
// The legitimate pattern M2.3 practices throughout is precisely
// execution-derived:
//
//     M1 execution     -> manifest declaration
//     fresh M4 execution -> observed capability
//
// So a declaration MAY derive from an execution. What is forbidden is one
// identical ExecutionID serving as both the declared basis and the scored
// observation.
//
// D2 is therefore withdrawn, not weakened: it forbade something legitimate,
// which is the worse kind of error because it reads as caution.

// ---------------------------------------------------------------------
// D3 -- absence is not a negative declaration
// ---------------------------------------------------------------------

/**
 * The frozen schema is untouched: `support` stays supported | unsupported and
 * gains no 'unknown'. What is separated is the VALUE of a declaration from
 * the EXISTENCE of one.
 *
 * `None` means "we hold no contrastable declaration". It is NOT
 * { support: 'unsupported' }: turning silence into an assertion would decide
 * the comparison's outcome for provider-support, where the two states ARE the
 * comparison.
 */
export type DeclarationLookup<T> = { readonly kind: 'some'; readonly declaration: T } | { readonly kind: 'none' };

export function isDeclared<T>(lookup: DeclarationLookup<T>): lookup is { kind: 'some'; declaration: T } {
  return lookup.kind === 'some';
}

// ---------------------------------------------------------------------
// D4/D5 -- comparison
// ---------------------------------------------------------------------

/** D4. Both binary kinds compare directly, state against state. */
export function compareBinaryClaim(
  declared: { readonly state: string }, observed: { readonly state: string },
): 'pass' | 'fail' {
  return declared.state === observed.state ? 'pass' : 'fail';
}

/**
 * D5.1 -- which domain specs admit a decidable membership.
 *
 * Four of the five do. `coupled-parameters` carries `constraints:
 * readonly string[]` -- free text, with no evaluator anywhere in the tree --
 * so x ∈ D is not mechanically decidable for it, and a portable-boundary
 * claim may not use it under this contract. Improvising the comparison at run
 * time is exactly what this remediation exists to prevent, and inventing a
 * constraint language would be design, not materialisation.
 */
export function domainMembershipIsDecidable(spec: CapabilityDomainSpec): boolean {
  return spec.kind !== 'coupled-parameters';
}

export function assertDomainUsableForBoundaryClaim(spec: CapabilityDomainSpec): void {
  if (!domainMembershipIsDecidable(spec)) {
    throw new CapabilityContractError(
      `A portable-boundary claim cannot use a '${spec.kind}' domain: membership is not mechanically decidable, ` +
      'so Expected_D(x) would have to be improvised during execution.',
    );
  }
}

/** D5. Expected_D(x), once membership is decidable. */
export function expectedBoundaryState(inDomain: boolean): 'allowed' | 'forbidden' {
  return inDomain ? 'allowed' : 'forbidden';
}

// ---------------------------------------------------------------------
// D7' -- the frozen independence rule, and the two backend rules with it
// ---------------------------------------------------------------------

export interface CapabilityEvidenceRefs {
  /** ExecutionIDs the manifest cell's basis rests on. */
  readonly declarationEvidenceIds: readonly string[];
  /** ExecutionIDs the scored observation rests on. */
  readonly scoredEvidenceIds: readonly string[];
}

/**
 * The frozen rule, verbatim in effect: disjointness over CONCRETE EVIDENCE
 * IDENTITY, never over abstract mechanism.
 *
 * M3.9-A's own D7 added a second invariant requiring the SOURCES to differ,
 * and asserted it was what the first existed to protect. That was wrong
 * against the freeze, which resolves the shared-mechanism case explicitly in
 * favour of legitimacy. This function therefore checks disjointness of
 * identities and nothing else -- a declaration derived from an M1 execution
 * and a probe derived from a fresh M4 execution of the same operation are
 * legitimate, and must not be refused.
 */
export function assertEvidenceDisjoint(refs: CapabilityEvidenceRefs): void {
  const scored = new Set(refs.scoredEvidenceIds);
  const shared = refs.declarationEvidenceIds.filter((id) => scored.has(id));
  if (shared.length > 0) {
    throw new CapabilityContractError(
      `Execution ${shared[0]} serves as both declared basis and scored observation. A single identical ExecutionID ` +
      'on both sides makes R_cap tautological by construction.',
    );
  }
}

/**
 * Manifest.backend = ExecutionEvidence.subject.backend over the FULL
 * structural tuple, never family alone (M2.3.4).
 */
export function assertBackendComparability(
  manifestBackend: { family: string; apiVersion: string; sourcePin: string; apiSurface: string },
  evidenceBackend: { family: string; apiVersion: string; sourcePin: string; apiSurface: string },
): void {
  for (const f of ['family', 'apiVersion', 'sourcePin', 'apiSurface'] as const) {
    if (manifestBackend[f] !== evidenceBackend[f]) {
      throw new CapabilityContractError(
        `Manifest backend differs from the evidence's at '${f}': '${manifestBackend[f]}' vs ` +
        `'${evidenceBackend[f]}'. Comparability is the full tuple, never family alone.`,
      );
    }
  }
}

/**
 * Basis.backendPin must be compatible with Manifest.backend.sourcePin for any
 * pin-specific basis (M2.3.4).
 *
 * The rule generalises a real case: pss.provider.explicit-salt-bytes is valid
 * for Bouncy Castle only because the pinned jar falls within D-042's scope --
 * not because "Bouncy Castle" as a library supports it.
 */
export function assertBasisPinCompatible(params: {
  readonly basisKind: string;
  readonly basisBackendPin?: string;
  readonly manifestSourcePin: string;
}): void {
  const pinSpecific = params.basisKind === 'backend-documentation';
  if (!pinSpecific) return;
  if (params.basisBackendPin === undefined) {
    throw new CapabilityContractError(
      'A backend-documentation basis must name the pin it was read against; a library-wide claim is not a ' +
      'declaration about the pinned artifact.',
    );
  }
  if (params.basisBackendPin !== params.manifestSourcePin) {
    throw new CapabilityContractError(
      `Basis pin '${params.basisBackendPin}' is not the manifest's '${params.manifestSourcePin}'.`,
    );
  }
}
