// M2.4.5 -- executability planner, part 1: requirement resolution.
// Source: Paper_4_Experimental_Harness v0.21, §8.4-9.3.
// No backend/mutationId branching anywhere -- all differences emerge from
// Requirement + Manifest data alone.

import type { ProviderCapabilityDeclaration } from '../schema/capability.js';
import type { StimulusCapabilityRequirement, ProviderCapabilityCondition } from '../requirements/stimulus-requirements.js';

export class HarnessIntegrityError extends Error {}

export interface CapabilityRequirementResolution {
  readonly requirement: StimulusCapabilityRequirement;
  readonly declaration: ProviderCapabilityDeclaration;
  readonly satisfied: boolean;
}

// Enforces: for all r, for all p, exists exactly one d : d.capabilityId = r.capabilityId
// BEFORE evaluating requiredCondition. Zero or multiple matches is a harness
// integrity error -- never 'not-executed'.
export function resolveDeclaration(
  requirement: StimulusCapabilityRequirement,
  declarations: readonly ProviderCapabilityDeclaration[],
): ProviderCapabilityDeclaration {
  const matches = declarations.filter((d) => d.capabilityId === requirement.capabilityId);
  if (matches.length === 0) {
    throw new HarnessIntegrityError(
      `Requirement references capabilityId '${requirement.capabilityId}' (mutation ${requirement.mutationId}), ` +
      'but no declaration with that id exists in the manifest. This is a harness integrity error, not a not-executed case.',
    );
  }
  if (matches.length > 1) {
    throw new HarnessIntegrityError(
      `capabilityId '${requirement.capabilityId}' has ${matches.length} declarations in the manifest -- ` +
      'must be exactly one. This is a harness integrity error.',
    );
  }
  return matches[0]!;
}

// Satisfies(A_p^pre, kappa) -- the frozen condition engine. Exactly the
// three condition kinds that exist in v0.21, nothing GCM-specific,
// nothing PSS-specific: 80 in Domain_BC falls out of 'domain-includes'
// naturally, the same code path used for every other domain-typed capability.
export function satisfies(decl: ProviderCapabilityDeclaration, condition: ProviderCapabilityCondition): boolean {
  switch (condition.kind) {
    case 'supported':
    case 'control-available':
      return decl.kind === 'provider-support' && decl.support === 'supported';
    case 'domain-includes':
      return decl.kind === 'provider-domain'
        && decl.supportedDomain.kind === 'integer-set'
        && decl.supportedDomain.values.includes(condition.value as number);
  }
}

export function resolveRequirement(
  requirement: StimulusCapabilityRequirement,
  declarations: readonly ProviderCapabilityDeclaration[],
): CapabilityRequirementResolution {
  const declaration = resolveDeclaration(requirement, declarations);
  return { requirement, declaration, satisfied: satisfies(declaration, requirement.requiredCondition) };
}
