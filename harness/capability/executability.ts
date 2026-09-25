// M2.4.5 -- executability planner, part 2: Executable(p,s).
// Source: Paper_4_Experimental_Harness v0.21, §8.4 (formula), §9.3
// (per-instance granularity -- the exact reason the unit here is
// (mutationId, stimulusInstanceId, backend), never just (mutationId, backend)).

import type { BackendIdentity } from '../schema/backend-identity.js';
import type { ProviderCapabilityDeclaration } from '../schema/capability.js';
import type { StimulusCapabilityRequirement } from '../requirements/stimulus-requirements.js';
import { resolveRequirement, type CapabilityRequirementResolution } from './requirement-resolution.js';

export type ExecutabilityDecision =
  | {
      readonly status: 'executable';
      readonly backend: BackendIdentity;
      readonly satisfiedRequirements: readonly CapabilityRequirementResolution[];
    }
  | {
      readonly status: 'not-executed';
      readonly reason: 'backend-capability-absent';
      readonly backend: BackendIdentity;
      readonly unsatisfiedRequirements: readonly CapabilityRequirementResolution[];
    };

// Executable(p,s) = AND over kappa in Requirements(s) of Satisfies(A_p^pre, kappa).
// Unit of decision: (mutationId, stimulusInstanceId, backend) -- a
// requirement with no stimulusInstanceId applies to every instance of that
// mutation; one WITH a stimulusInstanceId applies only to that instance
// (GCM's own three tag-length rows, §9.3).
export function decideExecutability(
  mutationId: string,
  stimulusInstanceId: string,
  backend: BackendIdentity,
  declarations: readonly ProviderCapabilityDeclaration[],
  allRequirements: readonly StimulusCapabilityRequirement[],
): ExecutabilityDecision {
  const applicable = allRequirements.filter(
    (r) => r.mutationId === mutationId && (r.stimulusInstanceId === undefined || r.stimulusInstanceId === stimulusInstanceId),
  );

  // No capability gate at all for this stimulus -- trivially executable.
  if (applicable.length === 0) {
    return { status: 'executable', backend, satisfiedRequirements: [] };
  }

  const resolutions = applicable.map((r) => resolveRequirement(r, declarations));
  const unsatisfied = resolutions.filter((r) => !r.satisfied);

  if (unsatisfied.length > 0) {
    return { status: 'not-executed', reason: 'backend-capability-absent', backend, unsatisfiedRequirements: unsatisfied };
  }
  return { status: 'executable', backend, satisfiedRequirements: resolutions };
}
