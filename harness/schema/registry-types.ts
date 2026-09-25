// M2.4.2 -- static materialization only. No behavior here.
// Source: Paper_4_Experimental_Harness v0.21, §2 (M2.1 registry), §5.8-5.9
// (applicability matrix), §5.6 (ExpectedRelationSpec).

import type { ClauseId, OperationId } from './capability.js';

export type MutationId = string;

export type RelationId = 'R_byte' | 'R_interop' | 'R_ser' | 'R_val' | 'R_err' | 'R_cap';

// Frozen boundary/interface/applicability facts, never derived at runtime.
export interface RelationApplicability {
  readonly R_byte: boolean;
  readonly R_interop: boolean;
  readonly R_ser: boolean;
  readonly R_val: boolean;
  readonly R_err: boolean;
  readonly R_cap: boolean;
}

// §5.6: prediction, not observation. Kept structurally distinct from the
// pass/fail/n-a vocabulary that only observed data may use.
export type ExpectedDetection = 'detect' | 'not-expected' | 'conditional' | 'n/a';

export interface ExpectedRelationSpec {
  readonly expectation: ExpectedDetection;
  readonly condition?: string;
}

export interface ExpectedSpectrum {
  readonly R_byte: ExpectedRelationSpec;
  readonly R_interop: ExpectedRelationSpec;
  readonly R_ser: ExpectedRelationSpec;
  readonly R_val: ExpectedRelationSpec;
  readonly R_err: ExpectedRelationSpec;
  readonly R_cap: ExpectedRelationSpec;
}

// A single pre-registered stimulus instance under a mutation class.
// mutationId != stimulusInstanceId, and one class may have several
// (§7.2: CapabilityID != StimulusInstanceID, applied identically here to
// mutation classes, e.g. GCM-TAGLENGTH-PROFILE-BOUNDARY-BYPASS's 3 stimuli).
export interface StimulusInstanceDescriptor {
  readonly stimulusInstanceId: string;
  readonly description: string;
}

// M2.4.6a correction: Gamma_0(c) is "the set of clauses an intervention may
// perturb", not "the physical DTO fields that must change". Different
// classes act on genuinely different experimental state -- a request, an
// adapter-invocation choice, or a capability declaration -- never forced
// into one shape. Reclassifying entries with this tag changes neither
// Gamma_0 nor mutationId for any class; it is metadata, not a redesign.
// Not yet claimed exhaustive -- audited per-family as each is implemented.
export type MutationMechanism =
  | 'request-transform'
  | 'adapter-transform'
  | 'capability-transform'
  | 'artifact-transform';

// Metadata only -- no mutate() body. That is M2.4.6's own deliverable.
export interface MutationRegistryEntry {
  readonly mutationId: MutationId;
  readonly operation: OperationId;
  readonly gamma0: readonly ClauseId[]; // reference by clause ID, never copied as editable truth
  readonly mechanism: MutationMechanism; // first-pass classification, M2.4.6a
  readonly expectedSpectrum: ExpectedSpectrum;
  readonly stimulusInstances: readonly StimulusInstanceDescriptor[];
  readonly notes?: string;
}
