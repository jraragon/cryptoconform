// M2.4.3 -- evidence core. Structural assembly only.
// Source: Paper_4_Experimental_Harness v0.21, §5.5 (Gap 3 fix).
// One MutationResult per causal class c -- matching M_o's own granularity
// (D-052: diagnostic hypothesis H(c|r) operates over the class set M_o, not
// over instances). This is why MutationResult carries NEITHER
// stimulusInstanceId NOR any backend identity: those belong to
// MutationInstanceResult and RelationObservation.scope respectively.
//
// The actual fail-dominant/existential DERIVATION of observedSpectrum from
// raw instance results is M2.4.7's own scientific-aggregation deliverable.
// This factory only assembles an already-computed spectrum and enforces the
// structural invariants (no evaluator logic here).

import type { OperationId } from '../schema/capability.js';
import type { RelationApplicability, ExpectedSpectrum } from '../schema/registry-types.js';
import type { RelationSpectrum } from './relation-spectrum.js';
import type { MutationInstanceResult } from './mutation-instance-result.js';

export interface DetectionSupport {
  readonly divergentInstances: number;
  readonly evaluatedInstances: number;
}

// Deliberately: no stimulusInstanceId, no backend field anywhere in this type.
export interface MutationResult {
  readonly mutationId: string;
  readonly operation: OperationId;
  readonly gamma0Ref: string; // reference to the frozen registry entry, never a copy
  /**
   * M3.3 -- binds this result to the CONTENT of its registry entry, so a
   * later registry change cannot be silently absorbed. gamma0Ref names the
   * entry; this proves which entry it was.
   */
  readonly registryEntryHash?: string;
  readonly applicability: RelationApplicability;
  readonly expectedSpectrum: ExpectedSpectrum;
  readonly instanceResultRefs: readonly string[]; // mutationId+stimulusInstanceId pairs, by reference
  readonly observedSpectrum: RelationSpectrum;
  readonly detectionSupport: DetectionSupport;
  readonly complete: boolean;
}

function instanceRef(r: MutationInstanceResult): string {
  return `${r.mutationId}::${r.stimulusInstanceId}`;
}

export function makeMutationResult(params: {
  readonly mutationId: string;
  readonly operation: OperationId;
  readonly gamma0Ref: string;
  readonly registryEntryHash?: string;
  readonly applicability: RelationApplicability;
  readonly expectedSpectrum: ExpectedSpectrum;
  readonly instanceResults: readonly MutationInstanceResult[];
  readonly observedSpectrum: RelationSpectrum; // supplied by M2.4.7's own aggregation, not derived here
  readonly detectionSupport: DetectionSupport;
}): MutationResult {
  // complete(c) = AND over all instance results' own completeness (§5.3's
  // completeness gate, restated at the class level -- structural only).
  const complete = params.instanceResults.every((r) => r.complete);
  return {
    mutationId: params.mutationId,
    operation: params.operation,
    gamma0Ref: params.gamma0Ref,
    ...(params.registryEntryHash !== undefined ? { registryEntryHash: params.registryEntryHash } : {}),
    applicability: params.applicability,
    expectedSpectrum: params.expectedSpectrum,
    instanceResultRefs: params.instanceResults.map(instanceRef),
    observedSpectrum: params.observedSpectrum,
    detectionSupport: params.detectionSupport,
    complete,
  };
}
