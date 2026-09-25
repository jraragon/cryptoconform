// M2.4.3 -- evidence core.
// Source: Paper_4_Experimental_Harness v0.21, §5.7.
// Phase A/B never produces a Gamma_0-attributed result: no mutationId,
// no Gamma_0 reference, never contributes to r(c).

import type { OperationId } from '../schema/capability.js';

export interface BaselineResult {
  readonly baselineInstanceId: string;
  readonly phase: 'A' | 'B';
  readonly operation: OperationId;
  readonly observations: readonly string[]; // RelationObservation.observationId refs
  readonly complete: boolean;
}
