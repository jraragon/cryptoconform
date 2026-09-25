// M2.4.3 -- evidence core.
// Source: Paper_4_Experimental_Harness v0.21, §5.13.
// Only pass/fail/n-a may ever appear here -- not-executed and
// insufficient-evidence are ObservationStates, never RelationValues.

export type RelationValue = 'pass' | 'fail' | 'n/a';

export interface RelationSpectrum {
  readonly R_byte: RelationValue;
  readonly R_interop: RelationValue;
  readonly R_ser: RelationValue;
  readonly R_val: RelationValue;
  readonly R_err: RelationValue;
  readonly R_cap: RelationValue;
}

// The only legal boundary-crossing conversions (§5.13):
// conformant -> pass, divergent -> fail, n/a -> n/a.
import type { ObservationState } from './execution-status.js';

export function toRelationValue(state: ObservationState): RelationValue | undefined {
  switch (state) {
    case 'conformant': return 'pass';
    case 'divergent': return 'fail';
    case 'n/a': return 'n/a';
    case 'not-executed':
    case 'insufficient-evidence':
      return undefined; // deliberately: these must never cross into a RelationSpectrum cell
  }
}
