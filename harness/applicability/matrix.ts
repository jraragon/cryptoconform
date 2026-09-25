// M2.4.2 -- static materialization only.
// Source: Paper_4_Experimental_Harness v0.21, §5.9 (audited against v0.6 +
// M1's executed evidence). 36 cells, 6 operations x 6 relations.

import type { OperationId } from '../schema/capability.js';
import type { RelationApplicability } from '../schema/registry-types.js';

export const APPLICABILITY_MATRIX: Readonly<Record<OperationId, RelationApplicability>> =
  Object.freeze({
    hkdf: Object.freeze({ R_byte: true, R_interop: false, R_ser: false, R_val: true, R_err: true, R_cap: true }),
    gcm: Object.freeze({ R_byte: true, R_interop: true, R_ser: true, R_val: true, R_err: true, R_cap: true }),
    oaep: Object.freeze({ R_byte: false, R_interop: true, R_ser: false, R_val: true, R_err: true, R_cap: true }),
    pss: Object.freeze({ R_byte: false, R_interop: true, R_ser: false, R_val: true, R_err: true, R_cap: true }),
    'rsa-ser': Object.freeze({ R_byte: true, R_interop: true, R_ser: true, R_val: true, R_err: true, R_cap: true }),
    'ec-ser': Object.freeze({ R_byte: true, R_interop: true, R_ser: true, R_val: true, R_err: true, R_cap: true }),
  });

// Notes preserved from §5.9, not encoded as booleans (they are necessity/
// taxonomy facts, not applicability facts -- conflating them was the exact
// error §5.9 catches for AES-GCM's and RSA-PSS's own R_err cells):
//  - GCM.R_err = true structurally, but its NECESSITY as a distinct relation
//    is separately flagged "provisional pending necessity" (stage 3-4, D-066).
//  - PSS.R_err = true structurally; PSS's error TAXONOMY is merely narrower
//    than OAEP's (3 vs 4 classes) -- a K2/taxonomy fact, not an applicability one.
