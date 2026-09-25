// M2.4.3 -- evidence core.
// Source: Paper_4_Experimental_Harness v0.21, §5.12 (R_byte's own scope),
// §5.13 (R_interop), §5.17 (R_cap's 'manifest' scope, its first genuine use).

import type { BackendIdentity } from '../schema/backend-identity.js';
import { backendIdentityEquals } from '../schema/backend-identity.js';

export type ObservationScope =
  | { readonly kind: 'single-backend'; readonly backend: BackendIdentity }
  | { readonly kind: 'backend-pair'; readonly from: BackendIdentity; readonly to: BackendIdentity }
  | { readonly kind: 'cross-backend-set'; readonly backends: readonly BackendIdentity[] }
  | { readonly kind: 'manifest'; readonly backend: BackendIdentity; readonly apiSurface: string };

// M3.2.1-R (M3-H1a/H1b) -- ObservationScope equality, per-variant semantics.
// Never a positional/structural deep-equal: each variant's own discriminating
// content differs.
//   - single-backend: backend identity alone.
//   - backend-pair: ORDERED. A->B != B->A -- R_interop(p,q) and R_interop(q,p)
//     are distinct scopes by design (Paper_4_Experimental_Harness v0.25/v0.26,
//     every Phase B cross-provider file: "R_interop(p->q) and R_interop(q->p)
//     are structurally distinct observations... never collapsed").
//   - manifest: the (backend, apiSurface) pair that actually discriminates it.
//   - cross-backend-set: a SET, order-independent -- {A,B,C} == {C,A,B}.
export function scopeEquals(a: ObservationScope, b: ObservationScope): boolean {
  if (a.kind !== b.kind) return false;
  switch (a.kind) {
    case 'single-backend':
      return backendIdentityEquals(a.backend, (b as typeof a).backend);
    case 'backend-pair': {
      const bb = b as typeof a;
      return backendIdentityEquals(a.from, bb.from) && backendIdentityEquals(a.to, bb.to);
    }
    case 'manifest': {
      const bb = b as typeof a;
      return backendIdentityEquals(a.backend, bb.backend) && a.apiSurface === bb.apiSurface;
    }
    case 'cross-backend-set': {
      const bSet = (b as typeof a).backends;
      if (a.backends.length !== bSet.length) return false;
      // Order-independent: every element of `a` must have a matching,
      // not-yet-consumed element in `b` (handles duplicate entries correctly,
      // unlike a naive .every(x => bSet.some(...))).
      const remaining = [...bSet];
      for (const item of a.backends) {
        const idx = remaining.findIndex((r) => backendIdentityEquals(item, r));
        if (idx === -1) return false;
        remaining.splice(idx, 1);
      }
      return true;
    }
  }
}
