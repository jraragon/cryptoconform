// Bloque A -- a class that produced no scientific result at all.
//
// This replaces `unscoredClasses.reason`, which carried an exception message
// as if it were science. A machine-readable cause must never depend on the
// text of a thrown error: the text can change with a refactor, and no
// consumer can branch on it without coupling to wording.
//
// Its meaning also NARROWED in Bloque A, and the narrowing is the point.
// Before Core.2, a class reached this collection whenever any applicable
// relation had zero executable support -- which is not an omission at all
// but a per-relation fact, now recorded as a NonScoreableCell while the
// class keeps its other relations. What remains here is only the genuine
// case: the class produced nothing.
//
//     NonScoreableCell   a RELATION of a class has no scoreable result
//     OmittedClass       the CLASS produced no result whatsoever
//
// Keeping the two apart is what lets the frozen dataset distinguish
// deliberately-not-scoreable from lost.

import type { OperationId } from '../schema/capability.js';

export type ClassOmissionReason =
  /** The harness failed while processing the class. Never a scientific outcome. */
  | 'harness-error'
  /** The class was in the plan but never reached aggregation. */
  | 'not-reached';

export interface OmittedClass {
  readonly mutationId: string;
  readonly operation: OperationId;
  readonly reason: ClassOmissionReason;
  /** Free-text diagnostic. Useful to a human, never branched on. */
  readonly diagnostic?: string;
}
