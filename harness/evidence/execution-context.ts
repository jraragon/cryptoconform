// M2.4.3 -- evidence core. Represent/validate only, no evaluator logic.
// Source: Paper_4_Experimental_Harness v0.21, §5.5, Gap 1.

export type Phase = 'A' | 'B' | 'C';

// phase in {A,B} <=> kind='baseline'; phase=C <=> kind='mutation'.
// Structurally unrepresentable to have phase=C with no mutationId, or
// phase=A with a real mutationId -- the exact illegal-state class Gap 1
// (M2.2, §5.5) was designed to eliminate.
export type ExecutionContext =
  | { readonly kind: 'baseline'; readonly phase: 'A' | 'B'; readonly baselineInstanceId: string }
  | { readonly kind: 'mutation'; readonly phase: 'C'; readonly mutationId: string; readonly stimulusInstanceId: string };

// Identical shape, reused for RelationObservation (§5.5).
export type ObservationContext = ExecutionContext;

export function isBaselineContext(ctx: ExecutionContext): ctx is Extract<ExecutionContext, { kind: 'baseline' }> {
  return ctx.kind === 'baseline';
}

export function isMutationContext(ctx: ExecutionContext): ctx is Extract<ExecutionContext, { kind: 'mutation' }> {
  return ctx.kind === 'mutation';
}
