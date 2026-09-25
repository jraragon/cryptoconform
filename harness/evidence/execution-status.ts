// M2.4.3 -- evidence core.
// Source: Paper_4_Experimental_Harness v0.21, §10.4 (ExecutionEvidence),
// §9-10 (NonExecution reasons, provider-cap-manifest work).

// A contractual rejection is not an execution failure (§5.15):
// executionStatus='completed' must coexist with outcome={kind:'reject',...}.
export type ExecutionStatus = 'completed' | 'harness-error' | 'environment-error' | 'timeout';

// n/a says "the obligation does not exist here"; not-executed says "the
// obligation exists but this scope cannot materialize the stimulus" (§5.2,
// Gap 2). Reason is structured, never a free-text string.
export interface NonExecution {
  readonly state: 'not-executed';
  readonly reason: 'stimulus-not-expressible' | 'backend-capability-absent' | 'direction-not-materializable';
}

// The internal, five-state vocabulary (§5.13): only 'conformant'/'divergent'/
// 'n/a' may cross into the scored pass/fail/n-a boundary. 'not-executed' and
// 'insufficient-evidence' are absorbed into coverage/detection-support
// bookkeeping and must never leak into a RelationSpectrum cell.
export type ObservationState = 'conformant' | 'divergent' | 'n/a' | 'not-executed' | 'insufficient-evidence';
