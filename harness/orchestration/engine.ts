// M2.4.7 -- orchestration engine. Coordinates execution; does not decide
// applicability (M2.4.5), does not interpret results (M2.4.4), does not
// aggregate into MutationResult (M2.4.8).
//
// Generic over an ExecutionAdapter registered per (operation, backend) --
// NEVER dispatches on mutationId itself. The specific mutation to run
// arrives already selected as a MutationImplementation<TFixture>; this
// module only needs to know how to (a) call the real M1 adapter for that
// fixture shape and (b) turn its native EvidenceRecord into this harness's
// own ExecutionEvidence. Both of those are supplied by the CALLER
// (operation-specific wiring), never hardcoded here by mutationId.

import type { BackendIdentity } from '../schema/backend-identity.js';
import type { OperationId } from '../schema/capability.js';
import type { ExecutionEvidence } from '../evidence/execution-evidence.js';
import { makeBaselineExecution, makeMutationExecution } from '../evidence/execution-evidence.js';
import type { MutationImplementation } from '../mutations/framework.js';

export interface ExecutionAdapter<TFixture, TNativeRecord> {
  readonly operation: OperationId;
  readonly backend: BackendIdentity;
  // Calls the REAL M1 adapter (e.g. hkdfWebCrypto) -- never reimplemented here.
  readonly execute: (fixture: TFixture) => Promise<TNativeRecord>;
  // Projects the M1-native record into this harness's own ExecutionEvidence
  // fields. Operation-specific, supplied by the caller -- this is where
  // "how do I read a HkdfEvidenceRecord" lives, never inside the generic engine.
  readonly toEvidenceFields: (fixture: TFixture, record: TNativeRecord) => Pick<ExecutionEvidence, 'subject' | 'input' | 'output' | 'outcome' | 'clauseIdsEvaluated' | 'executionStatus' | 'nativeObservation'>;
}

let executionCounter = 0;
function nowIso(): string {
  return new Date().toISOString();
}

// Phase A/B <=> baseline context (Evidence Core's own invariant, M2.4.3),
// exercised here for a real execution, not just constructed in isolation.
export async function executeBaseline<TFixture, TNativeRecord>(
  phase: 'A' | 'B',
  baselineInstanceId: string,
  fixture: TFixture,
  adapter: ExecutionAdapter<TFixture, TNativeRecord>,
): Promise<ExecutionEvidence> {
  const record = await adapter.execute(fixture);
  const fields = adapter.toEvidenceFields(fixture, record);
  executionCounter += 1;
  return makeBaselineExecution(phase, baselineInstanceId, {
    operation: adapter.operation,
    provenance: { timestampIso: nowIso() },
    ...fields,
  });
}

// Phase C <=> mutation context. mutate() is called here (the ONLY place a
// MutationImplementation's own transform runs); execute() still delegates
// to the real M1 adapter -- the orchestrator itself performs no cryptography.
export async function executeMutation<TFixture, TNativeRecord>(
  mutation: MutationImplementation<TFixture>,
  stimulusInstanceId: string,
  baseFixture: TFixture,
  adapter: ExecutionAdapter<TFixture, TNativeRecord>,
): Promise<ExecutionEvidence> {
  const mutatedFixture = mutation.mutate(baseFixture, stimulusInstanceId);
  const record = await adapter.execute(mutatedFixture);
  const fields = adapter.toEvidenceFields(mutatedFixture, record);
  executionCounter += 1;
  return makeMutationExecution(mutation.mutationId, stimulusInstanceId, {
    operation: adapter.operation,
    provenance: { timestampIso: nowIso() },
    ...fields,
  });
}

export function resetExecutionCounterForTests(): void {
  executionCounter = 0;
}
export function getExecutionCount(): number {
  return executionCounter;
}
