// M2.4.3 -- evidence core. Represent/validate only.
// Source: Paper_4_Experimental_Harness v0.21, §5.5.

import type { ExecutionContext } from './execution-context.js';
import type { ExecutionStatus } from './execution-status.js';
import type { BackendIdentity } from '../schema/backend-identity.js';
import type { OperationId, ClauseId } from '../schema/capability.js';

export interface EvidencePayload {
  readonly kind: string;
  readonly bytes?: string; // hex or base64, opaque to this layer
  readonly value?: unknown;
}

export interface ExecutionEvidence {
  readonly executionId: string;
  readonly operation: OperationId;
  readonly context: ExecutionContext;
  readonly subject: {
    readonly backend: BackendIdentity;
    readonly direction: 'encrypt' | 'decrypt' | 'sign' | 'verify' | 'import' | 'export' | 'derive';
    readonly path: 'sdk' | 'native';
  };
  readonly input: EvidencePayload;
  readonly output?: EvidencePayload;
  readonly outcome: { readonly kind: string; readonly detail?: string };
  readonly clauseIdsEvaluated: readonly ClauseId[];
  readonly nativeObservation?: {
    readonly exceptionType?: string;
    readonly exceptionMessage?: string;
    readonly nativeReturnCode?: string | number | boolean;
  };
  readonly executionStatus: ExecutionStatus;
  readonly provenance: { readonly timestampIso: string };
}

let executionCounter = 0;
function nextExecutionId(prefix: string): string {
  executionCounter += 1;
  return `${prefix}-${executionCounter}`;
}

type CommonExecutionFields = Omit<ExecutionEvidence, 'executionId' | 'context'>;

// Illegal-by-construction: this factory can ONLY produce phase in {A,B}
// paired with kind='baseline'. There is no parameter combination that
// yields phase='C' here.
export function makeBaselineExecution(
  phase: 'A' | 'B',
  baselineInstanceId: string,
  fields: CommonExecutionFields,
): ExecutionEvidence {
  return {
    executionId: nextExecutionId('exec'),
    context: { kind: 'baseline', phase, baselineInstanceId },
    ...fields,
  };
}

// Illegal-by-construction: this factory can ONLY produce phase='C' paired
// with kind='mutation' and both a mutationId and a stimulusInstanceId.
export function makeMutationExecution(
  mutationId: string,
  stimulusInstanceId: string,
  fields: CommonExecutionFields,
): ExecutionEvidence {
  return {
    executionId: nextExecutionId('exec'),
    context: { kind: 'mutation', phase: 'C', mutationId, stimulusInstanceId },
    ...fields,
  };
}
