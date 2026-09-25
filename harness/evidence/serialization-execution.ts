// M3.7.2 -- serialization execution, extracted to neutral infrastructure.
//
// Behaviour-preserving extraction, NOT a reimplementation. This transformation
// was written and validated for the M3.5 dry run and now also serves the
// production binder, so the productive path no longer depends conceptually on
// dry-run.ts. Both callers use THIS function; dry-run.ts re-exports it so the
// dry run's own behaviour is byte-identical to what M3.5 validated.
//
// Call shape and identity only. It records WHAT the M1 function returned; it
// does not judge it. Deciding what a return MEANS is R_ser's and R_interop's
// job, settled in C1 and C3.

import { makeMutationExecution } from './execution-evidence.js';
import type { ExecutionEvidence } from './execution-evidence.js';
import type { BackendIdentity } from '../schema/backend-identity.js';
import type { OperationId } from '../schema/capability.js';

export interface SerializationCallResult {
  readonly ok: boolean;
  readonly artifactHex?: string;
  readonly errorClass?: string;
  readonly detail?: string;
  readonly extra?: Readonly<Record<string, unknown>>;
}

export function wrapSerializationExecution(params: {
  readonly operation: OperationId;
  readonly backend: BackendIdentity;
  readonly direction: 'export' | 'import';
  readonly mutationId: string;
  readonly stimulusInstanceId: string;
  readonly inputKind: string;
  readonly result: SerializationCallResult;
}): ExecutionEvidence {
  const { result } = params;
  return makeMutationExecution(params.mutationId, params.stimulusInstanceId, {
    operation: params.operation,
    subject: { backend: params.backend, direction: params.direction, path: 'native' },
    input: { kind: params.inputKind },
    ...(result.artifactHex === undefined
      ? {}
      : { output: { kind: 'canonical-serialization', bytes: result.artifactHex } }),
    outcome: result.ok
      ? { kind: 'accept', ...(result.detail === undefined ? {} : { detail: result.detail }) }
      : { kind: 'reject', ...(result.errorClass === undefined ? {} : { detail: result.errorClass }) },
    clauseIdsEvaluated: [],
    // The M1 function's own return, carried verbatim for a projector to read.
    ...(result.extra === undefined ? {} : { nativeObservation: { nativeReturnCode: JSON.stringify(result.extra) } }),
    executionStatus: 'completed',
    provenance: { timestampIso: new Date().toISOString() },
  });
}

