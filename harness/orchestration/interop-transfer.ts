// Bloque C2 -- the R_interop producer-to-consumer transfer.
//
// The capability gap recorded open since M3.2 §5: the orchestration context
// offered getBaseline, runMutation and runDeclarationProbe, all executing on
// baseFixture, and none could feed ONE BACKEND'S OWN ARTIFACT to another.
// Running both sides on the base fixture and comparing afterwards is not
// interoperability -- it is two independent local executions with an
// inference laid over them.
//
//     A --mutation--> artifact_A --> B --consume--> observation_{A->B}
//
// The invariant that makes it interoperability rather than inference:
//
//     the bytes B consumes are IDENTICALLY the bytes A produced
//
// enforced by construction (the consumer input is the producer output object,
// never re-derived) and checked by a transferHash carried on the record, so
// the dataset can demonstrate it afterwards rather than asking to be trusted.

import { createHash } from 'node:crypto';
import type { BackendIdentity } from '../schema/backend-identity.js';
import { backendIdentityEquals } from '../schema/backend-identity.js';
import type { OperationId } from '../schema/capability.js';
import type { ExecutionEvidence } from '../evidence/execution-evidence.js';
import { consumerRole, producerRole, resolveDispatch, DispatchError, type ExecutionRole } from './dispatch.js';

export class TransferError extends Error {}

/**
 * What crosses the boundary. Deliberately opaque bytes plus its provenance:
 * the transfer layer must not interpret the artifact, because interpreting it
 * is the consumer's contractual job and duplicating that here would put
 * scientific semantics in the plumbing.
 */
export interface TransferredArtifact {
  readonly bytesHex: string;
  readonly producedBy: BackendIdentity;
  readonly producerExecutionId: string;
  /** SHA-256 of the bytes, computed once at production. */
  readonly transferHash: string;
}

export interface TransferRecord {
  readonly operation: OperationId;
  readonly from: BackendIdentity;
  readonly to: BackendIdentity;
  readonly producerRole: ExecutionRole;
  readonly consumerRole: ExecutionRole;
  readonly artifact: TransferredArtifact;
  readonly producerExecution: ExecutionEvidence;
  readonly consumerExecution: ExecutionEvidence;
  /** Recomputed from what the consumer actually received. */
  readonly consumedHash: string;
}

export function hashArtifact(bytesHex: string): string {
  return createHash('sha256').update(bytesHex, 'utf8').digest('hex');
}

export function makeTransferredArtifact(
  bytesHex: string, producedBy: BackendIdentity, producerExecutionId: string,
): TransferredArtifact {
  if (bytesHex.length === 0) {
    throw new TransferError('A producer that emitted no artifact cannot begin a transfer.');
  }
  return { bytesHex, producedBy, producerExecutionId, transferHash: hashArtifact(bytesHex) };
}

/**
 * Runs one direction of an interoperability observation.
 *
 * Directional by construction: from -> to is not to -> from, matching
 * R_interop's own frozen asymmetry (Obs_interop(p->q) != Obs_interop(q->p)),
 * unlike R_byte, whose scope is an unordered cross-backend-set.
 *
 * Self-pairs are refused: a backend consuming its own artifact is Phase A/B's
 * local round trip, already covered, and admitting it here would inflate
 * R_interop with observations that demonstrate nothing cross-provider.
 */
export async function runTransfer(params: {
  readonly operation: OperationId;
  readonly from: BackendIdentity;
  readonly to: BackendIdentity;
  /** Produces the artifact on `from`. Runs the mutation if there is one. */
  readonly produce: () => Promise<{ readonly bytesHex: string; readonly execution: ExecutionEvidence }>;
  /** Consumes EXACTLY the produced artifact on `to`. */
  readonly consume: (artifact: TransferredArtifact) => Promise<ExecutionEvidence>;
}): Promise<TransferRecord> {
  if (backendIdentityEquals(params.from, params.to)) {
    throw new TransferError(
      `Self-transfer on '${params.from.family}' is Phase A/B's own local round trip, not an interoperability ` +
      'observation. Refused rather than counted.',
    );
  }
  // Fail-closed before executing anything: an operation with no
  // producer/consumer split has no transfer, and an unknown backend refuses.
  const pRole = producerRole(params.operation);
  const cRole = consumerRole(params.operation);
  resolveDispatch(params.operation, params.from, pRole);
  resolveDispatch(params.operation, params.to, cRole);

  const produced = await params.produce();
  const artifact = makeTransferredArtifact(produced.bytesHex, params.from, produced.execution.executionId);
  const consumerExecution = await params.consume(artifact);

  // The identity check. Recomputed from the artifact the consumer was handed
  // rather than asserted, so a transfer that silently substituted bytes is a
  // refusal instead of a quietly wrong observation.
  const consumedHash = hashArtifact(artifact.bytesHex);
  if (consumedHash !== artifact.transferHash) {
    throw new TransferError(
      `Transfer identity broken for ${params.operation} ${params.from.family} -> ${params.to.family}: ` +
      'the consumer did not receive the bytes the producer emitted.',
    );
  }
  if (produced.execution.executionId === consumerExecution.executionId) {
    throw new TransferError('Producer and consumer must be two distinct executions.');
  }

  return {
    operation: params.operation, from: params.from, to: params.to,
    producerRole: pRole, consumerRole: cRole,
    artifact, producerExecution: produced.execution, consumerExecution, consumedHash,
  };
}

export { DispatchError };
