// M3.7.4 / D14 -- the scored execution policy.
//
// The last thing decided before any scored datum exists. After the new freeze
// this is immutable, so it is written as a CONTRACT with its reasons, not as
// configuration.
//
// ---------------------------------------------------------------------
// The audit that decided the unit
// ---------------------------------------------------------------------
//
// runPhaseC writes NOTHING while it runs. Every accumulator -- executions,
// observations, instances, mutations, scientificResults, omittedClasses --
// lives in memory and is returned at the end. A process that dies mid-run
// therefore leaves no partial state at all: not a corrupt file, not a
// half-written bundle. Everything is lost.
//
// So the choice is not "one-shot vs blockwise for tidiness". Under one-shot,
// an interruption at hour six of the scored run costs the entire run, and the
// only recovery is to execute the whole population again -- which is both
// expensive and, worse, an invitation to salvage. Blockwise exists to make
// recovery a mechanical resumption rather than a judgement call.
//
// ---------------------------------------------------------------------
// Why blockwise does not change what an observation is
// ---------------------------------------------------------------------
//
// This was the question that could have stopped the milestone, and it has a
// determinate answer: aggregation is strictly PER CLASS.
// aggregateMutationClass receives one class's instances and nothing else, and
// detectionSupport counts divergent instances within that same class. Nothing
// in Phase C aggregates across classes -- the cross-operation machinery is
// M5's, by explicit disposition.
//
//     class-aligned partition  =>  r(c) is bit-identical to the one-shot run
//
// So the policy admits blockwise ONLY with class-aligned blocks. A partition
// that split a class across blocks would compute r(c) on partial instances,
// and that WOULD change the science. The constraint is enforced, not trusted.
//
// ---------------------------------------------------------------------
// What the policy forbids
// ---------------------------------------------------------------------
//
// Partial results exist because persistence requires them. They may not
// influence anything: not the order, not the selection, not retries, not
// exclusions. An operator may not decide at the end which blocks to keep.
// That is the whole reason the completion gate is mechanical.

import { createHash } from 'node:crypto';
import type { OperationId } from '../schema/capability.js';

export class ExecutionPolicyError extends Error {}

/** Frozen identity of this policy. Any change to the rules changes this. */
export const SCORED_EXECUTION_POLICY_VERSION = 'M3.7.4/1';

// =====================================================================
// 1. Unit of execution
// =====================================================================

export type ExecutionUnit = 'blockwise-class-aligned';

/**
 * The block a class belongs to. Class-aligned by construction: the block key
 * is derived from the class, so no class can be split.
 *
 * Blocks are per OPERATION, which is the coarsest partition that still gives
 * useful recovery granularity, and which happens to align with the only
 * boundary the analysis machinery ever respects (M_o is per-operation).
 */
export function blockOf(operation: OperationId): string {
  return `block:${operation}`;
}

// =====================================================================
// 2. Total deterministic order
// =====================================================================

/**
 * The scored order, derived from NORMATIVE IDENTITIES only.
 *
 * Never from object iteration order, filesystem order, test discovery or
 * backend availability -- all four vary between machines and would make the
 * run unreproducible in exactly the way R4 exists to detect.
 *
 * Ordered by (operation, mutationId, stimulusInstanceId, relation, scope key),
 * each a frozen identifier, and compared with a fixed collation so the order
 * cannot drift with locale.
 */
export interface OrderableObligation {
  readonly operation: OperationId;
  readonly mutationId: string;
  readonly stimulusInstanceId: string;
  readonly relation: string;
  readonly scopeKey: string;
}

const OPERATION_ORDER: readonly OperationId[] =
  Object.freeze(['hkdf', 'gcm', 'oaep', 'pss', 'rsa-ser', 'ec-ser']);

function cmp(a: string, b: string): number {
  // Codepoint comparison, deliberately not localeCompare: locale-sensitive
  // collation would make the order machine-dependent.
  return a < b ? -1 : a > b ? 1 : 0;
}

export function compareObligations(a: OrderableObligation, b: OrderableObligation): number {
  const oa = OPERATION_ORDER.indexOf(a.operation);
  const ob = OPERATION_ORDER.indexOf(b.operation);
  if (oa === -1 || ob === -1) throw new ExecutionPolicyError(`Unknown operation in ordering: ${a.operation}/${b.operation}`);
  return (oa - ob)
    || cmp(a.mutationId, b.mutationId)
    || cmp(a.stimulusInstanceId, b.stimulusInstanceId)
    || cmp(a.relation, b.relation)
    || cmp(a.scopeKey, b.scopeKey);
}

export function scoredOrder<T extends OrderableObligation>(obligations: readonly T[]): readonly T[] {
  return [...obligations].sort(compareObligations);
}

// =====================================================================
// 3. Failure semantics
// =====================================================================

export type FailureDisposition =
  /** The run stops. Nothing about the experiment is recorded from it. */
  | 'abort-run'
  /** This block is void and must be re-executed whole; other blocks stand. */
  | 'void-block'
  /** A legitimate experimental outcome. Recorded as science. */
  | 'experimental-observation';

export type FailureKind =
  | 'environment-mismatch'
  | 'harness-error'
  | 'projection-error'
  | 'binding-error'
  | 'timeout'
  | 'backend-crash'
  | 'contractual-rejection'
  | 'insufficient-evidence'
  | 'non-scoreable';

/**
 * The disposition of every failure kind, decided in advance.
 *
 * The invariant that matters more than any individual row:
 *
 *     an instrument failure NEVER becomes a scientific result
 *
 * EnvironmentMismatch and ProjectionError already abort by their own
 * contracts (M3.4, C3); this table makes the whole classification explicit so
 * no unlisted kind can be improvised into 'experimental-observation' during
 * M4.
 */
export const FAILURE_POLICY: Readonly<Record<FailureKind, { readonly disposition: FailureDisposition; readonly why: string }>> =
  Object.freeze({
    'environment-mismatch': {
      disposition: 'abort-run',
      why: 'A wrong toolchain describes an invalid experiment, not an experimental outcome. Already fail-closed in M3.4.',
    },
    'projection-error': {
      disposition: 'abort-run',
      why: 'A projection refusal proves the instrument broke its own contract. Filing it as evidence would record a defect as a result.',
    },
    'binding-error': {
      disposition: 'abort-run',
      why: 'An obligation that cannot be bound means the plan and the instrument disagree; continuing would score an incomplete population.',
    },
    'harness-error': {
      disposition: 'void-block',
      why: 'A fault in the harness invalidates what that block produced, but says nothing about the other blocks, which are independent by class alignment.',
    },
    'timeout': {
      disposition: 'void-block',
      why: 'Operational, not experimental: the backend was not given the chance to answer, so no verdict about it may be recorded.',
    },
    'backend-crash': {
      disposition: 'void-block',
      why: 'The same. A crashed process produced no answer -- which is not the same as answering badly, and must not be scored as if it were.',
    },
    'contractual-rejection': {
      disposition: 'experimental-observation',
      why: 'A rejection IS the observation. The run completed and produced a decision; R_val and R_err are what interpret it.',
    },
    'insufficient-evidence': {
      disposition: 'experimental-observation',
      why: 'A valid observation that does not permit a verdict. It blocks completeness for its own scope and nothing else.',
    },
    'non-scoreable': {
      disposition: 'experimental-observation',
      why: 'An applicable relation with no scoreable result, carrying its cause. Persisting the fact is not scoring it.',
    },
  });

export function dispositionOf(kind: FailureKind): FailureDisposition {
  const row = FAILURE_POLICY[kind];
  if (row === undefined) {
    throw new ExecutionPolicyError(
      `Unclassified failure kind '${kind}'. Refusing: an unlisted failure must not be improvised into a result during M4.`,
    );
  }
  return row.disposition;
}

// =====================================================================
// 4. Retry policy
// =====================================================================

/**
 * Retry is permitted for exactly two operational conditions, both of which
 * mean the backend never answered, and for nothing else.
 *
 * There is deliberately no retry on a RESULT. 'It came out strange, run it
 * again' is how a scored dataset is quietly selected, and no wording of it is
 * admissible. A retry is recorded with its attempt number so the dataset shows
 * that it happened.
 */
export const RETRYABLE: readonly FailureKind[] = Object.freeze(['timeout', 'backend-crash']);
export const MAX_ATTEMPTS = 2;

export function mayRetry(kind: FailureKind, attempt: number): boolean {
  if (!RETRYABLE.includes(kind)) return false;
  return attempt < MAX_ATTEMPTS;
}

// =====================================================================
// 5. Persistence and atomicity
// =====================================================================

/**
 * A block is COMMITTED only once its bundle is written whole and its digest
 * recorded. A partial write is not a partial block: it is no block, and the
 * block is re-executed from the start.
 *
 * Resumption is mechanical -- the set of committed block ids determines what
 * remains -- and never a judgement about which partial results looked usable.
 * Two attempts at the same block can never both be committed: the second
 * replaces the first only if the first was never committed.
 */
export interface BlockCommit {
  readonly blockId: string;
  readonly runId: string;
  readonly policyVersion: string;
  readonly obligationCount: number;
  readonly digest: string;
  readonly attempt: number;
}

export function digestOf(serialized: string): string {
  return createHash('sha256').update(serialized, 'utf8').digest('hex');
}

export function assertCommitConsistent(commits: readonly BlockCommit[]): void {
  const seen = new Map<string, BlockCommit>();
  for (const c of commits) {
    const prior = seen.get(c.blockId);
    if (prior !== undefined) {
      throw new ExecutionPolicyError(
        `Block '${c.blockId}' is committed twice (attempts ${prior.attempt} and ${c.attempt}). Evidence from two ` +
        'attempts must never be mixed: a re-executed block replaces an uncommitted one, never a committed one.',
      );
    }
    if (c.policyVersion !== SCORED_EXECUTION_POLICY_VERSION) {
      throw new ExecutionPolicyError(
        `Block '${c.blockId}' was produced under policy '${c.policyVersion}', not '${SCORED_EXECUTION_POLICY_VERSION}'. ` +
        'Blocks from different execution policies are not one dataset.',
      );
    }
    seen.set(c.blockId, c);
  }
  const runIds = new Set(commits.map((c) => c.runId));
  if (runIds.size > 1) {
    throw new ExecutionPolicyError(`Commits span ${runIds.size} run identities; one dataset comes from one run.`);
  }
}

// =====================================================================
// 6. Run identity
// =====================================================================

/**
 * What the dataset must be able to prove about its own production. Every
 * field is an identity, not a description: a reader can check each one
 * against the artifact it names.
 */
export interface ScoredRunIdentity {
  readonly runId: string;
  readonly policyVersion: string;
  /** The frozen instrument commit the run executed from. */
  readonly instrumentCommit: string;
  /** The plan's own cardinality, so a truncated plan is detectable. */
  readonly plannedObligations: number;
  readonly requiredObligations: number;
  /** Environment identity, as M3.4's protocol reports it. */
  readonly environmentDigest: string;
}

export function assertRunIdentityComplete(id: Partial<ScoredRunIdentity>): asserts id is ScoredRunIdentity {
  for (const field of ['runId', 'policyVersion', 'instrumentCommit', 'plannedObligations', 'requiredObligations', 'environmentDigest'] as const) {
    if (id[field] === undefined) {
      throw new ExecutionPolicyError(`Run identity is missing '${field}'; the dataset could not prove how it was produced.`);
    }
  }
}

// =====================================================================
// 7. Completion gate
// =====================================================================

/**
 * Mechanical, and symmetric in both directions.
 *
 * The run is complete iff the committed obligations are EXACTLY the required
 * population: none missing, and none extra. The second half matters as much
 * as the first -- a run that scored something outside the required set has
 * measured something nobody pre-registered.
 *
 * The operator does not decide at the end what to keep. There is no
 * "keep what succeeded" path, by construction: this function takes the
 * required set and the committed set and returns a verdict, with no room for
 * a subset.
 */
export interface CompletionVerdict {
  readonly complete: boolean;
  readonly missing: readonly string[];
  readonly unexpected: readonly string[];
}

export function assessCompletion(
  required: readonly string[], committed: readonly string[],
): CompletionVerdict {
  const req = new Set(required);
  const com = new Set(committed);
  const missing = [...req].filter((k) => !com.has(k)).sort();
  const unexpected = [...com].filter((k) => !req.has(k)).sort();
  return { complete: missing.length === 0 && unexpected.length === 0, missing, unexpected };
}

export function assertRunComplete(verdict: CompletionVerdict): void {
  if (verdict.complete) return;
  throw new ExecutionPolicyError(
    `The scored run is not complete: ${verdict.missing.length} required obligation(s) missing, ` +
    `${verdict.unexpected.length} unexpected. Refusing to treat a partial population as a dataset.`,
  );
}

// =====================================================================
// 8. No adaptive inspection
// =====================================================================

/**
 * The order and the block membership are functions of the PLAN alone.
 *
 * Stated as a checkable property rather than as a rule nobody can verify:
 * given the same plan, the order is the same whatever has been observed, so a
 * result cannot have influenced it.
 */
export function orderIsResultIndependent<T extends OrderableObligation>(
  obligations: readonly T[],
): boolean {
  const a = scoredOrder(obligations).map((o) => `${o.mutationId}|${o.relation}|${o.scopeKey}`);
  const shuffled = [...obligations].reverse();
  const b = scoredOrder(shuffled).map((o) => `${o.mutationId}|${o.relation}|${o.scopeKey}`);
  return a.length === b.length && a.every((x, i) => x === b[i]);
}
