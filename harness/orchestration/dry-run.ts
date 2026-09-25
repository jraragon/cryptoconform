// Bloque D / M3.5 -- the dry run.
//
// M3.1 is explicit that instrument validation "is explicitly not the
// scientific dataset itself, and no result from this validation may be
// reused as scored M4 data". That has to be structural, not a promise:
//
//     DryRunEvidence  n  ScoredM4Evidence  =  {}
//
// enforced three ways at once, so no single slip can defeat it. Every bundle
// produced here carries runKind 'dry-run'; it is written under its own
// directory; and assertNotScored refuses a dry-run bundle wherever scored
// evidence is expected. A dry-run bundle reaching the scored path is an
// ABORT, on the same principle as EnvironmentMismatch and ProjectionError: an
// instrument-validation artifact presented as science is not a degraded
// result, it is the wrong artifact.
//
// --- The two shapes C deliberately left unnormalised ---------------------
//
// Bloque C recorded that OAEP/PSS expose adapter FACTORIES needing key
// material bound, and that the serialization operations expose export/import
// FUNCTIONS that are not adapters at all -- and that normalising M1 to make
// everything look like an ExecutionAdapter would misrepresent the reference
// implementation. The wrappers below adapt CALL SHAPE, EXECUTION and IDs, and
// nothing else. They decide no contractual semantics: no expectation, no
// error classification, no comparison. If one of them had needed to, that
// would not be dry-run plumbing and the block would have stopped.

import { mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import type { ExecutionEvidence } from '../evidence/execution-evidence.js';
import type { BackendIdentity } from '../schema/backend-identity.js';
import type { OperationId } from '../schema/capability.js';
import { exportBundle, importBundle, type EvidenceBundle } from '../aggregation/evidence-export.js';

export class DryRunContaminationError extends Error {}

export const DRY_RUN_OUTPUT_DIR = 'dry-run-output';

export interface DryRunBundle {
  /** Structural, not a label: a scored consumer refuses on it. */
  readonly runKind: 'dry-run';
  readonly bundle: EvidenceBundle;
}

export function makeDryRunBundle(bundle: EvidenceBundle): DryRunBundle {
  return { runKind: 'dry-run', bundle };
}

/**
 * The gate a scored consumer must call. Refuses rather than downgrades: a
 * dry-run artifact presented as scored evidence is the wrong artifact, not a
 * weaker one.
 */
export function assertNotScored(candidate: { readonly runKind?: string }): void {
  if (candidate.runKind === 'dry-run') {
    throw new DryRunContaminationError(
      'This is a DRY RUN bundle and must never enter the scored dataset. M3.1: no result from instrument ' +
      'validation may be reused as scored M4 data.',
    );
  }
}

export function persistDryRun(dir: string, name: string, dr: DryRunBundle): string {
  mkdirSync(dir, { recursive: true });
  const path = `${dir}/${name}.json`;
  // The runKind travels INSIDE the serialized object, so it survives being
  // copied out of its directory -- the directory alone would be a convention.
  writeFileSync(path, JSON.stringify({ runKind: dr.runKind, bundle: JSON.parse(exportBundle(dr.bundle)) }, null, 1));
  return path;
}

export function reloadDryRun(path: string): DryRunBundle {
  const raw = JSON.parse(readFileSync(path, 'utf8')) as { runKind?: string; bundle?: unknown };
  if (raw.runKind !== 'dry-run') {
    throw new DryRunContaminationError(`${path} does not declare runKind 'dry-run'.`);
  }
  return { runKind: 'dry-run', bundle: importBundle(JSON.stringify(raw.bundle)) };
}

// ---------------------------------------------------------------------
// Serialization execution wrapper
//
// Call shape and identity only. It records WHAT the M1 function returned; it
// does not judge it. `materialPreserved` and `importOk` are carried into the
// evidence payload untouched, for a projector to read later -- deciding what
// they mean is R_ser's and R_interop's job, settled in C1 and C3.
// ---------------------------------------------------------------------

export type { SerializationCallResult } from '../evidence/serialization-execution.js';
export { wrapSerializationExecution } from '../evidence/serialization-execution.js';

/**
 * Binds key material to an adapter factory.
 *
 * Trivial by design, and named so the binding is a visible step rather than
 * something a caller does inline: OAEP and PSS have no adapter until the
 * material exists, and the SAME material must reach producer and consumer or
 * a cross-provider observation means nothing.
 */
export function bindFactory<TKey, TAdapter>(factory: (key: TKey) => TAdapter, key: TKey): TAdapter {
  return factory(key);
}
