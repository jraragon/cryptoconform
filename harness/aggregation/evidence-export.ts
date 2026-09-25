// M2.4.8 -- evidence bundle export/import. Lossless serialization of
// everything needed to reconstruct the full traceability chain:
// MutationID -> StimulusInstanceID -> ExecutionID[] -> RelationObservationID[]
// -> MutationInstanceResult -> MutationResult.
//
// M2.5.4 finding: the original M2.4.8 shape had no slot for Phase A/B's
// own terminal aggregate (BaselineResult, M2.4.3) -- only the Phase-C
// shapes (MutationInstanceResult/MutationResult). Extended additively
// (optional field, defaults to empty) rather than modifying the frozen
// M2.4.8 semantics: existing bundles with no baselineResults field remain
// valid, and Phase C's own export/import behavior is completely unchanged.

import type { ExecutionEvidence } from '../evidence/execution-evidence.js';
import type { RelationObservation } from '../evidence/relation-observation.js';
import type { MutationInstanceResult } from '../evidence/mutation-instance-result.js';
import type { MutationResult } from '../evidence/mutation-result.js';
import type { BaselineResult } from '../evidence/baseline-result.js';
import type { PhaseCScientificMutationResult } from '../evidence/phase-c-scientific-result.js';
import { toRelationSpectrum, isFullyScoreable } from '../evidence/phase-c-scientific-result.js';
import type { OmittedClass } from '../evidence/class-omission.js';

// Bloque A: the serialized contract CHANGED, so the version changed with it.
// Reusing '1.0' would let a reader assume a bundle carries a total r(c) for
// every class when it may not. '1.0' remains readable -- those bundles
// predate partial results and are still valid on their own terms.
export type BundleVersion = '1.0' | '2.0';

export interface EvidenceBundle {
  readonly bundleVersion: BundleVersion;
  readonly executions: readonly ExecutionEvidence[];
  readonly observations: readonly RelationObservation[];
  readonly instanceResults: readonly MutationInstanceResult[];
  /**
   * The M2 representation, for the reducible subset only:
   * NonScoreable(c) = {}. Kept rather than replaced, so a v1.0 reader keeps
   * working and the historical shape stays available.
   */
  readonly mutationResults: readonly MutationResult[];
  /**
   * The canonical M3 scientific representation, for EVERY class including
   * partial ones. Not an independent source of truth: for a reducible class
   * its projection must reproduce the MutationResult exactly, which
   * assertBundleConsistency checks.
   *
   *     ScientificResults  ⊇  MutationResults   (in coverage, not in authority)
   */
  readonly scientificResults?: readonly PhaseCScientificMutationResult[];
  /**
   * Classes that produced no scientific result at all. Structured, because a
   * machine-readable reason must never depend on the text of an exception --
   * which is precisely what the previous `unscoredClasses.reason` was.
   */
  readonly omittedClasses?: readonly OmittedClass[];
  readonly baselineResults?: readonly BaselineResult[]; // M2.5.4 addition, optional for backward compatibility
}

// Deterministic, stable-key-order JSON (same discipline as M2.3.5's own
// canonical-hash.ts) -- so two exports of the identical bundle produce
// byte-identical output, not merely equivalent JSON. Exported (M3.2.3) for
// reuse wherever a deterministic fixture-content key is needed (e.g. the
// Phase C orchestrator's own R_byte baseline cache key) -- never
// duplicated as a second implementation elsewhere.
export function canonicalize(value: unknown): string {
  return JSON.stringify(sortKeysDeep(value));
}
export function sortKeysDeep(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(sortKeysDeep);
  if (value !== null && typeof value === 'object') {
    const sorted: Record<string, unknown> = {};
    for (const key of Object.keys(value as Record<string, unknown>).sort()) {
      sorted[key] = sortKeysDeep((value as Record<string, unknown>)[key]);
    }
    return sorted;
  }
  return value;
}

export function exportBundle(bundle: EvidenceBundle): string {
  return canonicalize(bundle);
}

export function importBundle(serialized: string): EvidenceBundle {
  const parsed = JSON.parse(serialized) as EvidenceBundle;
  if (parsed.bundleVersion !== '1.0' && parsed.bundleVersion !== '2.0') {
    throw new Error(`Unsupported EvidenceBundle version: ${String((parsed as { bundleVersion?: unknown }).bundleVersion)}`);
  }
  return parsed;
}

export class BundleConsistencyError extends Error {}

/**
 * The two representations must agree wherever they overlap.
 *
 * For a reducible class the scientific result's own projection has to
 * reproduce the MutationResult's spectrum exactly; for a partial one there
 * must be no MutationResult at all, since constructing one would require
 * fabricating the cells H11 forbids. Without this check the bundle would
 * carry two independently-writable answers to the same question.
 */
export function assertBundleConsistency(bundle: EvidenceBundle): void {
  const scientific = bundle.scientificResults ?? [];
  if (scientific.length === 0) return; // a v1.0 bundle has nothing to cross-check

  const byId = new Map(bundle.mutationResults.map((m) => [m.mutationId, m]));
  for (const sr of scientific) {
    const m = byId.get(sr.mutationId);
    if (isFullyScoreable(sr)) {
      if (m === undefined) {
        throw new BundleConsistencyError(
          `${sr.mutationId} is fully scoreable but has no MutationResult -- the reducible subset must stay reducible.`,
        );
      }
      const projected = toRelationSpectrum(sr);
      if (canonicalize(projected) !== canonicalize(m.observedSpectrum)) {
        throw new BundleConsistencyError(
          `${sr.mutationId}: the scientific result's projection disagrees with its MutationResult spectrum.`,
        );
      }
    } else if (m !== undefined) {
      throw new BundleConsistencyError(
        `${sr.mutationId} has ${sr.nonScoreable.length} non-scoreable relation(s) yet carries a MutationResult; ` +
        'a partial class has no M2 representation and one must not have been fabricated.',
      );
    }
  }

  // No class may simply vanish: every mutationResult must have its
  // scientific counterpart, so the two collections cannot drift apart.
  const scientificIds = new Set(scientific.map((s) => s.mutationId));
  for (const m of bundle.mutationResults) {
    if (!scientificIds.has(m.mutationId)) {
      throw new BundleConsistencyError(`${m.mutationId} has a MutationResult but no scientific result.`);
    }
  }
}

/**
 * Dataset-alone reconstruction of a class's scientific result: r~(c), its
 * non-scoreable cells with their causes, and its outstanding required
 * evidence -- without the registry, the in-memory plan, or any exception
 * raised during the run.
 */
export function reconstructScientificResult(
  bundle: EvidenceBundle,
  mutationId: string,
): {
  readonly result: PhaseCScientificMutationResult;
  readonly instances: readonly MutationInstanceResult[];
} {
  const result = (bundle.scientificResults ?? []).find((s) => s.mutationId === mutationId);
  if (result === undefined) {
    const omitted = (bundle.omittedClasses ?? []).find((o) => o.mutationId === mutationId);
    throw new Error(
      omitted === undefined
        ? `No scientific result and no omission record for ${mutationId} in this bundle.`
        : `${mutationId} produced no scientific result: ${omitted.reason}.`,
    );
  }
  const instances = bundle.instanceResults.filter(
    (i) => result.instanceResultRefs.includes(`${i.mutationId}::${i.stimulusInstanceId}`),
  );
  return { result, instances };
}

// Full traceability reconstruction, directly from an imported bundle alone
// -- no side-channel state, no re-derivation from the live registry needed.
export function reconstructTraceability(bundle: EvidenceBundle, mutationId: string, stimulusInstanceId: string) {
  const instance = bundle.instanceResults.find(
    (r) => r.mutationId === mutationId && r.stimulusInstanceId === stimulusInstanceId,
  );
  if (!instance) throw new Error(`No MutationInstanceResult for ${mutationId}::${stimulusInstanceId} in this bundle`);

  const observations = instance.observations
    .map((id) => bundle.observations.find((o) => o.observationId === id))
    .filter((o): o is RelationObservation => o !== undefined);

  const executionIds = new Set(observations.flatMap((o) => o.participants));
  const executions = bundle.executions.filter((e) => executionIds.has(e.executionId));

  const mutationResult = bundle.mutationResults.find((r) => r.mutationId === mutationId);

  return { mutationId, stimulusInstanceId, executions, observations, instanceResult: instance, mutationResult };
}

// M2.5.4 addition: the Phase A/B analogue of reconstructTraceability above.
// BaselineResult -> RelationObservation[] -> ExecutionEvidence[], directly
// from an imported bundle alone.
export function reconstructBaselineTraceability(bundle: EvidenceBundle, baselineInstanceId: string) {
  const baseline = (bundle.baselineResults ?? []).find((b) => b.baselineInstanceId === baselineInstanceId);
  if (!baseline) throw new Error(`No BaselineResult for ${baselineInstanceId} in this bundle`);

  const observations = baseline.observations
    .map((id) => bundle.observations.find((o) => o.observationId === id))
    .filter((o): o is RelationObservation => o !== undefined);

  const executionIds = new Set(observations.flatMap((o) => o.participants));
  const executions = bundle.executions.filter((e) => executionIds.has(e.executionId));

  return { baselineInstanceId, phase: baseline.phase, operation: baseline.operation, executions, observations, baselineResult: baseline };
}
