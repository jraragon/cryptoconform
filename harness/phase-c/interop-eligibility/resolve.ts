// M3-H9.3a-3.2.5b -- resolution, integrity pins and structural guards.
//
// Read-only over the registry. Nothing here executes mutate(), invokes a
// contractual validator, or derives eligibility from evidence: the whole
// module consumes a pre-registered table and computes hashes over it.
//
// --- The two hashes, and why they are two -----------------------------
//
//     H_registry = SHA256(canonicalize(REGISTRY))       the ARTIFACT
//     H_entry(c,s) = SHA256(canonicalize(ResolvedEntry)) the DECISION
//
// H_registry identifies which frozen version of the table was installed.
// H_entry identifies which decision was actually applied to this pair --
// class default or stimulus override, with its provenance. Repeating one
// global hash 81 times would prove the file's identity and nothing about
// the entry, and a class using a default is not distinguishable from one
// using an override by the file hash alone.
//
// H_entry covers the FULL resolved entry INCLUDING provenance. Two
// decisions with the same outcome but a different normative justification
// are not the same scientific object, so hashing only
// 'eligible'/'non-eligible' would collapse them.
//
// --- Why H_registry is not in harness/audits/hashes.ts ----------------
//
// The M3-H9.3a-3.2.5a inspection found that hashes.ts pins exactly four
// objects, all of ONE family: the portable profile and the three provider
// manifests, under M2.4.2's own closure criterion. Notably MUTATION_REGISTRY
// and APPLICABILITY_MATRIX -- older and more foundational -- are audited for
// cardinality there but never hashed. Adding this table would either widen
// that file's meaning silently or leave the newest table pinned while the
// two oldest are not.
//
// The correct precedent is the M3 frozen material corpus, which did not
// join hashes.ts either: it declared its own hash and had its own loader
// recompute it, failing closed at the point of materialisation. This module
// follows that pattern.

import { createHash } from 'node:crypto';
import { canonicalize } from '../../hashing/canonical-hash.js';
import { MUTATION_REGISTRY } from '../../registry/mutations.js';
import { APPLICABILITY_MATRIX } from '../../applicability/matrix.js';
import { INTEROP_ELIGIBILITY_REGISTRY } from './registry.js';
import {
  InteropEligibilityRegistryError,
  type InteropEligibility,
  type InteropEligibilityRegistry,
  type ResolvedEligibilityEntry,
} from './types.js';

function sha256Hex(input: string): string {
  return createHash('sha256').update(input, 'utf8').digest('hex');
}

// ---------------------------------------------------------------------
// Resolution
//
//     Eligibility(c,s) = Override(c,s) if present, else Default(c)
//
// Fail-closed on an unknown class: a pair with R_interop applicable and no
// registry entry must never silently resolve to 'eligible', which would be
// the permissive default and therefore the dangerous one.
// ---------------------------------------------------------------------

const BY_ID = new Map(INTEROP_ELIGIBILITY_REGISTRY.map((e) => [e.mutationId, e]));

export function resolveInteropEligibility(
  mutationId: string,
  stimulusInstanceId: string,
): ResolvedEligibilityEntry {
  const entry = BY_ID.get(mutationId);
  if (entry === undefined) {
    throw new InteropEligibilityRegistryError(
      `No InteropEligibility entry for '${mutationId}'. A pair with R_interop applicable must resolve ` +
      'exactly one decision; refusing to default to eligible.',
    );
  }
  const override = entry.stimulusOverrides?.[stimulusInstanceId];
  return override !== undefined
    ? { mutationId, stimulusInstanceId, eligibility: override, source: 'stimulus-override' }
    : { mutationId, stimulusInstanceId, eligibility: entry.classDefault, source: 'class-default' };
}

export function isEligible(e: InteropEligibility): boolean {
  return e.kind === 'eligible';
}

// ---------------------------------------------------------------------
// Integrity pins
// ---------------------------------------------------------------------

export function computeRegistryHash(registry: InteropEligibilityRegistry = INTEROP_ELIGIBILITY_REGISTRY): string {
  return sha256Hex(canonicalize(registry));
}

export function computeEntryHash(resolved: ResolvedEligibilityEntry): string {
  return sha256Hex(canonicalize(resolved));
}

// Declared independently of the computation, exactly as the frozen corpus
// declares each record's own sha256: the pin is what makes the recomputation
// fail-closed, and a pin derived from the value it checks would prove
// nothing.
export const INTEROP_ELIGIBILITY_REGISTRY_SHA256 =
  '68cff7530c2af14826a43cbe0f5a598d9675ca1538bdd5931b8db66044169404';

export function verifyRegistryIntegrity(expected: string = INTEROP_ELIGIBILITY_REGISTRY_SHA256): void {
  const actual = computeRegistryHash();
  if (actual !== expected) {
    throw new InteropEligibilityRegistryError(
      `InteropEligibility registry hashes to ${actual}, but the declared pin is ${expected}. ` +
      'The normative table has changed -- refusing rather than absorbing the new value.',
    );
  }
}

// ---------------------------------------------------------------------
// Structural guards
//
// Every one is derived from the frozen registry and applicability matrix at
// call time, never from a hard-coded list of mutationIds -- so adding a
// class to MUTATION_REGISTRY cannot leave this table silently stale.
// ---------------------------------------------------------------------

export interface EligibilityPair {
  readonly mutationId: string;
  readonly stimulusInstanceId: string;
  readonly resolved: ResolvedEligibilityEntry;
}

/** Every (class, stimulus) whose operation has R_interop applicable. */
export function interopApplicablePairs(): readonly { mutationId: string; stimulusInstanceId: string }[] {
  const out: { mutationId: string; stimulusInstanceId: string }[] = [];
  for (const e of MUTATION_REGISTRY) {
    if (!APPLICABILITY_MATRIX[e.operation].R_interop) continue;
    for (const si of e.stimulusInstances) {
      out.push({ mutationId: e.mutationId, stimulusInstanceId: si.stimulusInstanceId });
    }
  }
  return out;
}

/** Resolves every applicable pair, or throws on the first that cannot be resolved. */
export function resolveAll(): readonly EligibilityPair[] {
  return interopApplicablePairs().map((p) => ({
    ...p,
    resolved: resolveInteropEligibility(p.mutationId, p.stimulusInstanceId),
  }));
}

// Two granularities, deliberately reported side by side rather than one
// derived from the other. M3-H9.3a-3.2.1's own result is a CLASS count
// (70 uniform + 1 mixed); the population partition is a PAIR count
// (55 + 16 + 10). Collapsing them would misstate whichever one was dropped.
export interface RegistryAuditResult {
  readonly classEntries: number;
  readonly classesWithOverride: number;
  readonly totalPairs: number;
  readonly eligible: number;
  readonly producerContractuallyBlocked: number;
  readonly noOperationalInput: number;
  readonly pairsByClassDefault: number;
  readonly pairsByStimulusOverride: number;
}

// I_tot  every applicable pair resolves exactly one decision
// I_abs   no entry exists for an operation without R_interop
// I_ovr   an override must differ from its own class default
// I_key   an override must name a stimulus the frozen registry declares
// I_dup   no duplicate mutationId
// Exposed separately from auditRegistry so a test can make each guard FIRE
// on a deliberately malformed table, rather than only observe that the real
// one passes. A guard never seen to reject is a guard never tested.
export function auditRegistryEntries(registry: InteropEligibilityRegistry): void {
  const seen = new Set<string>();
  for (const entry of registry) {
    if (seen.has(entry.mutationId)) {
      throw new InteropEligibilityRegistryError(`Duplicate registry entry for '${entry.mutationId}' (I_dup).`);
    }
    seen.add(entry.mutationId);

    const frozen = MUTATION_REGISTRY.find((e) => e.mutationId === entry.mutationId);
    if (frozen === undefined) {
      throw new InteropEligibilityRegistryError(
        `Registry entry '${entry.mutationId}' names no class in the frozen MUTATION_REGISTRY.`,
      );
    }
    if (frozen.operation !== entry.operation) {
      throw new InteropEligibilityRegistryError(
        `Registry entry '${entry.mutationId}' declares operation '${entry.operation}', ` +
        `but the frozen registry says '${frozen.operation}'.`,
      );
    }
    if (!APPLICABILITY_MATRIX[frozen.operation].R_interop) {
      throw new InteropEligibilityRegistryError(
        `Registry entry '${entry.mutationId}' belongs to operation '${frozen.operation}', which does not have ` +
        'R_interop applicable. Eligibility is not defined where the relation is not part of the protocol (I_abs).',
      );
    }

    const declared = new Set(frozen.stimulusInstances.map((s) => s.stimulusInstanceId));
    for (const [stimulusInstanceId, value] of Object.entries(entry.stimulusOverrides ?? {})) {
      if (!declared.has(stimulusInstanceId)) {
        throw new InteropEligibilityRegistryError(
          `Override '${entry.mutationId}::${stimulusInstanceId}' names a stimulus the frozen registry ` +
          'does not declare (I_key).',
        );
      }
      if (canonicalize(value) === canonicalize(entry.classDefault)) {
        throw new InteropEligibilityRegistryError(
          `Override '${entry.mutationId}::${stimulusInstanceId}' is identical to its class default. An override ` +
          'must be a positive statement that this stimulus DIFFERS; a redundant one hides the few that ' +
          'genuinely do (I_ovr).',
        );
      }
    }
  }
}

export function auditRegistry(): RegistryAuditResult {
  auditRegistryEntries(INTEROP_ELIGIBILITY_REGISTRY);

  const pairs = resolveAll(); // I_tot: throws on any unresolvable pair
  let eligible = 0, blocked = 0, noInput = 0, defaults = 0, overrides = 0;
  for (const p of pairs) {
    const e = p.resolved.eligibility;
    if (e.kind === 'eligible') eligible += 1;
    else if (e.reason === 'producer-contractually-blocked') blocked += 1;
    else noInput += 1;
    if (p.resolved.source === 'stimulus-override') overrides += 1; else defaults += 1;
  }

  return {
    classEntries: INTEROP_ELIGIBILITY_REGISTRY.length,
    classesWithOverride: INTEROP_ELIGIBILITY_REGISTRY
      .filter((e) => Object.keys(e.stimulusOverrides ?? {}).length > 0).length,
    totalPairs: pairs.length,
    eligible,
    producerContractuallyBlocked: blocked,
    noOperationalInput: noInput,
    pairsByClassDefault: defaults,
    pairsByStimulusOverride: overrides,
  };
}
