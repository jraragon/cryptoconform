// M3-H11.4-Core.1 -- structural tests for the NonScoreable vocabulary.
//
// Vocabulary only: nothing here exercises aggregation or completeness, which
// arrive in Core.2 and Core.3. What these tests fix is that the new object
// cannot be used to say something the frozen model already says better --
// in particular that it can never stand in for n/a.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';

import {
  assertNonScoreableWellFormed,
  isEnvironmentInvariant,
  scoreableApplicableDomain,
  NonScoreableIntegrityError,
  type NonScoreableCause,
  type NonScoreableCell,
} from '../../../harness/evidence/non-scoreable.js';
import type { RelationId } from '../../../harness/schema/registry-types.js';
import { APPLICABILITY_MATRIX } from '../../../harness/applicability/matrix.js';

const ALL: readonly RelationId[] = ['R_byte', 'R_interop', 'R_ser', 'R_val', 'R_err', 'R_cap'];

const cell = (over: Partial<NonScoreableCell> = {}): NonScoreableCell => ({
  mutationId: 'GCM-PROVIDER-CAPABILITY-MISMATCH',
  operation: 'gcm',
  relation: 'R_interop',
  cause: 'contractually-non-eligible',
  stimulusInstanceIds: ['default'],
  ...over,
});

// ---------------------------------------------------------------------
// The observable domain
// ---------------------------------------------------------------------

test('D_c is the applicable set minus the non-scoreable relations', () => {
  const applicable = ALL.filter((r) => APPLICABILITY_MATRIX['gcm'][r]);
  assert.equal(applicable.length, 6, 'GCM has all six applicable');
  const d = scoreableApplicableDomain(applicable, [cell()]);
  assert.deepEqual([...d], ['R_byte', 'R_ser', 'R_val', 'R_err', 'R_cap']);
});

test('D_c is computed as a complement, so it cannot disagree with the cells', () => {
  // Not two independently maintained lists: one is derived from the other.
  const applicable = ALL.filter((r) => APPLICABILITY_MATRIX['pss'][r]);
  const cells = [cell({ mutationId: 'PSS-KEY-ROLE-BYPASS', operation: 'pss' })];
  const d = scoreableApplicableDomain(applicable, cells);
  for (const c of cells) assert.ok(!d.includes(c.relation));
  for (const r of applicable) assert.ok(d.includes(r) || cells.some((c) => c.relation === r));
});

test('an inapplicable relation is absent from D_c without any cell -- n/a keeps its own domain', () => {
  // HKDF has no R_interop. That absence is n/a's business, not
  // NonScoreable's, and must be visible without recording anything.
  const applicable = ALL.filter((r) => APPLICABILITY_MATRIX['hkdf'][r]);
  assert.deepEqual([...applicable], ['R_byte', 'R_val', 'R_err', 'R_cap']);
  assert.deepEqual([...scoreableApplicableDomain(applicable, [])], [...applicable]);
});

// ---------------------------------------------------------------------
// Integrity guards -- each made to FIRE, not merely present
// ---------------------------------------------------------------------

test('a relation recorded twice is refused: D_c would be ambiguous', () => {
  assert.throws(
    () => assertNonScoreableWellFormed('GCM-PROVIDER-CAPABILITY-MISMATCH', ALL, [cell(), cell()]),
    NonScoreableIntegrityError,
  );
});

test('a cell for an INAPPLICABLE relation is refused -- it must never re-label n/a', () => {
  // This is the guard that matters most: without it, the new vocabulary
  // could quietly absorb the frozen n/a rule and make Applicability
  // unobservable in the dataset.
  const hkdfApplicable = ALL.filter((r) => APPLICABILITY_MATRIX['hkdf'][r]);
  assert.throws(
    () => assertNonScoreableWellFormed(
      'HKDF-INFO-TAMPER', hkdfApplicable,
      [cell({ mutationId: 'HKDF-INFO-TAMPER', operation: 'hkdf', relation: 'R_interop' })],
    ),
    /must never be recorded as unscoreable/,
  );
});

test('a cell naming a different class is refused', () => {
  assert.throws(
    () => assertNonScoreableWellFormed('PSS-KEY-ROLE-BYPASS', ALL, [cell()]),
    /attached to class/,
  );
});

test('the well-formed case passes', () => {
  assert.doesNotThrow(() => assertNonScoreableWellFormed(
    'GCM-PROVIDER-CAPABILITY-MISMATCH', ALL,
    [cell(), cell({ relation: 'R_ser', cause: 'zero-executable-support' })],
  ));
});

// ---------------------------------------------------------------------
// The two causes are not one
// ---------------------------------------------------------------------

test('the causes differ by environment-invariance, which is the testable property', () => {
  assert.equal(isEnvironmentInvariant('contractually-non-eligible'), true);
  assert.equal(isEnvironmentInvariant('zero-executable-support'), false);
});

test('the cause vocabulary is exactly two, and disjoint from NonExecutionReason', () => {
  const causes: NonScoreableCause[] = ['contractually-non-eligible', 'zero-executable-support'];
  assert.equal(new Set(causes).size, 2);
  // The frozen scope-level vocabulary must not leak in: it answers "why could
  // THIS SCOPE not run", a different question at a different granularity.
  const frozenScopeReasons = ['backend-capability-absent', 'stimulus-not-expressible', 'direction-not-materializable'];
  for (const r of frozenScopeReasons) assert.ok(!causes.includes(r as NonScoreableCause));
});

// ---------------------------------------------------------------------
// Boundaries this module must not cross
// ---------------------------------------------------------------------

test('RelationSpectrum is untouched: still exactly three values, six required fields', () => {
  const src = readFileSync(new URL('../../../harness/evidence/relation-spectrum.ts', import.meta.url), 'utf8');
  assert.ok(src.includes("export type RelationValue = 'pass' | 'fail' | 'n/a';"),
    'the frozen three-value domain must not gain a fourth member');
  assert.equal((src.match(/readonly R_\w+: RelationValue;/g) ?? []).length, 6);
  assert.ok(!src.includes('?:'), 'no spectrum cell may become optional');
});

test('H11.4-Core boundary: this module introduces no cross-operation comparison', () => {
  // Frozen for the whole of H11.4-Core (H11.3-6 is blocked by M3-H12).
  // Checked by source inspection rather than by discipline, the same way
  // plan-assembly.ts already guards its own isolation.
  const src = readFileSync(new URL('../../../harness/evidence/non-scoreable.ts', import.meta.url), 'utf8');
  for (const forbidden of ['DetectionGain', 'DiagnosticGain', 'Undetermined', 'Keep(', 'O_min', 'APPLICABILITY_MATRIX']) {
    assert.ok(!src.includes(forbidden), `Core.1 must not reach for '${forbidden}'`);
  }
});

test('the cell carries its operation, so a cross-operation comparison is refusable by inspection', () => {
  // H12.0 established that M_o and Mut(o) are both per-operation, so every
  // spectrum comparison is confined to one operation. Carrying `operation`
  // is what lets a later consumer enforce that instead of assuming it.
  const a = cell();
  const b = cell({ mutationId: 'PSS-KEY-ROLE-BYPASS', operation: 'pss' });
  assert.notEqual(a.operation, b.operation);
});

test('note is documentation, never semantics', () => {
  const withNote = cell({ note: 'EligibleSet empty: capability-declaration fixture' });
  const without = cell();
  // Same cause, same relation, same class: the note cannot make them differ
  // in any way a consumer is allowed to branch on.
  assert.equal(withNote.cause, without.cause);
  assert.equal(withNote.relation, without.relation);
});
