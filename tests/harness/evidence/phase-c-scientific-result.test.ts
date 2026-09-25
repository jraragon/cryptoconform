// M3-H11.4-Core.2 -- the Phase C scientific result and its bridge to M2.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';

import {
  ALL_RELATION_IDS,
  isFullyScoreable,
  makePhaseCScientificResult,
  toRelationSpectrum,
  ScientificResultIntegrityError,
  type PartialRelationSpectrum,
} from '../../../harness/evidence/phase-c-scientific-result.js';
import type { NonScoreableCell } from '../../../harness/evidence/non-scoreable.js';
import type { RelationApplicability } from '../../../harness/schema/registry-types.js';
import type { MutationInstanceResult } from '../../../harness/evidence/mutation-instance-result.js';

const ALL_APPLICABLE: RelationApplicability =
  { R_byte: true, R_interop: true, R_ser: true, R_val: true, R_err: true, R_cap: true };
const HKDF_APPLICABLE: RelationApplicability =
  { R_byte: true, R_interop: false, R_ser: false, R_val: true, R_err: true, R_cap: true };

const inst = (mutationId: string, stimulusInstanceId = 'default'): MutationInstanceResult => ({
  mutationId, stimulusInstanceId, operation: 'gcm', observations: [],
  coverage: { planned: [], reached: [], outstanding: [] }, complete: true,
});

const cell = (relation: NonScoreableCell['relation'], cause: NonScoreableCell['cause']): NonScoreableCell => ({
  mutationId: 'C', operation: 'gcm', relation, cause, stimulusInstanceIds: ['default'],
});

const build = (over: {
  applicability?: RelationApplicability;
  observedSpectrum: PartialRelationSpectrum;
  nonScoreable?: readonly NonScoreableCell[];
}) => makePhaseCScientificResult({
  mutationId: 'C', operation: 'gcm', gamma0Ref: 'registry:C',
  applicability: over.applicability ?? ALL_APPLICABLE,
  observedSpectrum: over.observedSpectrum,
  nonScoreable: over.nonScoreable ?? [],
  instanceResults: [inst('C')],
  detectionSupport: { divergentInstances: 0, evaluatedInstances: 1 },
});

const full = (v: 'pass' | 'fail' | 'n/a' = 'pass'): PartialRelationSpectrum =>
  Object.fromEntries(ALL_RELATION_IDS.map((r) => [r, v]));

// ---------------------------------------------------------------------
// The representation invariant
// ---------------------------------------------------------------------

test('a fully scoreable class carries six cells and no NonScoreable', () => {
  const r = build({ observedSpectrum: full() });
  assert.equal(isFullyScoreable(r), true);
  assert.equal(Object.keys(r.observedSpectrum).length, 6);
});

test('XOR: a relation is either scored or recorded non-scoreable, never both', () => {
  assert.throws(
    () => build({ observedSpectrum: full(), nonScoreable: [cell('R_interop', 'contractually-non-eligible')] }),
    /both scored and recorded non-scoreable/,
  );
});

test('XOR: a cell cannot simply go missing', () => {
  // The failure mode this invariant exists for: a key quietly absent with no
  // recorded cause is indistinguishable from data loss.
  const { R_interop, ...rest } = full() as Record<string, 'pass'>;
  void R_interop;
  assert.throws(() => build({ observedSpectrum: rest }), /cannot simply go missing/);
});

test('an inapplicable relation is MATERIALISED as n/a, never omitted', () => {
  // Omission must carry exactly one meaning. Sharing it with inapplicability
  // would make Applicability unreadable from the dataset.
  const spectrum: PartialRelationSpectrum = { R_byte: 'pass', R_val: 'pass', R_err: 'pass', R_cap: 'pass' };
  assert.throws(
    () => build({ applicability: HKDF_APPLICABLE, observedSpectrum: spectrum }),
    /must be materialised as 'n\/a', not omitted/,
  );
  assert.doesNotThrow(() => build({
    applicability: HKDF_APPLICABLE,
    observedSpectrum: { ...spectrum, R_interop: 'n/a', R_ser: 'n/a' },
  }));
});

test('an inapplicable relation scored as anything but n/a is refused', () => {
  assert.throws(
    () => build({
      applicability: HKDF_APPLICABLE,
      observedSpectrum: { ...full(), R_interop: 'pass', R_ser: 'n/a' },
    }),
    /scored 'pass'/,
  );
});

test('a NonScoreableCell on an INAPPLICABLE relation is refused -- n/a keeps its domain', () => {
  const { R_interop, ...rest } = full() as Record<string, 'pass'>;
  void R_interop;
  assert.throws(
    () => build({
      applicability: HKDF_APPLICABLE,
      observedSpectrum: { ...rest, R_ser: 'n/a' },
      nonScoreable: [cell('R_interop', 'contractually-non-eligible')],
    }),
    /must never be recorded as unscoreable/,
  );
});

test('an instance belonging to another class is refused -- the intra-M_o boundary', () => {
  assert.throws(
    () => makePhaseCScientificResult({
      mutationId: 'C', operation: 'gcm', gamma0Ref: 'registry:C', applicability: ALL_APPLICABLE,
      observedSpectrum: full(), nonScoreable: [],
      instanceResults: [inst('OTHER-CLASS')],
      detectionSupport: { divergentInstances: 0, evaluatedInstances: 1 },
    }),
    /belongs to another class/,
  );
});

// ---------------------------------------------------------------------
// The bridge to M2
// ---------------------------------------------------------------------

test('a complete result reduces losslessly to RelationSpectrum', () => {
  const spectrum = toRelationSpectrum(build({ observedSpectrum: { ...full(), R_val: 'fail' } }));
  assert.deepEqual(spectrum, { ...full(), R_val: 'fail' });
  assert.equal(Object.keys(spectrum).length, 6);
});

test('a partial result has NO RelationSpectrum, and one is not fabricated', () => {
  const { R_interop, ...rest } = full() as Record<string, 'pass'>;
  void R_interop;
  const partial = build({
    observedSpectrum: rest,
    nonScoreable: [cell('R_interop', 'contractually-non-eligible')],
  });
  assert.equal(isFullyScoreable(partial), false);
  assert.throws(() => toRelationSpectrum(partial), ScientificResultIntegrityError);
  assert.throws(() => toRelationSpectrum(partial), /must not be fabricated/);
});

test('the bridge refuses on the CELL, not merely on a missing key', () => {
  // Both conditions are checked, so a cell can never be dropped while the
  // vector still looks complete.
  const withCellAndFullVector = () => build({
    observedSpectrum: full(), nonScoreable: [cell('R_ser', 'zero-executable-support')],
  });
  assert.throws(withCellAndFullVector, /both scored and recorded non-scoreable/);
});

// ---------------------------------------------------------------------
// Boundaries
// ---------------------------------------------------------------------

test('RelationSpectrum itself is still exactly three values and six required fields', () => {
  const src = readFileSync(new URL('../../../harness/evidence/relation-spectrum.ts', import.meta.url), 'utf8');
  assert.ok(src.includes("export type RelationValue = 'pass' | 'fail' | 'n/a';"));
  assert.equal((src.match(/readonly R_\w+: RelationValue;/g) ?? []).length, 6);
});

test('MutationResult is unmodified: observedSpectrum is still a total RelationSpectrum', () => {
  const src = readFileSync(new URL('../../../harness/evidence/mutation-result.ts', import.meta.url), 'utf8');
  assert.ok(src.includes('readonly observedSpectrum: RelationSpectrum;'));
  assert.ok(!src.includes('Partial<'), 'the frozen M2 type must not gain a partial spectrum');
  assert.ok(!src.includes('nonScoreable'), 'NonScoreable must not leak into the M2 type');
});

test('H11.4-Core boundary: no cross-operation machinery in the new module', () => {
  const src = readFileSync(new URL('../../../harness/evidence/phase-c-scientific-result.ts', import.meta.url), 'utf8');
  for (const forbidden of ['DetectionGain', 'DiagnosticGain', 'Undetermined', 'O_min', 'APPLICABILITY_MATRIX']) {
    assert.ok(!src.includes(forbidden), `Core.2 must not reach for '${forbidden}'`);
  }
});

test('Core.2 introduces no completeness semantics -- that is Core.3', () => {
  const src = readFileSync(new URL('../../../harness/evidence/phase-c-scientific-result.ts', import.meta.url), 'utf8');
  assert.ok(!/readonly complete\b/.test(src),
    'complete must not be reintroduced here by totalising the vector; Core.3 derives it from RequiredEvidence');
});
