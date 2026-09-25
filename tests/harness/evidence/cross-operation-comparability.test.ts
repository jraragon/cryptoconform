// Bloque B / M3-H12 -- property tests for cross-operation comparability.
//
// Only the invariants that bear on the instrument and the dataset.
// DetectionGain, DiagnosticGain, Keep and O_min are M5 machinery and are
// deliberately not implemented, so they are not tested here either.

import { test } from 'node:test';
import assert from 'node:assert/strict';

import { readFileSync } from 'node:fs';
import {
  comparePatterns, decidableByMaskAlone, jointlyApplicable, scoreableDomain,
  M5_DATASET_REQUIREMENTS,
} from '../../../harness/evidence/cross-operation-comparability.js';
import {
  makePhaseCScientificResult, ALL_RELATION_IDS,
  type PartialRelationSpectrum, type PhaseCScientificMutationResult,
} from '../../../harness/evidence/phase-c-scientific-result.js';
import type { NonScoreableCell } from '../../../harness/evidence/non-scoreable.js';
import { APPLICABILITY_MATRIX } from '../../../harness/applicability/matrix.js';
import { MUTATION_REGISTRY } from '../../../harness/registry/mutations.js';
import type { RelationApplicability, RelationId } from '../../../harness/schema/registry-types.js';
import type { OperationId } from '../../../harness/schema/capability.js';
import type { MutationInstanceResult } from '../../../harness/evidence/mutation-instance-result.js';

const OPS: readonly OperationId[] = ['hkdf', 'gcm', 'oaep', 'pss', 'rsa-ser', 'ec-ser'];
const A = (o: OperationId): RelationApplicability => APPLICABILITY_MATRIX[o];

const instance = (mutationId: string): MutationInstanceResult => ({
  mutationId, stimulusInstanceId: 'default', operation: 'gcm', observations: [],
  coverage: { planned: [], reached: [], outstanding: [] }, complete: true,
});

/** Builds a class of `op` scoring `value` everywhere applicable, minus `absent`. */
function classOf(
  mutationId: string, op: OperationId, value: 'pass' | 'fail', absent: readonly RelationId[] = [],
): PhaseCScientificMutationResult {
  const applicability = APPLICABILITY_MATRIX[op];
  const spectrum: Record<string, string> = {};
  const nonScoreable: NonScoreableCell[] = [];
  for (const r of ALL_RELATION_IDS) {
    if (!applicability[r]) { spectrum[r] = 'n/a'; continue; }
    if (absent.includes(r)) {
      nonScoreable.push({ mutationId, operation: op, relation: r, cause: 'contractually-non-eligible', stimulusInstanceIds: ['default'] });
      continue;
    }
    spectrum[r] = value;
  }
  return makePhaseCScientificResult({
    mutationId, operation: op, gamma0Ref: `registry:${mutationId}`, applicability,
    observedSpectrum: spectrum as PartialRelationSpectrum, nonScoreable,
    instanceResults: [instance(mutationId)],
    detectionSupport: { divergentInstances: 0, evaluatedInstances: 1 },
  });
}

// =====================================================================
// The structural fact that repairs H12
// =====================================================================

test('J is never empty, and R_val/R_err/R_cap are applicable to all six operations', () => {
  const universal = ALL_RELATION_IDS.filter((r) => OPS.every((o) => A(o)[r]));
  assert.deepEqual([...universal], ['R_val', 'R_err', 'R_cap']);
  let min = Infinity;
  for (let i = 0; i < OPS.length; i++) {
    for (let j = i + 1; j < OPS.length; j++) {
      const J = jointlyApplicable(A(OPS[i]!), A(OPS[j]!));
      assert.ok(J.length > 0, `${OPS[i]} x ${OPS[j]}: J must never be empty`);
      min = Math.min(min, J.length);
    }
  }
  assert.equal(min, 3);
});

test('n/a is structurally absent from J -- the mask cannot enter the comparison', () => {
  // The single fact the remedy rests on. Checked over every operation pair
  // and every relation of J, not argued.
  for (let i = 0; i < OPS.length; i++) {
    for (let j = i + 1; j < OPS.length; j++) {
      const a = classOf('A', OPS[i]!, 'pass');
      const b = classOf('B', OPS[j]!, 'pass');
      for (const r of jointlyApplicable(a.applicability, b.applicability)) {
        assert.notEqual(a.observedSpectrum[r], 'n/a');
        assert.notEqual(b.observedSpectrum[r], 'n/a');
      }
    }
  }
});

test('CRITERION 1: the applicability mask alone can decide no comparison', () => {
  for (let i = 0; i < OPS.length; i++) {
    for (let j = 0; j < OPS.length; j++) {
      assert.equal(decidableByMaskAlone(A(OPS[i]!), A(OPS[j]!)), false);
    }
  }
});

test('two classes of DIFFERENT operations agreeing throughout J are `same`, not `different`', () => {
  // Under the frozen literal equality these were different by construction:
  // HKDF has R_byte where OAEP has n/a, and R_interop the other way round.
  const a = classOf('A', 'hkdf', 'pass');
  const b = classOf('B', 'oaep', 'pass');
  assert.equal(comparePatterns(a, b), 'same');
});

test('a witness inside J still yields `different`', () => {
  assert.equal(comparePatterns(classOf('A', 'hkdf', 'pass'), classOf('B', 'oaep', 'fail')), 'different');
});

// =====================================================================
// Criterion 2 -- absence cannot create equality
// =====================================================================

test('CRITERION 2: a missing cell inside J yields `undetermined`, never `same`', () => {
  const a = classOf('A', 'gcm', 'pass', ['R_val']); // R_val is in every J
  const b = classOf('B', 'oaep', 'pass');
  assert.equal(comparePatterns(a, b), 'undetermined');
});

test('a missing cell OUTSIDE J does not disturb the comparison', () => {
  // R_ser is not jointly applicable to GCM and OAEP, so losing it changes
  // nothing: it was never comparable in the first place.
  const a = classOf('A', 'gcm', 'pass', ['R_ser']);
  const b = classOf('B', 'oaep', 'pass');
  assert.equal(comparePatterns(a, b), 'same');
});

test('a witness survives even when other cells are missing -- difference needs only one', () => {
  const a = classOf('A', 'gcm', 'pass', ['R_val']);
  const b = classOf('B', 'oaep', 'fail');
  assert.equal(comparePatterns(a, b), 'different', 'R_err and R_cap still witness it');
});

// =====================================================================
// Criterion 3 -- monotonicity, the property that makes exclusivity safe
// =====================================================================

test('CRITERION 3: removing evidence can turn `different` into `undetermined`, never the reverse', () => {
  const b = classOf('B', 'oaep', 'pass');
  // Ablate one relation of J at a time and check the verdict never improves.
  const J = jointlyApplicable(A('gcm'), b.applicability);
  for (const witness of J) {
    // a differs from b exactly at `witness`
    const spectrum: Record<string, string> = {};
    for (const r of ALL_RELATION_IDS) {
      if (!A('gcm')[r]) { spectrum[r] = 'n/a'; continue; }
      spectrum[r] = r === witness ? 'fail' : 'pass';
    }
    const full = makePhaseCScientificResult({
      mutationId: 'A', operation: 'gcm', gamma0Ref: 'registry:A', applicability: A('gcm'),
      observedSpectrum: spectrum as PartialRelationSpectrum, nonScoreable: [],
      instanceResults: [instance('A')], detectionSupport: { divergentInstances: 0, evaluatedInstances: 1 },
    });
    assert.equal(comparePatterns(full, b), 'different');

    // Now lose exactly the witness. The only admissible outcomes are
    // 'undetermined' or 'different' (if another witness remains) -- never
    // 'same', which would be evidence created by evidence loss.
    const ablated = classOf('A', 'gcm', 'pass', [witness]);
    assert.notEqual(comparePatterns(ablated, b), 'same',
      `losing ${witness} must not manufacture agreement`);
  }
});

test('CRITERION 3: `same` degrades to `undetermined` under ablation, never to `different`', () => {
  const b = classOf('B', 'oaep', 'pass');
  for (const r of jointlyApplicable(A('gcm'), b.applicability)) {
    const ablated = classOf('A', 'gcm', 'pass', [r]);
    assert.equal(comparePatterns(ablated, b), 'undetermined');
  }
});

// =====================================================================
// The decisive check: Keep(HKDF) must not be decidable before M4
// =====================================================================

test('HKDF: under the FROZEN literal equality, all 8 classes are structurally unique', () => {
  // The baseline, reproduced rather than asserted, so the repair has
  // something measured to be a repair of.
  const hkdf = MUTATION_REGISTRY.filter((e) => e.operation === 'hkdf');
  const foreign = MUTATION_REGISTRY.filter((e) => e.operation !== 'hkdf');
  assert.equal(hkdf.length, 8);
  let unique = 0;
  for (const c of hkdf) {
    const allDiffer = foreign.every((f) =>
      ALL_RELATION_IDS.some((r) => A(c.operation)[r] !== A(f.operation)[r]));
    if (allDiffer) unique += 1;
  }
  assert.equal(unique, 8, 'DetectionGain(HKDF) was non-empty and Keep(HKDF) true by construction');
});

test('HKDF: under the prospective definition, NO comparison is decided before M4', () => {
  const hkdfOps = new Set(['hkdf']);
  for (const o of OPS) {
    if (hkdfOps.has(o)) continue;
    assert.equal(decidableByMaskAlone(A('hkdf'), A(o)), false);
    // And the verdict genuinely depends on the observed values, both ways.
    assert.equal(comparePatterns(classOf('H', 'hkdf', 'pass'), classOf('F', o, 'pass')), 'same');
    assert.equal(comparePatterns(classOf('H', 'hkdf', 'pass'), classOf('F', o, 'fail')), 'different');
  }
});

test('HKDF: the repair does not make necessity IMPOSSIBLE either', () => {
  // The symmetric failure mode. HKDF must still be able to come out
  // necessary on evidence -- R_byte is jointly applicable with GCM, which is
  // exactly the comparison H_HKDF is about.
  const J = jointlyApplicable(A('hkdf'), A('gcm'));
  assert.ok(J.includes('R_byte'), 'H_HKDF is a claim about R_byte against AES-GCM, and R_byte is in J');
  assert.equal(comparePatterns(classOf('H', 'hkdf', 'fail'), classOf('G', 'gcm', 'pass')), 'different');
});

test('H_RSA-ser and H_OAEP: their own comparisons keep the relations they rest on', () => {
  // H_RSA-ser rests on (R_ser, R_val, R_err, R_cap) against EC-ser.
  const jSer = jointlyApplicable(A('rsa-ser'), A('ec-ser'));
  for (const r of ['R_ser', 'R_val', 'R_err', 'R_cap'] as const) assert.ok(jSer.includes(r));
  // H_OAEP rests on R_interop, and OAEP's competitors in that relation are
  // GCM, PSS, RSA-ser and EC-ser -- all of which retain it in J.
  for (const o of ['gcm', 'pss', 'rsa-ser', 'ec-ser'] as const) {
    assert.ok(jointlyApplicable(A('oaep'), A(o)).includes('R_interop'));
  }
});

// =====================================================================
// Scope and dataset sufficiency
// =====================================================================

test('M3 does not implement the M5 quantities', () => {
  const text = readFileSync(new URL('../../../harness/evidence/cross-operation-comparability.ts', import.meta.url), 'utf8');
  for (const forbidden of ['function detectionGain', 'function diagnosticGain', 'function keep']) {
    assert.ok(!text.toLowerCase().includes(forbidden), `M3 must not implement '${forbidden}'`);
  }
});

test('dataset sufficiency: everything comparePatterns needs is in the scientific result', () => {
  const a = classOf('A', 'gcm', 'pass', ['R_ser']);
  for (const field of M5_DATASET_REQUIREMENTS.satisfiedByBundle) {
    assert.ok(field in a || field === 'detectionSupport', `${field} must travel with the result`);
  }
  // The one thing that does NOT travel, recorded rather than assumed:
  assert.deepEqual([...M5_DATASET_REQUIREMENTS.requiresRegistryBinding], ['gamma0']);
  assert.equal(typeof a.gamma0Ref, 'string', 'only a reference, never a copy');
});

test('S_c composes the two restrictions rather than applying them in sequence', () => {
  const a = classOf('A', 'oaep', 'pass', ['R_interop']);
  const s = scoreableDomain(a);
  assert.ok(!s.includes('R_byte'), 'not applicable to OAEP (H12 axis)');
  assert.ok(!s.includes('R_interop'), 'applicable but non-scoreable (H11 axis)');
  assert.deepEqual([...s], ['R_val', 'R_err', 'R_cap']);
});

