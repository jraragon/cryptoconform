// M3.6 -- Infrastructure Freeze Gate.
//
// The cumulative gate. No new construction: what this proves is that the
// instrument M4 will run is the one M3 built, that its known deviations are
// recorded in one place, and that the residual exposure is what it is claimed
// to be rather than merely asserted.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

import { isEnvironmentInvariant, type NonScoreableCause } from '../../harness/evidence/non-scoreable.js';
import { toRelationSpectrum, ScientificResultIntegrityError } from '../../harness/evidence/phase-c-scientific-result.js';
import { makePhaseCScientificResult } from '../../harness/evidence/phase-c-scientific-result.js';
import { assembleStructuralPlan } from '../../harness/phase-c/plan-assembly.js';
import { loadFrozenMaterialPool } from '../../harness/phase-c/material/load.js';
import { recountPlan } from '../../harness/phase-c/plan-binding-audit.js';
import { auditGroundTruth } from '../../harness/phase-c/ground-truth/resolve.js';
import { auditRegistry } from '../../harness/phase-c/interop-eligibility/resolve.js';
import { allRegistryEntryHashes } from '../../harness/evidence/registry-binding.js';
import type { MutationInstanceResult } from '../../harness/evidence/mutation-instance-result.js';
import type { RelationApplicability } from '../../harness/schema/registry-types.js';

const repoRoot = fileURLToPath(new URL('../../', import.meta.url));

// =====================================================================
// M3.6.1 -- the accumulated deviation entry exists, in ONE place
// =====================================================================

test('M3.6.1: a single formal deviation entry, covering every item', () => {
  const doc = readFileSync(`${repoRoot}M3-DEVIATIONS.md`, 'utf8');
  // The distinction the entry exists to keep.
  assert.ok(doc.includes('M2 historical freeze remains UNTOUCHED'));
  assert.ok(doc.includes('M3 prospective remediation defines the instrument FROZEN FOR M4'));
  // Every item the freeze must record.
  for (const item of [
    'Completeness measures obligation', 'NonScoreable', 'EvidenceBundle v2.0',
    'InteropEligibility', 'StructuralComparable', 'structurally-non-comparable',
    'RequiredEvidence', 'registryEntryHash', 'M3-H12', 'Analysis disposition to M5',
    'residual exposure',
  ]) {
    assert.ok(doc.includes(item), `the deviation entry must record '${item}'`);
  }
  // And it must state the assumption that failed, since that is what makes
  // the list a diagnosis rather than a changelog.
  assert.ok(doc.includes('at least one **scoreable** result at class level'),
    'the entry must state the assumption that failed, which is what makes it a diagnosis rather than a changelog');
});

test('M3.6.1: the frozen M2 artifacts are named as unmodified', () => {
  const doc = readFileSync(`${repoRoot}M3-DEVIATIONS.md`, 'utf8');
  assert.ok(doc.includes('4869a991'), 'the M2 TAR is identified');
  assert.ok(doc.includes('18f157b7'), 'and its commit');
});

// =====================================================================
// M3.6.2 -- the residual exposure is production-unreachable, PROVEN
// =====================================================================

test('M3.6.2: no production path builds a MutationResult without the strict bridge', () => {
  // Call-site inspection: every production construction of a MutationResult
  // must pass observedSpectrum through toRelationSpectrum.
  const out = execFileSync('grep', ['-rn', 'makeMutationResult(', `${repoRoot}harness`], { encoding: 'utf8' })
    .split('\n').filter((l) => l.length > 0 && !l.includes('export function'));
  assert.ok(out.length > 0, 'there must be at least one production call site to inspect');
  for (const line of out) {
    const file = line.split(':')[0]!;
    const src = readFileSync(file, 'utf8');
    assert.ok(src.includes('toRelationSpectrum('),
      `${file} constructs a MutationResult without the strict bridge`);
  }
  // Exactly ONE cast to RelationSpectrum exists in production, and it is the
  // last line of toRelationSpectrum itself -- after both refusals, when every
  // cell has been proven present. Anywhere else it would be the unsafe cast
  // this residual is about.
  const casts = execFileSync('bash', ['-c',
    `grep -rn "as RelationSpectrum" ${repoRoot}harness || true`], { encoding: 'utf8' })
    .split('\n').filter((l) => l.length > 0);
  assert.equal(casts.length, 1, `expected one guarded cast, found:\n${casts.join('\n')}`);
  assert.ok(casts[0]!.includes('phase-c-scientific-result.ts'), 'and only inside the strict bridge');
});

test('M3.6.2: the bridge itself refuses a partial result, both ways', () => {
  const inst: MutationInstanceResult = {
    mutationId: 'C', stimulusInstanceId: 'default', operation: 'gcm', observations: [],
    coverage: { planned: [], reached: [], outstanding: [] }, complete: true,
  };
  const applicability: RelationApplicability =
    { R_byte: true, R_interop: true, R_ser: true, R_val: true, R_err: true, R_cap: true };
  const partial = makePhaseCScientificResult({
    mutationId: 'C', operation: 'gcm', gamma0Ref: 'registry:C', applicability,
    observedSpectrum: { R_byte: 'pass', R_ser: 'pass', R_val: 'pass', R_err: 'pass', R_cap: 'pass' },
    nonScoreable: [{
      mutationId: 'C', operation: 'gcm', relation: 'R_interop',
      cause: 'structurally-non-comparable', stimulusInstanceIds: ['default'],
    }],
    instanceResults: [inst], detectionSupport: { divergentInstances: 0, evaluatedInstances: 1 },
  });
  assert.throws(() => toRelationSpectrum(partial), ScientificResultIntegrityError);
  assert.throws(() => toRelationSpectrum(partial), /must not be fabricated/);
});

// =====================================================================
// M3.6.3 -- the taxonomy M4 and M5 will need to read the dataset
// =====================================================================

test('M3.6.3: three causes, and exactly one is environmentally reversible', () => {
  const causes: readonly NonScoreableCause[] =
    ['contractually-non-eligible', 'zero-executable-support', 'structurally-non-comparable'];
  const reversible = causes.filter((c) => !isEnvironmentInvariant(c));
  assert.deepEqual(reversible, ['zero-executable-support'],
    'an absent cell means something different in each case, and only this one is an artefact of the environment');
  const doc = readFileSync(`${repoRoot}M3-DEVIATIONS.md`, 'utf8');
  for (const c of causes) assert.ok(doc.includes(c), `the freeze must name '${c}'`);
});

// =====================================================================
// M3.6.3 -- the frozen cardinalities, all from the instrument itself
// =====================================================================

test('M3.6.3: the instrument reports the frozen figures', () => {
  const plan = assembleStructuralPlan(loadFrozenMaterialPool());
  const rc = recountPlan(plan);
  const gt = auditGroundTruth();
  const el = auditRegistry();

  assert.equal(plan.classes.length, 79);
  assert.equal(gt.pairs, 90);
  assert.equal(el.totalPairs, 81);
  assert.deepEqual(
    { eligible: el.eligible, blocked: el.producerContractuallyBlocked, noInput: el.noOperationalInput },
    { eligible: 55, blocked: 16, noInput: 10 },
  );
  assert.equal(rc.planned, 1641);
  // M3.7.1 -- D13 repaired. These were 1416/225 under the pre-H13 definition
  // of Required; the counter now consumes isRequiredEvidence itself.
  assert.equal(rc.required, 886);
  assert.equal(rc.notRequiredDistinct, 755);
  // The union over THREE causes, never the sum.
  const union =
    rc.notRequiredContractuallyNonEligible + rc.notRequiredStructurallyNonComparable + rc.notRequiredNotExecutable
    - rc.overlapNonEligibleAndNotExecutable - rc.overlapNonComparableAndNotExecutable
    - rc.overlapNonEligibleAndNonComparable;
  assert.equal(union, rc.notRequiredDistinct);
  assert.equal(rc.required + rc.notRequiredDistinct, rc.planned);
  assert.equal(allRegistryEntryHashes().size, 79);
});

test('M3.6.3: the transported snapshot preserves the frozen evidence shapes', () => {
  // Historical Git-boundary verification is performed externally before
  // freezing. This portable gate validates the transported snapshot itself.
  // RelationSpectrum and MutationResult keep their frozen shapes.
  const spec = readFileSync(`${repoRoot}harness/evidence/relation-spectrum.ts`, 'utf8');
  assert.ok(spec.includes("export type RelationValue = 'pass' | 'fail' | 'n/a';"));
  assert.equal((spec.match(/readonly R_\w+: RelationValue;/g) ?? []).length, 6);
  const mr = readFileSync(`${repoRoot}harness/evidence/mutation-result.ts`, 'utf8');
  assert.ok(mr.includes('readonly observedSpectrum: RelationSpectrum;'));
  assert.ok(!mr.includes('nonScoreable'));
});
