// M3-H13.2 -- structural comparability remediation gate.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';

import {
  structuralComparability, structurallyNonComparableRelations,
} from '../../../harness/phase-c/structural-comparability.js';
import { isEnvironmentInvariant, type NonScoreableCause } from '../../../harness/evidence/non-scoreable.js';
import { isRequiredEvidence, makeMutationInstanceResult, type PlannedObservation } from '../../../harness/evidence/mutation-instance-result.js';
import { MUTATION_REGISTRY } from '../../../harness/registry/mutations.js';
import { APPLICABILITY_MATRIX } from '../../../harness/applicability/matrix.js';
import { CHROMIUM_WEBCRYPTO } from '../../../harness/schema/backend-identity.js';
import type { RelationId } from '../../../harness/schema/registry-types.js';

const RELS: readonly RelationId[] = ['R_byte', 'R_interop', 'R_ser', 'R_val', 'R_err', 'R_cap'];
const scope = { kind: 'single-backend', backend: CHROMIUM_WEBCRYPTO } as PlannedObservation['scope'];

function tally() {
  const t: Record<string, { applicable: number; nonComparable: number }> =
    Object.fromEntries(RELS.map((r) => [r, { applicable: 0, nonComparable: 0 }]));
  for (const e of MUTATION_REGISTRY) {
    for (const si of e.stimulusInstances) {
      for (const r of RELS) {
        if (!APPLICABILITY_MATRIX[e.operation][r]) continue;
        t[r]!.applicable += 1;
        if (structuralComparability(e.mutationId, si.stimulusInstanceId, r).value === 'structurally-non-comparable') {
          t[r]!.nonComparable += 1;
        }
      }
    }
  }
  return t;
}

test('H13: the pre-experimental table, derived from frozen premises', () => {
  const t = tally();
  assert.deepEqual(t['R_byte'], { applicable: 62, nonComparable: 48 });
  // M3.7-D2 added the artifact-side PSS population to the R_interop barrier.
  assert.deepEqual(t['R_interop'], { applicable: 81, nonComparable: 45 });
  assert.deepEqual(t['R_ser'], { applicable: 53, nonComparable: 23 });
  assert.deepEqual(t['R_val'], { applicable: 90, nonComparable: 17 });
  assert.deepEqual(t['R_err'], { applicable: 90, nonComparable: 52 });
  assert.deepEqual(t['R_cap'], { applicable: 90, nonComparable: 6 });
});

test("H13: 'comparable' is a BOUND, not a promise", () => {
  // R_ser reading 53/53 must never be read as 'R_ser is always comparable':
  // Comparable_ser's material-availability condition is a RUNTIME one, and a
  // relation with no pre-registered barrier stays REQUIRED and resolves its
  // comparability during execution. That is what preserves
  // insufficient-evidence.
  const src = readFileSync(new URL('../../../harness/phase-c/structural-comparability.ts', import.meta.url), 'utf8');
  assert.ok(src.includes('is a bound, not a promise') || src.includes("'true' is a bound"));
  assert.ok(src.includes('no third'), 'there is deliberately no third `unknown` value');
});

test('H13: structural comparability is PRE-EXPERIMENTAL -- no evidence may reach it', () => {
  const src = readFileSync(new URL('../../../harness/phase-c/structural-comparability.ts', import.meta.url), 'utf8');
  const imports = src.split('\n').filter((l) => l.trimStart().startsWith('import'));
  for (const line of imports) {
    for (const forbidden of ['execution-evidence', 'relation-observation', 'adapters/', 'engine.js', 'src/contract']) {
      assert.ok(!line.includes(forbidden), `no evidence source may reach this decision: ${line.trim()}`);
    }
  }
});

test('H13: Required = Applicable & Eligible & Executable & StructuralComparable', () => {
  const p: PlannedObservation = { relation: 'R_err', scope, executability: { kind: 'required' } };
  assert.equal(isRequiredEvidence(p), true, 'without the set, behaviour is unchanged');
  assert.equal(isRequiredEvidence(p, undefined, new Set<RelationId>(['R_err'])), false);
  // A barrier on one relation does not suppress another's obligation.
  const q: PlannedObservation = { relation: 'R_val', scope, executability: { kind: 'required' } };
  assert.equal(isRequiredEvidence(q, undefined, new Set<RelationId>(['R_err'])), true);
});

test('H13: a structurally non-comparable relation no longer blocks completeness', () => {
  // The exact failure runPhaseC produced: R_err insufficient-evidence for a
  // required scope, outstanding forever, aggregation refusing.
  const planned: PlannedObservation[] = [
    { relation: 'R_err', scope, executability: { kind: 'required' } },
  ];
  const before = makeMutationInstanceResult({
    mutationId: 'HKDF-INFO-TAMPER', stimulusInstanceId: 'default', operation: 'hkdf',
    planned, observations: [],
  });
  assert.equal(before.complete, false, 'this is what blocked M3.5.2');

  const after = makeMutationInstanceResult({
    mutationId: 'HKDF-INFO-TAMPER', stimulusInstanceId: 'default', operation: 'hkdf',
    planned, observations: [],
    structurallyNonComparable: [...structurallyNonComparableRelations('HKDF-INFO-TAMPER', 'default').keys()],
  });
  assert.equal(after.complete, true);
  assert.equal(after.coverage.planned.length, 1, 'and the plan is NOT pruned to achieve it');
});

test('H13: R_interop keeps its specialised cause -- the general dimension is defined THROUGH it', () => {
  const v = structuralComparability('GCM-PROVIDER-CAPABILITY-MISMATCH', 'default', 'R_interop');
  assert.equal(v.value, 'structurally-non-comparable');
  assert.equal(v.cause, 'contractually-non-eligible', 'not renamed, not migrated');
  const w = structuralComparability('GCM-PROVIDER-CAPABILITY-MISMATCH', 'default', 'R_val');
  assert.equal(w.cause, 'structurally-non-comparable');
});

test('H13: every non-comparable verdict names the frozen premise it cannot satisfy', () => {
  for (const e of MUTATION_REGISTRY) {
    for (const si of e.stimulusInstances) {
      for (const [, v] of structurallyNonComparableRelations(e.mutationId, si.stimulusInstanceId)) {
        assert.ok(v.premise !== undefined && v.premise.length > 20, `${e.mutationId}: a barrier must name its premise`);
        assert.ok(v.cause !== undefined);
      }
    }
  }
});

test('H13: the new cause is environment-invariant; only zero-executable-support is not', () => {
  const causes: NonScoreableCause[] =
    ['contractually-non-eligible', 'zero-executable-support', 'structurally-non-comparable'];
  assert.equal(causes.length, 3);
  assert.equal(isEnvironmentInvariant('structurally-non-comparable'), true,
    'no backend can create an error class the contract does not determine');
  assert.equal(isEnvironmentInvariant('contractually-non-eligible'), true);
  assert.equal(isEnvironmentInvariant('zero-executable-support'), false);
});

test('H13: the eleven declarative fixtures are non-comparable in three relations at once', () => {
  const declarative = [
    'HKDF-CAPABILITY-BOUNDARY-MISMATCH', 'GCM-PROVIDER-CAPABILITY-MISMATCH', 'GCM-ERROR-MISCLASSIFICATION',
    'OAEP-DECRYPT-ERROR-DISCLOSURE', 'OAEP-PROVIDER-CAPABILITY-MISREPORT', 'PSS-ERROR-MISCLASSIFICATION',
    'PSS-PROVIDER-CAPABILITY-MISREPORT', 'RSA-SER-ERROR-MISCLASSIFICATION', 'RSA-SER-PROVIDER-CAPABILITY-MISREPORT',
    'EC-ERROR-MAP-SWAP', 'EC-CAPABILITY-MANIFEST-MISMATCH',
  ];
  for (const id of declarative) {
    const m = structurallyNonComparableRelations(id, 'default');
    assert.ok(m.has('R_val'), `${id}: no expected validation decision`);
    assert.ok(m.has('R_err'), `${id}: no expected error`);
    if (APPLICABILITY_MATRIX[MUTATION_REGISTRY.find((e) => e.mutationId === id)!.operation]['R_interop']) {
      assert.ok(m.has('R_interop'), `${id}: no operational flow`);
    }
  }
  // Recorded as an architectural result: one family of fixtures, reappearing
  // in three audits that looked unrelated. NOT a fixture category that
  // decides three relations automatically -- each verdict is still derived
  // from its own frozen premise.
  assert.equal(declarative.length, 11);
});
