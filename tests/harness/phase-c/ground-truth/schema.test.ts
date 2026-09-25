import { test } from 'node:test';
import assert from 'node:assert/strict';

import {
  resolveGroundTruth,
  type GroundTruthTable, type ClassGroundTruth, type RelationGroundTruth,
  type SerializationObservationBasis, type ErrorExpectation, type GroundTruthProvenance,
} from '../../../../harness/phase-c/ground-truth/schema.js';

// ---------------------------------------------------------------------
// M3-H9.2a -- schema design only. These tests assert the STRUCTURE, never
// any scientific value: nothing is populated until H9.3.
// ---------------------------------------------------------------------

const contractDerived: GroundTruthProvenance = {
  kind: 'contract-derived', clauseIds: ['gcm.tagLength'] as never,
};
const m3Decision: GroundTruthProvenance = {
  kind: 'm3-normative-decision', rationale: 'schema test fixture', decidedIn: 'M3-H9.2a',
};

// --- Provenance distinguishes the two kinds of gap ------------------------

test('M3-H9.2a: provenance is a union -- a contract-derived premise cannot omit its clauses', () => {
  // The two H9.1 categories are structurally different, not a free-text
  // label: contract-derived REQUIRES clauseIds, m3-normative-decision
  // REQUIRES a rationale. Neither can masquerade as the other.
  assert.equal(contractDerived.kind, 'contract-derived');
  if (contractDerived.kind === 'contract-derived') {
    assert.ok(Array.isArray(contractDerived.clauseIds));
  }
  assert.equal(m3Decision.kind, 'm3-normative-decision');
  if (m3Decision.kind === 'm3-normative-decision') {
    assert.ok(m3Decision.rationale.length > 0);
    assert.ok(m3Decision.decidedIn.length > 0);
  }
});

// --- The empty serialization basis is unconstructible ----------------------

test('M3-H9.2a: SerializationObservationBasis has exactly the three frozen values', () => {
  const all: SerializationObservationBasis[] = [
    'representation-conformance', 'material-preservation', 'both',
  ];
  assert.equal(all.length, 3);
  // The executable type previously used two independent booleans, admitting
  // {rep:false, material:false} -- an R_ser observation requiring no check,
  // which the frozen design does not define. The union removes that state
  // by construction rather than by validation.
  assert.equal(new Set(all).size, 3);
});

// --- Absence of an expected error is a stated case, not a missing field ---

test('M3-H9.2a: no-error-expected must be STATED, with a reason', () => {
  const expected: ErrorExpectation = { kind: 'error-expected', errorClass: 'invalid_key' };
  const absent: ErrorExpectation = {
    kind: 'no-error-expected',
    reason: 'the contractually correct outcome carries no observable error class',
  };
  assert.equal(expected.kind, 'error-expected');
  assert.equal(absent.kind, 'no-error-expected');
  if (absent.kind === 'no-error-expected') assert.ok(absent.reason.length > 0);
  // An undefined field would be indistinguishable from "not yet decided";
  // the union forces the distinction. This is the verified(false) trap that
  // Comparable_err condition 4 guards against.
});

// --- Class default with stimulus override ---------------------------------

function table(entries: ClassGroundTruth[]): GroundTruthTable {
  return new Map(entries.map((e) => [e.mutationId, e]));
}

test('M3-H9.2a: a class without overrides resolves to its default for every stimulus', () => {
  const def: RelationGroundTruth = {
    expectedValidation: { decision: { kind: 'reject' }, provenance: m3Decision },
  };
  const t = table([{ mutationId: 'X', operation: 'gcm', classDefault: def }]);
  assert.equal(resolveGroundTruth(t, 'X', 'default'), def);
  assert.equal(resolveGroundTruth(t, 'X', 'another-stimulus'), def,
    '74 of 79 classes are single-stimulus; the default must serve them without duplication');
});

test('M3-H9.2a: an override applies to its own stimulus ONLY', () => {
  const def: RelationGroundTruth = {
    expectedValidation: { decision: { kind: 'reject' }, provenance: m3Decision },
  };
  const override: RelationGroundTruth = {
    expectedValidation: { decision: { kind: 'accept' }, provenance: m3Decision },
  };
  const t = table([{
    mutationId: 'Y', operation: 'gcm', classDefault: def,
    stimulusOverrides: new Map([['s2', override]]),
  }]);
  assert.equal(resolveGroundTruth(t, 'Y', 's1'), def);
  assert.equal(resolveGroundTruth(t, 'Y', 's2'), override);
  // An override's mere existence is a positive statement that this stimulus
  // differs -- the distinction M3-H6 had to recover for executability.
});

test('M3-H9.2a: an unknown class resolves to undefined, never to a fabricated default', () => {
  const t = table([]);
  assert.equal(resolveGroundTruth(t, 'NO-SUCH', 'default'), undefined);
});

// --- Layer separation ------------------------------------------------------

test('M3-H9.2a: the schema imports nothing from the execution or evidence layers', async () => {
  const { readFileSync } = await import('node:fs');
  const src = readFileSync(new URL('../../../../harness/phase-c/ground-truth/schema.ts', import.meta.url), 'utf8');
  const imports = src.split('\n').filter((l) => l.trimStart().startsWith('import'));
  for (const line of imports) {
    for (const forbidden of ['/evidence/', '/orchestration/', '/evaluators/', '/aggregation/']) {
      assert.ok(!line.includes(forbidden),
        `ground truth must not depend on execution or evidence: ${line.trim()}`);
    }
  }
  // ExecutionPlan = StructuralPlan + NormativeGroundTruth + Executability,
  // never ObservedEvidence -> ExpectedOutcome.
  assert.ok(src.includes('src/contract/'), 'it may depend on the frozen contract, which is its source');
});

test('M3-H9.2a: nothing is populated yet -- this step designs structure only', async () => {
  const { readFileSync } = await import('node:fs');
  const src = readFileSync(new URL('../../../../harness/phase-c/ground-truth/schema.ts', import.meta.url), 'utf8');
  // No GroundTruthTable instance and no mutationId literal may appear: the
  // 79 classes are populated in H9.3, after the scientific decisions.
  assert.ok(!src.includes('new Map(['), 'no populated table may appear in the schema');
  const { MUTATION_REGISTRY } = await import('../../../../harness/registry/mutations.js');
  for (const e of MUTATION_REGISTRY) {
    assert.ok(!src.includes(e.mutationId), `found a populated entry for ${e.mutationId}`);
  }
});
