// M3.9-A -- the capability evidence contract. No data, no acquisition.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';

import {
  assertBackendComparability, assertBasisPinCompatible, assertDomainUsableForBoundaryClaim,
  assertEvidenceDisjoint, CapabilityContractError, compareBinaryClaim,
  domainMembershipIsDecidable, expectedBoundaryState, isDeclared, PROBE_KIND_BY_CLAIM_KIND,
  probeKindFor, type DeclarationLookup,
} from '../../../harness/capability/evidence-contract.js';
import type { CapabilityDomainSpec } from '../../../harness/schema/capability.js';

test('D1: three rows, one per claim kind, each with its reason', () => {
  assert.deepEqual(Object.keys(PROBE_KIND_BY_CLAIM_KIND).sort(),
    ['interface-exposure', 'portable-boundary', 'provider-support']);
  assert.equal(probeKindFor('interface-exposure'), 'api-surface-inspection');
  assert.equal(probeKindFor('portable-boundary'), 'operation-execution');
  assert.equal(probeKindFor('provider-support'), 'runtime-probe');
  for (const [k, row] of Object.entries(PROBE_KIND_BY_CLAIM_KIND)) {
    assert.ok(row.why.length > 50, `${k}: a decision needs a reason, not a label`);
  }
});

test('D1: the decision is recorded as PROSPECTIVE, not as inherited', () => {
  const src = readFileSync(new URL('../../../harness/capability/evidence-contract.ts', import.meta.url), 'utf8');
  assert.ok(src.includes('PROSPECTIVE M3.9 DECISION, not inherited'));
  assert.ok(src.includes('semantic naturalness is not a normative rule'));
});

test('D1: an unfixed claim kind is refused, never chosen at run time', () => {
  assert.throws(() => probeKindFor('mystery' as never), CapabilityContractError);
  assert.throws(() => probeKindFor('mystery' as never), /Refusing rather than choosing one during execution/);
});

test("D2': withdrawn -- a declaration MAY derive from an execution", () => {
  // M3.9-A excluded 'execution-derived' by construction. The frozen model
  // practices exactly that pattern: M1 execution -> manifest declaration,
  // fresh M4 execution -> observed capability. D2 forbade something
  // legitimate, which reads as caution and is the worse kind of error.
  const src = readFileSync(new URL('../../../harness/capability/evidence-contract.ts', import.meta.url), 'utf8');
  assert.ok(src.includes("D2' -- SUPERSEDED by the frozen rule (M2.3.4)"));
  assert.ok(src.includes('withdrawn, not weakened'));
  assert.ok(!src.includes('ADMISSIBLE_PROVENANCE'), 'the provenance whitelist is gone, not softened');
});

test('D3: absence is not a negative declaration', () => {
  const none: DeclarationLookup<never> = { kind: 'none' };
  assert.equal(isDeclared(none), false);
  // The frozen schema gains no 'unknown': the union is untouched.
  const schema = readFileSync(new URL('../../../harness/schema/capability.ts', import.meta.url), 'utf8');
  assert.ok(schema.includes("readonly support: 'supported' | 'unsupported';"));
  assert.ok(!schema.includes("'supported' | 'unsupported' | 'unknown'"));
});

test('D4: the two binary kinds compare state against state', () => {
  assert.equal(compareBinaryClaim({ state: 'supported' }, { state: 'supported' }), 'pass');
  assert.equal(compareBinaryClaim({ state: 'exposed' }, { state: 'not-exposed' }), 'fail');
});

test('D5.1: four of five domain specs are decidable; coupled-parameters is not', () => {
  const specs: CapabilityDomainSpec[] = [
    { kind: 'enum', values: ['a'] },
    { kind: 'integer-set', values: [128] },
    { kind: 'fixed-bytes', length: 12 },
    { kind: 'constant', value: 1 },
  ];
  for (const s of specs) {
    assert.equal(domainMembershipIsDecidable(s), true, s.kind);
    assert.doesNotThrow(() => assertDomainUsableForBoundaryClaim(s));
  }
  const coupled: CapabilityDomainSpec = { kind: 'coupled-parameters', constraints: ['iv and tag are linked'] };
  assert.equal(domainMembershipIsDecidable(coupled), false);
  assert.throws(() => assertDomainUsableForBoundaryClaim(coupled), /not mechanically decidable/);
});

test('D5: Expected_D(x) is membership, and nothing else', () => {
  assert.equal(expectedBoundaryState(true), 'allowed');
  assert.equal(expectedBoundaryState(false), 'forbidden');
});

test("D7': disjointness over CONCRETE EVIDENCE IDENTITY, never over mechanism", () => {
  // The legitimate case the freeze resolves explicitly: same operation, same
  // mechanism, different executions.
  assert.doesNotThrow(() => assertEvidenceDisjoint({
    declarationEvidenceIds: ['M1-hkdf-001'], scoredEvidenceIds: ['M4-hkdf-777'],
  }));
  // The forbidden case: one identical ExecutionID on both sides.
  assert.throws(() => assertEvidenceDisjoint({
    declarationEvidenceIds: ['E-1', 'E-2'], scoredEvidenceIds: ['E-2'],
  }), /tautological by construction/);
});

test("D7': backend comparability is the FULL tuple, never family alone", () => {
  const a = { family: 'cryptopp', apiVersion: '8.9', sourcePin: 'abc', apiSurface: 'cryptopp-generic-api' };
  assert.doesNotThrow(() => assertBackendComparability(a, a));
  assert.throws(() => assertBackendComparability(a, { ...a, sourcePin: 'def' }), /never family alone/);
  assert.throws(() => assertBackendComparability(a, { ...a, apiVersion: '8.8' }), /apiVersion/);
});

test("D7': a backend-documentation basis must be pin-compatible", () => {
  // The real case: pss.provider.explicit-salt-bytes is valid for Bouncy
  // Castle only because the pinned jar falls within D-042's scope.
  assert.doesNotThrow(() => assertBasisPinCompatible({
    basisKind: 'backend-documentation', basisBackendPin: 'jar-1.77', manifestSourcePin: 'jar-1.77',
  }));
  assert.throws(() => assertBasisPinCompatible({
    basisKind: 'backend-documentation', manifestSourcePin: 'jar-1.77',
  }), /a library-wide claim is not a declaration about the pinned artifact/);
  assert.throws(() => assertBasisPinCompatible({
    basisKind: 'backend-documentation', basisBackendPin: 'jar-1.70', manifestSourcePin: 'jar-1.77',
  }), /is not the manifest's/);
  // A non-pin-specific basis is unaffected.
  assert.doesNotThrow(() => assertBasisPinCompatible({
    basisKind: 'm1-execution', manifestSourcePin: 'jar-1.77',
  }));
});

test('M3.9-A carries no data and no acquisition', () => {
  const src = readFileSync(new URL('../../../harness/capability/evidence-contract.ts', import.meta.url), 'utf8');
  const imports = src.split('\n').filter((l) => l.trimStart().startsWith('import'));
  for (const line of imports) {
    for (const forbidden of ['orchestration/', 'engine.js', 'execution-evidence', 'material/']) {
      assert.ok(!line.includes(forbidden), `the contract must define, not acquire: ${line.trim()}`);
    }
  }
  assert.ok(!src.includes('async '), 'nothing here executes anything');
});

test('M3.9-A changes no applicability, aggregation or cardinality', () => {
  const doc = readFileSync(new URL('../../../M3.9-CAPABILITY-EVIDENCE-CONTRACT.md', import.meta.url), 'utf8');
  assert.ok(doc.includes('1641 = 1246 + 395'));
  assert.ok(doc.includes('never defined, not something that was defined wrongly'));
});
