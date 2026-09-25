// M3-H9.3a-3.2.5b -- structural guards for the InteropEligibility registry.
//
// This file checks the registry as a NORMATIVE ARTIFACT: that it is total,
// unique, correctly scoped, non-redundant, pinned and serializable. It
// deliberately does NOT re-derive any eligibility value from the contract --
// that is the independent regression probe's own job, in the sibling file,
// and keeping the two apart is what makes the probe a refutation rather
// than a restatement.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';

import { MUTATION_REGISTRY } from '../../../../harness/registry/mutations.js';
import { APPLICABILITY_MATRIX } from '../../../../harness/applicability/matrix.js';
import { INTEROP_ELIGIBILITY_REGISTRY } from '../../../../harness/phase-c/interop-eligibility/registry.js';
import {
  auditRegistry,
  auditRegistryEntries,
  computeEntryHash,
  computeRegistryHash,
  interopApplicablePairs,
  resolveAll,
  resolveInteropEligibility,
  verifyRegistryIntegrity,
  INTEROP_ELIGIBILITY_REGISTRY_SHA256,
} from '../../../../harness/phase-c/interop-eligibility/resolve.js';
import {
  InteropEligibilityRegistryError,
  type ClassEligibilityEntry,
  type InteropEligibility,
} from '../../../../harness/phase-c/interop-eligibility/types.js';

// ---------------------------------------------------------------------
// Totality, uniqueness, scope
// ---------------------------------------------------------------------

test('I_tot: every R_interop-applicable pair resolves exactly one decision', () => {
  const pairs = interopApplicablePairs();
  assert.equal(pairs.length, 81, '81 pairs carry R_interop, recomputed from the frozen registry');
  for (const p of pairs) {
    const r = resolveInteropEligibility(p.mutationId, p.stimulusInstanceId);
    assert.equal(r.mutationId, p.mutationId);
    assert.equal(r.stimulusInstanceId, p.stimulusInstanceId);
    assert.ok(r.eligibility.kind === 'eligible' || r.eligibility.kind === 'non-eligible');
  }
});

test('I_abs: no entry exists for an operation without R_interop -- HKDF is absent entirely', () => {
  for (const entry of INTEROP_ELIGIBILITY_REGISTRY) {
    assert.ok(
      APPLICABILITY_MATRIX[entry.operation].R_interop,
      `${entry.mutationId}: eligibility is undefined where the relation is not part of the protocol`,
    );
  }
  const hkdfIds = new Set(MUTATION_REGISTRY.filter((e) => e.operation === 'hkdf').map((e) => e.mutationId));
  assert.equal(hkdfIds.size, 8, 'HKDF has 8 classes');
  for (const id of hkdfIds) {
    assert.throws(
      () => resolveInteropEligibility(id, 'default'),
      InteropEligibilityRegistryError,
      `${id}: HKDF must not resolve a pseudo-eligibility`,
    );
  }
});

test('the registry covers exactly the 71 classes with R_interop, no more and no fewer', () => {
  const expected = new Set(
    MUTATION_REGISTRY.filter((e) => APPLICABILITY_MATRIX[e.operation].R_interop).map((e) => e.mutationId),
  );
  const actual = new Set(INTEROP_ELIGIBILITY_REGISTRY.map((e) => e.mutationId));
  assert.equal(expected.size, 71);
  // Equality, never containment: a missing class could never be scored for
  // R_interop, and an orphan entry would describe a class that does not exist.
  const missing = [...expected].filter((id) => !actual.has(id));
  const orphan = [...actual].filter((id) => !expected.has(id));
  assert.deepEqual(missing, [], 'classes with R_interop but no eligibility entry');
  assert.deepEqual(orphan, [], 'eligibility entries naming no R_interop class');
});

test('I_dup / I_key: auditRegistry passes on the real table', () => {
  const r = auditRegistry();
  assert.equal(r.classEntries, 71);
  assert.equal(r.totalPairs, 81);
});

// ---------------------------------------------------------------------
// The cardinalities this gate exists to demonstrate FROM THE REGISTRY,
// no longer from a temporary script.
// ---------------------------------------------------------------------

test('81 = 55 eligible + 16 producer-contractually-blocked + 10 no-operational-input', () => {
  const r = auditRegistry();
  assert.equal(r.eligible, 55);
  assert.equal(r.producerContractuallyBlocked, 16);
  assert.equal(r.noOperationalInput, 10);
  assert.equal(r.eligible + r.producerContractuallyBlocked + r.noOperationalInput, r.totalPairs);
});

test('70 uniform classes + 1 genuine override, and the override is OAEP-KEY-ROLE-BYPASS', () => {
  const r = auditRegistry();
  assert.equal(r.classesWithOverride, 1);
  assert.equal(r.classEntries - r.classesWithOverride, 70);
  assert.equal(r.pairsByStimulusOverride, 1);
  assert.equal(r.pairsByClassDefault, 80);

  const withOverride = INTEROP_ELIGIBILITY_REGISTRY.filter(
    (e) => Object.keys(e.stimulusOverrides ?? {}).length > 0,
  );
  assert.deepEqual(withOverride.map((e) => e.mutationId), ['OAEP-KEY-ROLE-BYPASS']);
});

test('the one override is the ProducerReject/ConsumerReject asymmetry, invisible to (clauseId, errorClass)', () => {
  const enc = resolveInteropEligibility('OAEP-KEY-ROLE-BYPASS', 'encrypt-with-private');
  const dec = resolveInteropEligibility('OAEP-KEY-ROLE-BYPASS', 'decrypt-with-public');
  assert.equal(enc.source, 'class-default');
  assert.equal(dec.source, 'stimulus-override');
  assert.equal(enc.eligibility.kind, 'non-eligible');
  assert.equal(dec.eligibility.kind, 'eligible');
  // Both stimuli are rejected by the SAME clause with the SAME error class;
  // only their position in Dec_q(Enc_p(m)) differs. A table keyed on the
  // clause could not have separated them.
  assert.deepEqual(
    enc.eligibility.kind === 'non-eligible' && enc.eligibility.reason === 'producer-contractually-blocked'
      ? [...enc.eligibility.provenance.clauseIds] : null,
    ['oaep.key'],
  );
});

// ---------------------------------------------------------------------
// I_ovr -- a redundant override is refused, not tolerated
// ---------------------------------------------------------------------

test('I_ovr: an override identical to its class default is refused', () => {
  // Built here rather than smuggled into the real table: a guard must be
  // shown to FIRE, not merely to be present. Note the override is a
  // DIFFERENT OBJECT with the same shape, so the comparison has to be
  // canonical -- reference equality would let this through.
  const eligible: InteropEligibility = { kind: 'eligible' };
  const redundant: ClassEligibilityEntry = {
    mutationId: 'GCM-PLAINTEXT-NORMALIZATION', operation: 'gcm', classDefault: eligible,
    stimulusOverrides: { default: { kind: 'eligible' } },
  };
  assert.throws(() => auditRegistryEntries([redundant]), /identical to its class default/);
});

test('I_key: an override naming an undeclared stimulus is refused', () => {
  const bad: ClassEligibilityEntry = {
    mutationId: 'GCM-TAGLENGTH-PROFILE-BOUNDARY-BYPASS', operation: 'gcm',
    classDefault: { kind: 'eligible' },
    stimulusOverrides: { 'tagLength-999': { kind: 'non-eligible', reason: 'no-operational-input' } },
  };
  assert.throws(() => auditRegistryEntries([bad]), /does not declare/);
});

test('I_dup: a duplicated mutationId is refused', () => {
  const one: ClassEligibilityEntry = {
    mutationId: 'GCM-AAD-IGNORED', operation: 'gcm', classDefault: { kind: 'eligible' },
  };
  assert.throws(() => auditRegistryEntries([one, one]), /Duplicate registry entry/);
});

test('I_abs: an entry for an operation without R_interop is refused', () => {
  const hkdf: ClassEligibilityEntry = {
    mutationId: 'HKDF-INFO-TAMPER', operation: 'hkdf', classDefault: { kind: 'eligible' },
  };
  assert.throws(() => auditRegistryEntries([hkdf]), /does not have R_interop applicable/);
});

test('an entry naming no frozen class, or the wrong operation, is refused', () => {
  assert.throws(
    () => auditRegistryEntries([{ mutationId: 'GCM-DOES-NOT-EXIST', operation: 'gcm', classDefault: { kind: 'eligible' } }]),
    /names no class in the frozen MUTATION_REGISTRY/,
  );
  assert.throws(
    () => auditRegistryEntries([{ mutationId: 'GCM-AAD-IGNORED', operation: 'pss', classDefault: { kind: 'eligible' } }]),
    /the frozen registry says/,
  );
});

// ---------------------------------------------------------------------
// Pins
// ---------------------------------------------------------------------

test('H_registry: the declared pin matches, and verification is fail-closed', () => {
  assert.equal(computeRegistryHash(), INTEROP_ELIGIBILITY_REGISTRY_SHA256);
  assert.doesNotThrow(() => verifyRegistryIntegrity());
  // The rejection path is exercised, not only the happy one -- the lesson
  // from the GCM qualification defect, where an honest check with an
  // insufficient criterion passed truthfully.
  assert.throws(
    () => verifyRegistryIntegrity('f'.repeat(64)),
    InteropEligibilityRegistryError,
    'a changed table must refuse, never be absorbed',
  );
});

test('H_registry is deterministic across repeated computation', () => {
  assert.equal(computeRegistryHash(), computeRegistryHash());
});

test('H_entry distinguishes the applied decision, not merely the outcome', () => {
  const pairs = resolveAll();
  const hashes = pairs.map((p) => computeEntryHash(p.resolved));
  assert.equal(new Set(hashes).size, pairs.length, 'each (c,s) has its own entry hash');

  // Same outcome, different normative justification => different hash.
  // Provenance is inside the hashed object precisely so these two are not
  // the same scientific object.
  const a = computeEntryHash({
    mutationId: 'X', stimulusInstanceId: 'default', source: 'class-default',
    eligibility: { kind: 'non-eligible', reason: 'producer-contractually-blocked',
      provenance: { kind: 'contract-derived', clauseIds: ['gcm.key'] } },
  });
  const b = computeEntryHash({
    mutationId: 'X', stimulusInstanceId: 'default', source: 'class-default',
    eligibility: { kind: 'non-eligible', reason: 'producer-contractually-blocked',
      provenance: { kind: 'contract-derived', clauseIds: ['gcm.iv'] } },
  });
  assert.notEqual(a, b);
});

test('H_entry is reproducible from the resolved entry alone', () => {
  for (const p of resolveAll()) {
    const again = resolveInteropEligibility(p.mutationId, p.stimulusInstanceId);
    assert.equal(computeEntryHash(again), computeEntryHash(p.resolved));
  }
});

// ---------------------------------------------------------------------
// I_json -- the payload must survive the EvidenceBundle round trip
//
// exportBundle is JSON.stringify o sortKeysDeep. A Uint8Array or bigint
// anywhere in this payload would not survive it, and would fail silently
// rather than loudly -- the M3-H2 lesson, applied before the field ever
// reaches MutationInstanceResult.
// ---------------------------------------------------------------------

test('I_json: every resolved entry is a plain JSON value and round-trips unchanged', () => {
  for (const p of resolveAll()) {
    const round = JSON.parse(JSON.stringify(p.resolved)) as unknown;
    assert.deepEqual(round, JSON.parse(JSON.stringify(p.resolved)));
    assert.deepEqual(round, p.resolved, `${p.mutationId}::${p.stimulusInstanceId} must survive JSON verbatim`);
  }
});

test('I_json: no Uint8Array, bigint, Map, Set or Date anywhere in the registry', () => {
  const walk = (v: unknown, path: string): void => {
    if (v === null || v === undefined) return;
    assert.ok(!(v instanceof Uint8Array), `${path}: Uint8Array does not survive JSON`);
    assert.ok(!(v instanceof Map), `${path}: Map does not survive JSON`);
    assert.ok(!(v instanceof Set), `${path}: Set does not survive JSON`);
    assert.ok(!(v instanceof Date), `${path}: Date does not round-trip as a Date`);
    assert.notEqual(typeof v, 'bigint', `${path}: bigint does not survive JSON`);
    if (Array.isArray(v)) { v.forEach((x, i) => walk(x, `${path}[${i}]`)); return; }
    if (typeof v === 'object') {
      for (const [k, x] of Object.entries(v as Record<string, unknown>)) walk(x, `${path}.${k}`);
    }
  };
  walk(INTEROP_ELIGIBILITY_REGISTRY, 'registry');
});

// ---------------------------------------------------------------------
// I_iso -- the plan path must not acquire a contract or mutate() dependency
//
// The assembler already has ZERO imports from src/contract/ and never calls
// mutate(); the microcontract's independence-of-execution invariant is
// about keeping it that way once eligibility is wired in. Guarded the same
// way plan-assembly.ts already guards itself: by grepping its own source.
// ---------------------------------------------------------------------

test('I_iso: plan-assembly.ts imports nothing from src/contract and never calls mutate()', () => {
  const src = readFileSync(new URL('../../../../harness/phase-c/plan-assembly.ts', import.meta.url), 'utf8');
  assert.ok(!src.includes('src/contract'), 'the assembler must not depend on the contract');
  assert.ok(!src.includes(['.', 'mutate', '('].join('')), 'the assembler must not run the intervention');
});

test('I_iso: the resolve module derives nothing -- no mutate(), no contract, no fixtures', () => {
  const src = readFileSync(
    new URL('../../../../harness/phase-c/interop-eligibility/resolve.ts', import.meta.url), 'utf8');
  for (const forbidden of ['src/contract', 'fixture-index', 'mutation-index', 'material/load']) {
    assert.ok(!src.includes(forbidden), `resolve.ts must not reach for '${forbidden}'`);
  }
  assert.ok(!src.includes(['.', 'mutate', '('].join('')));
});

test('I_iso: registry.ts carries only a TYPE import from src/contract, erased at runtime', () => {
  const src = readFileSync(
    new URL('../../../../harness/phase-c/interop-eligibility/registry.ts', import.meta.url), 'utf8');
  // Only real import statements; the prose explaining this very rule
  // mentions the path too, and must not be counted as a dependency.
  const contractImports = src.split('\n')
    .filter((l) => l.trimStart().startsWith('import') && l.includes('src/contract'));
  assert.equal(contractImports.length, 1, 'exactly one reference to the contract');
  assert.ok(contractImports[0]!.startsWith('import type '), 'and it must be type-only');
});

// ---------------------------------------------------------------------
// Provenance discipline, checked over the real table
// ---------------------------------------------------------------------

test('provenance is present exactly where an external normative basis is claimed', () => {
  for (const p of resolveAll()) {
    const e = p.resolved.eligibility;
    const label = `${p.mutationId}::${p.stimulusInstanceId}`;
    if (e.kind === 'eligible') {
      assert.ok(!('provenance' in e), `${label}: eligible claims no basis, so it cites none`);
    } else if (e.reason === 'no-operational-input') {
      assert.ok(!('provenance' in e), `${label}: a structural fact must not forge a contractual citation`);
    } else {
      assert.equal(e.provenance.kind, 'contract-derived');
      assert.ok(e.provenance.clauseIds.length > 0, `${label}: a contractual claim without a clause is unforgeable`);
    }
  }
});

test('all 16 producer-blocked entries cite exactly one clause, and it belongs to their own operation', () => {
  const blocked = resolveAll().filter(
    (p) => p.resolved.eligibility.kind === 'non-eligible'
      && p.resolved.eligibility.reason === 'producer-contractually-blocked',
  );
  assert.equal(blocked.length, 16);
  for (const p of blocked) {
    const e = p.resolved.eligibility;
    if (e.kind !== 'non-eligible' || e.reason !== 'producer-contractually-blocked') throw new Error('unreachable');
    assert.equal(e.provenance.clauseIds.length, 1, `${p.mutationId}: one clause per decision`);
    const frozen = MUTATION_REGISTRY.find((x) => x.mutationId === p.mutationId)!;
    const prefix = frozen.operation === 'rsa-ser' ? 'rsa-ser' : frozen.operation;
    assert.ok(
      e.provenance.clauseIds[0]!.startsWith(`${prefix}.`),
      `${p.mutationId}: clause '${e.provenance.clauseIds[0]}' does not belong to operation '${frozen.operation}'`,
    );
  }
});

// ---------------------------------------------------------------------
// The registry must not be derivable from spelling
// ---------------------------------------------------------------------

test('the registry hard-codes no stimulusInstanceId except the one genuine override', () => {
  const src = readFileSync(
    new URL('../../../../harness/phase-c/interop-eligibility/registry.ts', import.meta.url), 'utf8');
  const allStimuli = new Set<string>();
  for (const e of MUTATION_REGISTRY) {
    for (const si of e.stimulusInstances) {
      if (si.stimulusInstanceId !== 'default') allStimuli.add(si.stimulusInstanceId);
    }
  }
  const hardCoded = [...allStimuli].filter((s) => src.includes(`'${s}'`));
  assert.deepEqual(hardCoded, ['decrypt-with-public'],
    'only the class that genuinely differs per stimulus may name a stimulus');
});
