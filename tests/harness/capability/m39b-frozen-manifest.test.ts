// M3.9-B -- the frozen manifest, materialised. Transcription, not research.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';

import {
  cellFor, declarationsFor, FROZEN_CELLS, FROZEN_DECLARATIONS, ManifestError, rCapClaimsFor,
} from '../../../harness/capability/frozen-manifest.js';
import { probeKindFor, domainMembershipIsDecidable, assertBasisPinCompatible } from '../../../harness/capability/evidence-contract.js';
import { ALL_BACKENDS, BOUNCY_CASTLE, CHROMIUM_WEBCRYPTO, CRYPTOPP } from '../../../harness/schema/backend-identity.js';
import { MUTATION_REGISTRY } from '../../../harness/registry/mutations.js';
import type { OperationId } from '../../../harness/schema/capability.js';

const OPS: readonly OperationId[] = ['hkdf', 'gcm', 'oaep', 'pss', 'rsa-ser', 'ec-ser'];

test('M3.9-B: 13 declarations, 39 cells -- the closed inventory', () => {
  assert.equal(FROZEN_DECLARATIONS.length, 13);
  assert.equal(FROZEN_CELLS.length, 39);
  assert.equal(new Set(FROZEN_DECLARATIONS.map((d) => d.capabilityId)).size, 13, 'capabilityIds are unique');
});

test('M3.9-B: the per-operation contribution matches the frozen inventory', () => {
  const counts = Object.fromEntries(OPS.map((o) => [o, declarationsFor(o).length]));
  assert.deepEqual(counts, { hkdf: 1, gcm: 2, oaep: 3, pss: 5, 'rsa-ser': 1, 'ec-ser': 1 });
  assert.equal(Object.values(counts).reduce((a, b) => a + b, 0), 13);
});

test('M3.9-B: every declaration has a cell for each of the three backends', () => {
  assert.equal(ALL_BACKENDS.length, 3);
  for (const d of FROZEN_DECLARATIONS) {
    for (const b of ALL_BACKENDS) assert.doesNotThrow(() => cellFor(d.capabilityId, b), `${d.capabilityId}/${b.family}`);
  }
  assert.equal(FROZEN_DECLARATIONS.length * ALL_BACKENDS.length, FROZEN_CELLS.length);
});

test('M3.9-B: every declaration names the mutation class that requires it', () => {
  // The necessity column of M2.3.3b-I, transcribed literally: no declaration
  // exists by symmetry, and every class it names must be a real one.
  let cited = 0;
  for (const d of FROZEN_DECLARATIONS) {
    assert.ok(d.necessity.length > 0, `${d.capabilityId}: no necessity recorded`);
    for (const n of d.necessity) {
      assert.ok(MUTATION_REGISTRY.some((e) => e.mutationId === n),
        `${d.capabilityId}: necessity '${n}' is not a registered class`);
      cited += 1;
    }
  }
  // Two rows carry more than one class -- hkdf's coarse claim is required by
  // both its declaration and its boundary class.
  assert.equal(cited, 14);
  assert.deepEqual([...FROZEN_DECLARATIONS[0]!.necessity],
    ['HKDF-UNSUPPORTED-HASH-DECLARATION', 'HKDF-CAPABILITY-BOUNDARY-MISMATCH']);
});

test('M3.9-B: twelve provider-support, one provider-domain, and no coupled-parameters', () => {
  const byKind: Record<string, number> = {};
  for (const d of FROZEN_DECLARATIONS) byKind[d.kind] = (byKind[d.kind] ?? 0) + 1;
  assert.deepEqual(byKind, { 'provider-support': 12, 'provider-domain': 1 });
  // The D5.1 gate, computed rather than asserted.
  const domains = FROZEN_CELLS.filter((c) => c.supportedDomain !== undefined);
  assert.equal(domains.length, 3, 'the one provider-domain declaration, across three backends');
  for (const c of domains) assert.equal(domainMembershipIsDecidable(c.supportedDomain!), true);
  assert.equal(domains.filter((c) => c.supportedDomain!.kind === 'coupled-parameters').length, 0);
});

test('M3.9-B: the three tag-length domains genuinely differ', () => {
  const get = (b: typeof CHROMIUM_WEBCRYPTO) => cellFor('gcm.provider.tag-length-range', b).supportedDomain!;
  const c = get(CHROMIUM_WEBCRYPTO), p = get(CRYPTOPP), b = get(BOUNCY_CASTLE);
  assert.notDeepEqual(c, p);
  assert.notDeepEqual(p, b);
  // Only Crypto++ admits t = 0 on the generic API path -- the finding that
  // grounds GCM-TAGLENGTH-PROFILE-BOUNDARY-BYPASS's executability.
  const values = (d: typeof c) => (d.kind === 'integer-set' ? d.values : []);
  assert.ok(values(p).includes(0));
  assert.ok(!values(c).includes(0) && !values(b).includes(0));
});

test('M3.9-B: every cell carries a basis, and only the two frozen kinds', () => {
  for (const c of FROZEN_CELLS) {
    assert.ok(['m1-reference-evidence', 'backend-documentation'].includes(c.basisKind), c.capabilityId);
    assert.ok(c.basis.length > 20, `${c.capabilityId}/${c.backend.family}: a basis must be citable`);
  }
});

test('M3.9-B: a value and a domain are never both present, and never both absent', () => {
  for (const c of FROZEN_CELLS) {
    const hasSupport = c.support !== undefined;
    const hasDomain = c.supportedDomain !== undefined;
    assert.notEqual(hasSupport, hasDomain, `${c.capabilityId}/${c.backend.family}`);
  }
});

test('M3.9-B: R_cap claims exclude execution-planning-only declarations', () => {
  for (const o of OPS) {
    for (const d of rCapClaimsFor(o)) assert.notEqual(d.usage, 'execution-planning');
  }
  // All thirteen are r-cap-claim or both, so all thirteen feed R_cap.
  assert.equal(OPS.flatMap((o) => rCapClaimsFor(o)).length, 13);
});

test('M3.9-B: only provider-support -> runtime-probe is exercised', () => {
  // A scope precision recorded in M3.9-A': none of the thirteen is
  // portable-boundary or interface-exposure, so the other two rows of D1
  // remain correct as contract and unexercised in fact.
  const kinds = new Set(FROZEN_DECLARATIONS.map((d) => d.kind));
  assert.ok(!kinds.has('portable-boundary'));
  assert.ok(!kinds.has('interface-exposure'));
  assert.equal(probeKindFor('provider-support'), 'runtime-probe');
});

test('M3.9-B: the pin-anchored cell is the one the freeze anchors', () => {
  const bc = cellFor('pss.provider.explicit-salt-bytes', BOUNCY_CASTLE);
  assert.equal(bc.support, 'supported');
  assert.ok(bc.basis.includes('D-042'));
  assert.ok(bc.basis.includes('pinned jar'), 'valid for the pin, not for the library');
  assert.doesNotThrow(() => assertBasisPinCompatible({
    basisKind: bc.basisKind, basisBackendPin: BOUNCY_CASTLE.sourcePin, manifestSourcePin: BOUNCY_CASTLE.sourcePin,
  }));
});

test('M3.9-B: an undeclared pair has no cell, and absence is not a negative', () => {
  assert.throws(() => cellFor('gcm.provider.support', { ...CRYPTOPP, sourcePin: 'other' }), ManifestError);
  assert.throws(() => cellFor('invented.capability', CRYPTOPP), /Absence is not a negative declaration/);
});

test('M3.9-B: transcription, not research -- no external source is consulted', () => {
  const src = readFileSync(new URL('../../../harness/capability/frozen-manifest.ts', import.meta.url), 'utf8');
  for (const forbidden of ['fetch(', 'http://', 'https://', 'readFileSync', 'execSync']) {
    assert.ok(!src.includes(forbidden), `the manifest must be transcribed, not gathered ('${forbidden}')`);
  }
  assert.ok(src.includes('TRANSCRIPTION, not research'));
});
