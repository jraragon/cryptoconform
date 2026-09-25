// M3.9-B -- claim resolution and scored acquisition.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';

import {
  allResolvedClaims, AcquisitionError, contrastClaim, declaredState, resolveClaims,
} from '../../../harness/capability/capability-acquisition.js';
import { ALL_BACKENDS, BOUNCY_CASTLE, CHROMIUM_WEBCRYPTO, CRYPTOPP } from '../../../harness/schema/backend-identity.js';
import type { OperationId } from '../../../harness/schema/capability.js';

const OPS: readonly OperationId[] = ['hkdf', 'gcm', 'oaep', 'pss', 'rsa-ser', 'ec-ser'];
const all = allResolvedClaims(OPS, ALL_BACKENDS);

test('M3.9-B: every R_cap coordinate now resolves claims -- the branch that never ran', () => {
  // 13 declarations x 3 backends, resolved through the closed inventory.
  assert.equal(all.length, 39);
  assert.equal(new Set(all.map((c) => `${c.capabilityId}|${c.backend.sourcePin}`)).size, 39);
  // And the 18 structural coordinates all carry at least one claim.
  const coords = new Set(all.map((c) => `${c.operation}|${c.backend.family}`));
  assert.equal(coords.size, 18);
});

test('M3.9-B: claims per operation match the frozen inventory', () => {
  const perOp = Object.fromEntries(OPS.map((o) => [o, resolveClaims(o, CRYPTOPP).length]));
  assert.deepEqual(perOp, { hkdf: 1, gcm: 2, oaep: 3, pss: 5, 'rsa-ser': 1, 'ec-ser': 1 });
});

test('M3.9-B: the probe kind comes from the claim, not from what is convenient', () => {
  for (const c of all) assert.equal(c.probeKind, 'runtime-probe');
  const claim = resolveClaims('hkdf', CRYPTOPP)[0]!;
  assert.throws(() => contrastClaim({
    claim, declarationEvidenceIds: ['M1-hkdf-1'],
    scored: { executionId: 'M4-1', backend: CRYPTOPP, observed: { kind: 'provider-support', state: 'supported' }, probeKind: 'operation-execution' },
  }), /never by what was convenient to run/);
});

test('M3.9-B: declared state is READ from the frozen cell, never probed', () => {
  assert.deepEqual(declaredState(resolveClaims('hkdf', CHROMIUM_WEBCRYPTO)[0]!),
    { kind: 'provider-support', state: 'supported' });
  const varSalt = resolveClaims('pss', CRYPTOPP).find((c) => c.capabilityId === 'pss.provider.variable-salt-length')!;
  assert.deepEqual(declaredState(varSalt), { kind: 'provider-support', state: 'unsupported' });
  const src = readFileSync(new URL('../../../harness/capability/capability-acquisition.ts', import.meta.url), 'utf8');
  assert.ok(src.includes('The declared side, read from the frozen cell. Never probed.'));
});

test('M3.9-B: contrast is pass on agreement and fail on divergence', () => {
  const claim = resolveClaims('pss', CRYPTOPP).find((c) => c.capabilityId === 'pss.provider.variable-salt-length')!;
  const scored = (state: 'supported' | 'unsupported') => ({
    executionId: 'M4-777', backend: CRYPTOPP,
    observed: { kind: 'provider-support' as const, state }, probeKind: 'runtime-probe' as const,
  });
  assert.equal(contrastClaim({ claim, declarationEvidenceIds: ['DOC-D-041'], scored: scored('unsupported') }), 'pass');
  assert.equal(contrastClaim({ claim, declarationEvidenceIds: ['DOC-D-041'], scored: scored('supported') }), 'fail');
});

test('M3.9-B: independence is over IDENTITY -- shared mechanism is legitimate', () => {
  const claim = resolveClaims('hkdf', CRYPTOPP)[0]!;
  const scored = (id: string) => ({
    executionId: id, backend: CRYPTOPP,
    observed: { kind: 'provider-support' as const, state: 'supported' as const }, probeKind: 'runtime-probe' as const,
  });
  // Both 'run HKDF'. The freeze says that shared mechanism is not a violation.
  assert.doesNotThrow(() => contrastClaim({
    claim, declarationEvidenceIds: ['M1-hkdf-closure'], scored: scored('M4-hkdf-probe'),
  }));
  // One identical ExecutionID on both sides is.
  assert.throws(() => contrastClaim({
    claim, declarationEvidenceIds: ['E-SAME'], scored: scored('E-SAME'),
  }), /tautological by construction/);
});

test('M3.9-B: backend comparability is the full tuple', () => {
  const claim = resolveClaims('gcm', BOUNCY_CASTLE).find((c) => c.capabilityId === 'gcm.provider.support')!;
  assert.throws(() => contrastClaim({
    claim, declarationEvidenceIds: ['M1-gcm'],
    scored: { executionId: 'M4-1', backend: { ...BOUNCY_CASTLE, sourcePin: 'other' }, observed: { kind: 'provider-support', state: 'supported' }, probeKind: 'runtime-probe' },
  }), /never family alone/);
});

test('M3.9-B: a domain cell is not contrasted by state equality', () => {
  const domain = resolveClaims('gcm', CRYPTOPP).find((c) => c.capabilityId === 'gcm.provider.tag-length-range')!;
  assert.equal(declaredState(domain), undefined);
  assert.throws(() => contrastClaim({
    claim: domain, declarationEvidenceIds: ['DOC'],
    scored: { executionId: 'M4-1', backend: CRYPTOPP, observed: { kind: 'provider-support', state: 'supported' }, probeKind: 'runtime-probe' },
  }), AcquisitionError);
  assert.throws(() => contrastClaim({
    claim: domain, declarationEvidenceIds: ['DOC'],
    scored: { executionId: 'M4-1', backend: CRYPTOPP, observed: { kind: 'provider-support', state: 'supported' }, probeKind: 'runtime-probe' },
  }), /contrasted by membership, not by state equality/);
});

test('M3.9-B: acquisition consults the closed inventory only', () => {
  const src = readFileSync(new URL('../../../harness/capability/capability-acquisition.ts', import.meta.url), 'utf8');
  for (const forbidden of ['fetch(', 'https://', 'readFileSync', 'execSync']) {
    assert.ok(!src.includes(forbidden), `no external source may be consulted ('${forbidden}')`);
  }
  assert.ok(src.includes('rCapClaimsFor'), 'claims come from the frozen inventory');
});
