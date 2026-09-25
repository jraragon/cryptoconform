import { test } from 'node:test';
import assert from 'node:assert/strict';

import {
  resolveOaepRequestFixture, resolveOaepEncryptRequestFixture, resolveOaepKeyRoleBypassFixture,
  isOaepKeyRoleBypass, OAEP_REQUEST_MUTATION_IDS, OAEP_REQUEST_STIMULUS_PAIRS,
  OAEP_BASELINE_PLAINTEXT_LEN, OAEP_INERT_CIPHERTEXT_LEN, OAEP_MAX_MESSAGE_LEN_BYTES,
} from '../../../../harness/phase-c/fixtures/oaep-request.js';
import { FixtureResolutionError } from '../../../../harness/phase-c/fixtures/hkdf-request.js';
import { loadFrozenMaterialPool, PHASE_C_MATERIAL_IDS } from '../../../../harness/phase-c/material/load.js';
import { getMutationImplementation } from '../../../../harness/phase-c/mutation-index.js';
import { MUTATION_REGISTRY } from '../../../../harness/registry/mutations.js';
import {
  validateOaepEncryptRequest, validateOaepDecryptRequest, MODULUS_BITS, OAEP_HASH, K_BYTES,
} from '../../../../src/contract/oaep.js';

const pool = loadFrozenMaterialPool();

// --- Closure conditions ----------------------------------------------------

test('M3.2.4b-2.4: OAEPRequestMutationIDs == ResolvedOAEPRequestMutationIDs (9 classes)', () => {
  const fromRegistry = MUTATION_REGISTRY
    .filter((e) => e.operation === 'oaep' && e.mechanism === 'request-transform')
    .map((e) => e.mutationId).sort();
  assert.deepEqual([...OAEP_REQUEST_MUTATION_IDS], fromRegistry);
  assert.equal(fromRegistry.length, 9);
});

test('M3.2.4b-2.4: OAEPRequestStimulusPairs == ResolvedOAEPRequestStimulusPairs (10 pairs, not 9)', () => {
  assert.equal(OAEP_REQUEST_STIMULUS_PAIRS.length, 10);
  for (const [m, s] of OAEP_REQUEST_STIMULUS_PAIRS) {
    assert.doesNotThrow(() => resolveOaepRequestFixture(m, s, pool), `${m}::${s}`);
  }
  const keys = OAEP_REQUEST_STIMULUS_PAIRS.map(([m, s]) => `${m}::${s}`);
  assert.equal(new Set(keys).size, keys.length, 'H5');
});

test('M3.2.4b-2.4: the group is NOT one shape -- 8 classes use OaepEncryptRequest, 1 uses OaepKeyRoleBypassState', () => {
  const bypass = OAEP_REQUEST_MUTATION_IDS.filter((id) => isOaepKeyRoleBypass(id));
  assert.equal(bypass.length, 1);
  assert.equal(OAEP_REQUEST_MUTATION_IDS.length - bypass.length, 8);
});

// --- Finding 1: no frozen key material is needed ---------------------------

test('M3.2.4b-2.4: this group references NO frozen material -- OaepKeyRef is a descriptor, not key bytes', async () => {
  const { readFileSync } = await import('node:fs');
  const src = readFileSync(new URL('../../../../harness/phase-c/fixtures/oaep-request.ts', import.meta.url), 'utf8');
  for (const id of Object.values(PHASE_C_MATERIAL_IDS)) {
    assert.ok(!src.includes(id), `found material reference '${id}'`);
  }
});

test('M3.2.4b-2.4: the key field carries only role metadata, never key bytes', () => {
  const f = resolveOaepEncryptRequestFixture('OAEP-MESSAGE-NORMALIZATION', 'default', pool);
  assert.deepEqual(Object.keys(f.key).sort(), ['modulusBits', 'role']);
  assert.equal(f.key.modulusBits, MODULUS_BITS);
  for (const v of Object.values(f.key)) assert.ok(!(v instanceof Uint8Array));
});

// --- H3 / H4 ---------------------------------------------------------------

test('M3.2.4b-2.4 (H3): no mutate() call in the resolver, and every pair is genuinely pre-mutation', async () => {
  const { readFileSync } = await import('node:fs');
  const src = readFileSync(new URL('../../../../harness/phase-c/fixtures/oaep-request.ts', import.meta.url), 'utf8');
  const forbidden = ['.', 'mutate', '('].join('');
  assert.ok(!src.includes(forbidden));

  for (const [m, s] of OAEP_REQUEST_STIMULUS_PAIRS) {
    const base = resolveOaepRequestFixture(m, s, pool);
    const mutated = getMutationImplementation(m).mutate(base, s) as typeof base;
    assert.notDeepEqual(mutated, base, `${m}::${s} must genuinely change under mutation`);
  }
});

test('M3.2.4b-2.4 (H4): the 8 encrypt-request fixtures pass the real frozen Accept_C', () => {
  for (const [m, s] of OAEP_REQUEST_STIMULUS_PAIRS) {
    if (isOaepKeyRoleBypass(m)) continue;
    const f = resolveOaepEncryptRequestFixture(m, s, pool);
    assert.doesNotThrow(() => validateOaepEncryptRequest(f), `${m}::${s}`);
  }
});

test('M3.2.4b-2.4 (H4): both branches of the key-role class are contractually VALID before mutation', () => {
  const enc = resolveOaepKeyRoleBypassFixture('OAEP-KEY-ROLE-BYPASS', 'encrypt-with-private', pool);
  assert.equal(enc.kind, 'encrypt');
  if (enc.kind === 'encrypt') assert.doesNotThrow(() => validateOaepEncryptRequest(enc.request));

  const dec = resolveOaepKeyRoleBypassFixture('OAEP-KEY-ROLE-BYPASS', 'decrypt-with-public', pool);
  assert.equal(dec.kind, 'decrypt');
  if (dec.kind === 'decrypt') assert.doesNotThrow(() => validateOaepDecryptRequest(dec.request));
});

test('M3.2.4b-2.4 (H4): the baseline plaintext is well inside the derived message bound (D-032)', () => {
  assert.ok(OAEP_BASELINE_PLAINTEXT_LEN > 0);
  assert.ok(OAEP_BASELINE_PLAINTEXT_LEN < OAEP_MAX_MESSAGE_LEN_BYTES,
    'strictly inside, so a boundary mutation genuinely crosses the boundary');
  const f = resolveOaepEncryptRequestFixture('OAEP-MESSAGE-BOUNDARY-BYPASS', 'default', pool);
  assert.equal(f.hash, OAEP_HASH);
  assert.equal(f.mgfHash, OAEP_HASH, 'MGF is coupled in the frozen portable profile');
});

// --- Finding 2: the first stimulus-DEPENDENT base fixture ------------------

test('M3.2.4b-2.4: stimulusInstanceId DOES determine F0 here -- the first such case', () => {
  const enc = resolveOaepKeyRoleBypassFixture('OAEP-KEY-ROLE-BYPASS', 'encrypt-with-private', pool);
  const dec = resolveOaepKeyRoleBypassFixture('OAEP-KEY-ROLE-BYPASS', 'decrypt-with-public', pool);
  assert.notDeepEqual(enc, dec);
  assert.notEqual(enc.kind, dec.kind, 'the discriminant itself differs, as mutate() requires');
});

test('M3.2.4b-2.4: mutate() would THROW on a mismatched discriminant -- proving the resolver must choose it', () => {
  const impl = getMutationImplementation('OAEP-KEY-ROLE-BYPASS');
  const enc = resolveOaepKeyRoleBypassFixture('OAEP-KEY-ROLE-BYPASS', 'encrypt-with-private', pool);
  // The correct pairing works...
  assert.doesNotThrow(() => impl.mutate(enc, 'encrypt-with-private'));
  // ...and the crossed pairing does not, which is exactly why F0 must depend
  // on the stimulus for this class.
  assert.throws(() => impl.mutate(enc, 'decrypt-with-public'));
});

test('M3.2.4b-2.4: each branch starts from the CONTRACTUALLY CORRECT role, and the mutation bypasses it', () => {
  const impl = getMutationImplementation('OAEP-KEY-ROLE-BYPASS');

  const enc = resolveOaepKeyRoleBypassFixture('OAEP-KEY-ROLE-BYPASS', 'encrypt-with-private', pool);
  assert.equal(enc.kind === 'encrypt' && enc.request.key.role, 'public');
  const mEnc = impl.mutate(enc, 'encrypt-with-private') as typeof enc;
  assert.equal(mEnc.kind === 'encrypt' && mEnc.request.key.role, 'private');

  const dec = resolveOaepKeyRoleBypassFixture('OAEP-KEY-ROLE-BYPASS', 'decrypt-with-public', pool);
  assert.equal(dec.kind === 'decrypt' && dec.request.key.role, 'private');
  const mDec = impl.mutate(dec, 'decrypt-with-public') as typeof dec;
  assert.equal(mDec.kind === 'decrypt' && mDec.request.key.role, 'public');
});

// --- Finding 3: the structural inert value ---------------------------------

test('M3.2.4b-2.4: the inert ciphertext is width-derived from the modulus, not an arbitrary size', () => {
  assert.equal(OAEP_INERT_CIPHERTEXT_LEN, K_BYTES);
  const dec = resolveOaepKeyRoleBypassFixture('OAEP-KEY-ROLE-BYPASS', 'decrypt-with-public', pool);
  assert.equal(dec.kind === 'decrypt' && dec.request.ciphertext.length, K_BYTES);
});

test('M3.2.4b-2.4: mutate(F0,s).ciphertext === F0.ciphertext -- the inert value is never consumed or intervened on', () => {
  const impl = getMutationImplementation('OAEP-KEY-ROLE-BYPASS');
  const dec = resolveOaepKeyRoleBypassFixture('OAEP-KEY-ROLE-BYPASS', 'decrypt-with-public', pool);
  const mutated = impl.mutate(dec, 'decrypt-with-public') as typeof dec;
  assert.ok(dec.kind === 'decrypt' && mutated.kind === 'decrypt');
  if (dec.kind === 'decrypt' && mutated.kind === 'decrypt') {
    assert.deepEqual(Buffer.from(mutated.request.ciphertext), Buffer.from(dec.request.ciphertext),
      'byte-identical: the intervention is on key.role alone');
  }
});

test('M3.2.4b-2.4: Gamma_0 for the key-role class is the role, confirming the ciphertext is outside the intervention', () => {
  const entry = MUTATION_REGISTRY.find((e) => e.mutationId === 'OAEP-KEY-ROLE-BYPASS')!;
  assert.ok(entry.gamma0.some((c) => c.includes('key')), `gamma0 = ${JSON.stringify(entry.gamma0)}`);
  assert.ok(!entry.gamma0.some((c) => c.includes('ciphertext')), 'the ciphertext is not a Gamma_0 clause here');
});

test('M3.2.4b-2.4: the inert ciphertext is deterministic across resolutions', () => {
  const a = resolveOaepKeyRoleBypassFixture('OAEP-KEY-ROLE-BYPASS', 'decrypt-with-public', pool);
  const b = resolveOaepKeyRoleBypassFixture('OAEP-KEY-ROLE-BYPASS', 'decrypt-with-public', pool);
  assert.deepEqual(a, b);
});

// --- Typed separation and fail-closed --------------------------------------

test('M3.2.4b-2.4: the two typed resolvers refuse each other classes -- no artificial union', () => {
  assert.throws(() => resolveOaepEncryptRequestFixture('OAEP-KEY-ROLE-BYPASS', 'encrypt-with-private', pool), FixtureResolutionError);
  assert.throws(() => resolveOaepKeyRoleBypassFixture('OAEP-MESSAGE-NORMALIZATION', 'default', pool), FixtureResolutionError);
});

test('M3.2.4b-2.4: unregistered, wrong-operation and wrong-mechanism ids fail closed', () => {
  assert.throws(() => resolveOaepRequestFixture('OAEP-MESSAGE-NORMALIZATION', 'no-such', pool), FixtureResolutionError);
  assert.throws(() => resolveOaepRequestFixture('GCM-AAD-IGNORED', 'default', pool), FixtureResolutionError);
  assert.throws(() => resolveOaepRequestFixture('OAEP-RANDOMNESS-INTERFACE-LEAK', 'default', pool), FixtureResolutionError);
  assert.throws(() => resolveOaepRequestFixture('OAEP-PROVIDER-CAPABILITY-MISREPORT', 'default', pool), FixtureResolutionError);
});

test('M3.2.4b-2.4: group membership is derived from the registry, not hard-coded', async () => {
  const { readFileSync } = await import('node:fs');
  const src = readFileSync(new URL('../../../../harness/phase-c/fixtures/oaep-request.ts', import.meta.url), 'utf8');
  for (const id of OAEP_REQUEST_MUTATION_IDS) {
    assert.ok(!src.includes(`'${id}'`), `no mutationId literal may appear; found '${id}'`);
  }
});
