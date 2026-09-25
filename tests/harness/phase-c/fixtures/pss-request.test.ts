import { test } from 'node:test';
import assert from 'node:assert/strict';

import {
  resolvePssRequestFixture, resolvePssSignRequestFixture, resolvePssVerifyRequestFixture,
  resolvePssKeyRoleBypassFixture, isPssKeyRoleBypass, isPssVerifyRequestClass,
  PSS_REQUEST_MUTATION_IDS, PSS_REQUEST_STIMULUS_PAIRS, pssBaselineSignMessage,
} from '../../../../harness/phase-c/fixtures/pss-request.js';
import { FixtureResolutionError } from '../../../../harness/phase-c/fixtures/hkdf-request.js';
import { loadFrozenMaterialPool, PHASE_C_MATERIAL_IDS } from '../../../../harness/phase-c/material/load.js';
import type { PssValidSignatureArtifact, Rsa3072KeyPairMaterial } from '../../../../harness/phase-c/material/schema.js';
import { getMutationImplementation } from '../../../../harness/phase-c/mutation-index.js';
import { MUTATION_REGISTRY } from '../../../../harness/registry/mutations.js';
import { validatePssSignRequest, validatePssVerifyRequest, MODULUS_BITS, PSS_HASH, SALT_LEN_BYTES } from '../../../../src/contract/pss.js';

const pool = loadFrozenMaterialPool();

// --- Closure conditions ----------------------------------------------------

test('M3.2.4b-2.6: PSSRequestMutationIDs == ResolvedPSSRequestMutationIDs (9 classes, 9 pairs)', () => {
  const fromRegistry = MUTATION_REGISTRY
    .filter((e) => e.operation === 'pss' && e.mechanism === 'request-transform')
    .map((e) => e.mutationId).sort();
  assert.deepEqual([...PSS_REQUEST_MUTATION_IDS], fromRegistry);
  assert.equal(fromRegistry.length, 9);
  assert.equal(PSS_REQUEST_STIMULUS_PAIRS.length, 9, 'no multi-stimulus class in this group');
  for (const [m, s] of PSS_REQUEST_STIMULUS_PAIRS) {
    assert.doesNotThrow(() => resolvePssRequestFixture(m, s, pool), `${m}::${s}`);
  }
});

test('M3.2.4b-2.6: the group is THREE shapes -- 7 sign, 1 verify, 1 key-role', () => {
  const keyRole = PSS_REQUEST_MUTATION_IDS.filter(isPssKeyRoleBypass);
  const verify = PSS_REQUEST_MUTATION_IDS.filter(isPssVerifyRequestClass);
  assert.equal(keyRole.length, 1);
  assert.equal(verify.length, 1);
  assert.equal(PSS_REQUEST_MUTATION_IDS.length - keyRole.length - verify.length, 7);
});

// --- Finding 1: the frozen signature IS required here ----------------------

test('M3.2.4b-2.6: the verify baseline uses the frozen signature AND the exact message it covers', () => {
  const verifyId = PSS_REQUEST_MUTATION_IDS.find(isPssVerifyRequestClass)!;
  const f = resolvePssVerifyRequestFixture(verifyId, 'default', pool);
  const artifact = pool.valueOf<PssValidSignatureArtifact>(PHASE_C_MATERIAL_IDS.pssSignature, 'pss-valid-signature');

  assert.deepEqual(Buffer.from(f.signature), Buffer.from(artifact.signature));
  assert.deepEqual(Buffer.from(f.message), Buffer.from(artifact.message),
    'the message must be the one the frozen signature covers, or the baseline would already fail');
  assert.notEqual(f.signature, artifact.signature, 'copies, not aliases into the pool');
});

test('M3.2.4b-2.6: the verify baseline signature GENUINELY VERIFIES -- otherwise the mutation would measure nothing', async () => {
  const { webcrypto } = await import('node:crypto');
  const verifyId = PSS_REQUEST_MUTATION_IDS.find(isPssVerifyRequestClass)!;
  const f = resolvePssVerifyRequestFixture(verifyId, 'default', pool);
  const rsa = pool.valueOf<Rsa3072KeyPairMaterial>(PHASE_C_MATERIAL_IDS.rsa, 'rsa-3072-keypair');

  const b64u = (b: Uint8Array) => Buffer.from(b).toString('base64url');
  const pub = await webcrypto.subtle.importKey(
    'jwk', { kty: 'RSA', n: b64u(rsa.n), e: b64u(rsa.e) }, { name: 'RSA-PSS', hash: 'SHA-256' }, false, ['verify'],
  );
  const ok = await webcrypto.subtle.verify({ name: 'RSA-PSS', saltLength: SALT_LEN_BYTES }, pub, f.signature, f.message);
  assert.equal(ok, true, 'the BASELINE must verify true');
});

test('M3.2.4b-2.6: after mutation the signature no longer covers the message -- the intervention is real', async () => {
  const { webcrypto } = await import('node:crypto');
  const verifyId = PSS_REQUEST_MUTATION_IDS.find(isPssVerifyRequestClass)!;
  const base = resolvePssVerifyRequestFixture(verifyId, 'default', pool);
  const mutated = getMutationImplementation(verifyId).mutate(base, 'default') as typeof base;
  const rsa = pool.valueOf<Rsa3072KeyPairMaterial>(PHASE_C_MATERIAL_IDS.rsa, 'rsa-3072-keypair');

  assert.notDeepEqual(Buffer.from(mutated.message), Buffer.from(base.message));
  assert.deepEqual(Buffer.from(mutated.signature), Buffer.from(base.signature), 'only the message is intervened on');

  const b64u = (b: Uint8Array) => Buffer.from(b).toString('base64url');
  const pub = await webcrypto.subtle.importKey(
    'jwk', { kty: 'RSA', n: b64u(rsa.n), e: b64u(rsa.e) }, { name: 'RSA-PSS', hash: 'SHA-256' }, false, ['verify'],
  );
  const ok = await webcrypto.subtle.verify({ name: 'RSA-PSS', saltLength: SALT_LEN_BYTES }, pub, mutated.signature, mutated.message);
  assert.equal(ok, false, 'a conformant verifier must reject the mutated pairing');
});

test('M3.2.4b-2.6: the 7 sign classes and the key-role class reference NO frozen material', () => {
  // Only the verify class touches the pool; the others carry a descriptor key
  // and a ProtocolParameter message.
  for (const id of PSS_REQUEST_MUTATION_IDS) {
    if (isPssVerifyRequestClass(id)) continue;
    const f = resolvePssRequestFixture(id, 'default', pool);
    const request = 'kind' in f ? f.request : f;
    assert.ok(!('signature' in request), `${id} must not carry a signature`);
    assert.deepEqual(Object.keys(request.key).sort(), ['modulusBits', 'role']);
  }
});

// --- Finding 2: PSS's key-role class is not OAEP's -------------------------

test('M3.2.4b-2.6: PSS-KEY-ROLE-BYPASS has ONE stimulus and mutate() accepts only kind=sign', () => {
  const keyRoleId = PSS_REQUEST_MUTATION_IDS.find(isPssKeyRoleBypass)!;
  const entry = MUTATION_REGISTRY.find((e) => e.mutationId === keyRoleId)!;
  assert.equal(entry.stimulusInstances.length, 1, 'unlike OAEP counterpart, which has two');

  const base = resolvePssKeyRoleBypassFixture(keyRoleId, 'default', pool);
  assert.equal(base.kind, 'sign');

  const impl = getMutationImplementation(keyRoleId);
  assert.doesNotThrow(() => impl.mutate(base, 'default'));
  // A verify-kind state would be rejected outright by mutate(), which is why
  // the resolver fixes the discriminant rather than deriving it.
  assert.throws(() => impl.mutate({ kind: 'verify', request: resolvePssVerifyRequestFixture(
    PSS_REQUEST_MUTATION_IDS.find(isPssVerifyRequestClass)!, 'default', pool) } as never, 'default'));
});

test('M3.2.4b-2.6: the key-role baseline starts from the CORRECT role, and the mutation bypasses it', () => {
  const keyRoleId = PSS_REQUEST_MUTATION_IDS.find(isPssKeyRoleBypass)!;
  const base = resolvePssKeyRoleBypassFixture(keyRoleId, 'default', pool);
  assert.equal(base.kind === 'sign' && base.request.key.role, 'private', 'signing requires a private key');
  const mutated = getMutationImplementation(keyRoleId).mutate(base, 'default') as typeof base;
  assert.equal(mutated.kind === 'sign' && mutated.request.key.role, 'public');
});

test('M3.2.4b-2.6: the key-role fixture COMPOSES the same sign request the plain resolver serves', () => {
  const keyRoleId = PSS_REQUEST_MUTATION_IDS.find(isPssKeyRoleBypass)!;
  const composed = resolvePssKeyRoleBypassFixture(keyRoleId, 'default', pool);
  const plainId = PSS_REQUEST_MUTATION_IDS.find((id) => !isPssKeyRoleBypass(id) && !isPssVerifyRequestClass(id))!;
  const plain = resolvePssSignRequestFixture(plainId, 'default', pool);
  assert.ok(composed.kind === 'sign');
  if (composed.kind === 'sign') assert.deepEqual(composed.request, plain, 'one canonical definition, not two');
});

// --- H3 / H4 ---------------------------------------------------------------

test('M3.2.4b-2.6 (H3): no mutate() call, and all 9 pairs are genuinely pre-mutation', async () => {
  const { readFileSync } = await import('node:fs');
  const src = readFileSync(new URL('../../../../harness/phase-c/fixtures/pss-request.ts', import.meta.url), 'utf8');
  const forbidden = ['.', 'mutate', '('].join('');
  assert.ok(!src.includes(forbidden));

  for (const [m, s] of PSS_REQUEST_STIMULUS_PAIRS) {
    const base = resolvePssRequestFixture(m, s, pool);
    const mutated = getMutationImplementation(m).mutate(base, s) as typeof base;
    assert.notDeepEqual(mutated, base, `${m}::${s}`);
  }
});

test('M3.2.4b-2.6 (H4): every fixture passes its own real frozen Accept_C before mutation', () => {
  for (const [m, s] of PSS_REQUEST_STIMULUS_PAIRS) {
    const f = resolvePssRequestFixture(m, s, pool);
    if ('kind' in f) {
      assert.ok(f.kind === 'sign');
      if (f.kind === 'sign') assert.doesNotThrow(() => validatePssSignRequest(f.request), m);
    } else if ('signature' in f) {
      assert.doesNotThrow(() => validatePssVerifyRequest(f), m);
    } else {
      assert.doesNotThrow(() => validatePssSignRequest(f), m);
    }
  }
});

test('M3.2.4b-2.6 (H4): the frozen portable profile is reproduced exactly (hash coupling, sLen=hLen, modulus)', () => {
  const plainId = PSS_REQUEST_MUTATION_IDS.find((id) => !isPssKeyRoleBypass(id) && !isPssVerifyRequestClass(id))!;
  const f = resolvePssSignRequestFixture(plainId, 'default', pool);
  assert.equal(f.hash, PSS_HASH);
  assert.equal(f.mgfHash, PSS_HASH);
  assert.equal(f.saltLengthBytes, SALT_LEN_BYTES);
  assert.equal(f.key.modulusBits, MODULUS_BITS);
  assert.deepEqual(Buffer.from(f.message), Buffer.from(pssBaselineSignMessage()));
});

// --- Typed separation, derivation, fail-closed -----------------------------

test('M3.2.4b-2.6: the three typed resolvers refuse each other classes', () => {
  const keyRoleId = PSS_REQUEST_MUTATION_IDS.find(isPssKeyRoleBypass)!;
  const verifyId = PSS_REQUEST_MUTATION_IDS.find(isPssVerifyRequestClass)!;
  const plainId = PSS_REQUEST_MUTATION_IDS.find((id) => !isPssKeyRoleBypass(id) && !isPssVerifyRequestClass(id))!;
  assert.throws(() => resolvePssSignRequestFixture(keyRoleId, 'default', pool), FixtureResolutionError);
  assert.throws(() => resolvePssSignRequestFixture(verifyId, 'default', pool), FixtureResolutionError);
  assert.throws(() => resolvePssVerifyRequestFixture(plainId, 'default', pool), FixtureResolutionError);
  assert.throws(() => resolvePssKeyRoleBypassFixture(plainId, 'default', pool), FixtureResolutionError);
});

test('M3.2.4b-2.6: shape selection is derived from Gamma_0, cross-checked against the registry', async () => {
  const { readFileSync } = await import('node:fs');
  const src = readFileSync(new URL('../../../../harness/phase-c/fixtures/pss-request.ts', import.meta.url), 'utf8');
  for (const id of PSS_REQUEST_MUTATION_IDS) {
    assert.ok(!src.includes(`'${id}'`), `no mutationId literal may appear; found '${id}'`);
    const entry = MUTATION_REGISTRY.find((e) => e.mutationId === id)!;
    assert.equal(isPssKeyRoleBypass(id), entry.gamma0.some((c) => c.endsWith('.key')));
    assert.equal(isPssVerifyRequestClass(id), entry.gamma0.some((c) => c.endsWith('.verification')));
  }
});

test('M3.2.4b-2.6: unregistered, wrong-operation and wrong-mechanism ids fail closed', () => {
  assert.throws(() => resolvePssRequestFixture(PSS_REQUEST_MUTATION_IDS[0]!, 'no-such', pool), FixtureResolutionError);
  assert.throws(() => resolvePssRequestFixture('OAEP-MESSAGE-NORMALIZATION', 'default', pool), FixtureResolutionError);
  assert.throws(() => resolvePssRequestFixture('PSS-RNG-INTERFACE-LEAK', 'default', pool), FixtureResolutionError);
  assert.throws(() => resolvePssRequestFixture('PSS-VERIFICATION-FALSE-ACCEPT', 'default', pool), FixtureResolutionError);
});
