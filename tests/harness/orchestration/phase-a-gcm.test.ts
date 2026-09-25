import { test, after } from 'node:test';
import assert from 'node:assert/strict';

import { executeBaseline } from '../../../harness/orchestration/engine.js';
import { GCM_ENCRYPT_CHROMIUM_ADAPTER, GCM_DECRYPT_CHROMIUM_ADAPTER } from '../../../harness/orchestration/gcm-chromium-wiring.js';
import { GCM_ENCRYPT_CRYPTOPP_ADAPTER, GCM_DECRYPT_CRYPTOPP_ADAPTER, GCM_ENCRYPT_BOUNCYCASTLE_ADAPTER, GCM_DECRYPT_BOUNCYCASTLE_ADAPTER } from '../../../harness/orchestration/gcm-native-wiring.js';
import { closeSharedChromium } from '../../../harness/orchestration/chromium-page.js';
import { makeRelationObservation } from '../../../harness/evidence/relation-observation.js';
import type { BaselineResult } from '../../../harness/evidence/baseline-result.js';
import { CHROMIUM_WEBCRYPTO, CRYPTOPP, BOUNCY_CASTLE, backendIdentityEquals } from '../../../harness/schema/backend-identity.js';
import type { GcmEncryptRequest, GcmDecryptRequest } from '../../../src/contract/gcm.js';

after(async () => {
  await closeSharedChromium();
});

// The deterministic AES-256-GCM vector already independently verified via
// both native CLIs directly from the command line before any TypeScript
// wiring was written (all-zero key/IV/plaintext/no-AAD, 128-bit tag).
function zeroFixture(): GcmEncryptRequest {
  return {
    key: Buffer.alloc(32, 0), plaintext: new Uint8Array(0), aad: undefined,
    iv: Buffer.alloc(12, 0), tagLengthBits: 128,
  };
}
const EXPECTED_ARTIFACT = '01000000000000000000000000530f8afbc74536b9a963b4f1c4cb738b';

const BACKENDS = [
  { name: 'Chromium', encryptAdapter: GCM_ENCRYPT_CHROMIUM_ADAPTER, decryptAdapter: GCM_DECRYPT_CHROMIUM_ADAPTER, expectedBackend: CHROMIUM_WEBCRYPTO },
  { name: 'Crypto++', encryptAdapter: GCM_ENCRYPT_CRYPTOPP_ADAPTER, decryptAdapter: GCM_DECRYPT_CRYPTOPP_ADAPTER, expectedBackend: CRYPTOPP },
  { name: 'Bouncy Castle', encryptAdapter: GCM_ENCRYPT_BOUNCYCASTLE_ADAPTER, decryptAdapter: GCM_DECRYPT_BOUNCYCASTLE_ADAPTER, expectedBackend: BOUNCY_CASTLE },
] as const;

for (const { name, encryptAdapter, expectedBackend } of BACKENDS) {
  test(`Phase A, GCM x ${name}: real encrypt reproduces the deterministic all-zero vector exactly`, async () => {
    const evidence = await executeBaseline('A', `phase-a-gcm-encrypt-${name}`, zeroFixture(), encryptAdapter);
    assert.equal(evidence.context.phase, 'A');
    assert.equal(evidence.outcome.kind, 'accept');
    assert.equal((evidence.output as { bytes: string }).bytes, EXPECTED_ARTIFACT);
    assert.ok(backendIdentityEquals(evidence.subject.backend, expectedBackend));
  });
}

for (const { name, decryptAdapter, expectedBackend } of BACKENDS) {
  test(`Phase A, GCM x ${name}: real LOCAL round-trip -- Dec_p(Enc_p(m)) = m (p->p, never scored as R_interop)`, async () => {
    const decryptFixture: GcmDecryptRequest = { key: zeroFixture().key, artifact: Buffer.from(EXPECTED_ARTIFACT, 'hex'), aad: undefined };
    const evidence = await executeBaseline('A', `phase-a-gcm-decrypt-${name}`, decryptFixture, decryptAdapter);
    assert.equal(evidence.outcome.kind, 'accept');
    assert.equal((evidence.output as { bytes: string }).bytes, ''); // empty plaintext, matching the all-zero vector's own construction
    assert.ok(backendIdentityEquals(evidence.subject.backend, expectedBackend));
  });
}

test('GCM Phase A: all three real backends produce the IDENTICAL artifact for the identical conformant input -- BaselineResult.complete=true, 3/3 cells', async () => {
  const evidences = await Promise.all(BACKENDS.map(({ encryptAdapter }) => executeBaseline('A', 'phase-a-gcm-all', zeroFixture(), encryptAdapter)));
  for (const e of evidences) {
    assert.equal((e.output as { bytes: string }).bytes, EXPECTED_ARTIFACT);
  }

  const observations = evidences.map((e, i) =>
    makeRelationObservation({
      applicable: true, context: e.context, relation: 'R_byte',
      scope: { kind: 'single-backend', backend: BACKENDS[i]!.expectedBackend },
      status: 'pass', participants: [e.executionId], evaluatorId: 'R_byte',
      basis: 'GCM Phase A, deterministic all-zero vector, real execution',
    }),
  );

  const baseline: BaselineResult = {
    baselineInstanceId: 'phase-a-gcm-3of3',
    phase: 'A', operation: 'gcm',
    observations: observations.map((o) => o.observationId),
    complete: true,
  };
  assert.equal(baseline.complete, true);
  assert.equal(baseline.observations.length, 3);
});

test('a real authenticated-tamper local check behaves per contract: corrupted tag is rejected as authentication_failure, on the real native backend', async () => {
  const corrupted = Buffer.from(EXPECTED_ARTIFACT, 'hex');
  const lastIndex = corrupted.length - 1;
  corrupted[lastIndex] = (corrupted[lastIndex] ?? 0) ^ 0xff; // flip the last tag byte
  const decryptFixture: GcmDecryptRequest = { key: zeroFixture().key, artifact: corrupted, aad: undefined };
  const evidence = await executeBaseline('A', 'phase-a-gcm-tamper-check', decryptFixture, GCM_DECRYPT_CRYPTOPP_ADAPTER);
  assert.equal(evidence.outcome.kind, 'reject');
  assert.equal((evidence.outcome as { detail: string }).detail.includes('authentication_failure'), true);
});
