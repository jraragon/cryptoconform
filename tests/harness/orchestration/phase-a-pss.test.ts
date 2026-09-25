import { test, after } from 'node:test';
import assert from 'node:assert/strict';
import { webcrypto } from 'node:crypto';

import { executeBaseline } from '../../../harness/orchestration/engine.js';
import { makePssSignChromiumAdapter, makePssVerifyChromiumAdapter } from '../../../harness/orchestration/pss-chromium-wiring.js';
import { makePssSignCryptoppAdapter, makePssVerifyCryptoppAdapter, makePssSignBouncyCastleAdapter, makePssVerifyBouncyCastleAdapter } from '../../../harness/orchestration/pss-native-wiring.js';
import { closeSharedChromium } from '../../../harness/orchestration/chromium-page.js';
import { makeRelationObservation } from '../../../harness/evidence/relation-observation.js';
import type { BaselineResult } from '../../../harness/evidence/baseline-result.js';
import { CHROMIUM_WEBCRYPTO, CRYPTOPP, BOUNCY_CASTLE, backendIdentityEquals } from '../../../harness/schema/backend-identity.js';
import type { OaepKeyHex as PssKeyHex } from '../../../harness/orchestration/oaep-chromium-wiring.js';
import type { PssSignRequest, PssVerifyRequest } from '../../../src/contract/pss.js';

after(async () => {
  await closeSharedChromium();
});

let pssKey: PssKeyHex;
function hexFromBase64Url(b64u: string): string {
  return Buffer.from(b64u, 'base64url').toString('hex');
}

test('setup: generate ONE real RSA-3072 PSS key pair via Node WebCrypto, shared across all three backends', async () => {
  const keyPair = await webcrypto.subtle.generateKey(
    { name: 'RSA-PSS', modulusLength: 3072, publicExponent: new Uint8Array([1, 0, 1]), hash: 'SHA-256' },
    true, ['sign', 'verify'],
  );
  const jwk = await webcrypto.subtle.exportKey('jwk', keyPair.privateKey);
  pssKey = {
    modulusHex: hexFromBase64Url(jwk.n!), publicExponentHex: hexFromBase64Url(jwk.e!), privateExponentHex: hexFromBase64Url(jwk.d!),
    pHex: hexFromBase64Url(jwk.p!), qHex: hexFromBase64Url(jwk.q!),
    dpHex: hexFromBase64Url(jwk.dp!), dqHex: hexFromBase64Url(jwk.dq!), qiHex: hexFromBase64Url(jwk.qi!),
  };
});

const MESSAGE = Buffer.from('cafebabecafebabecafebabecafebabe', 'hex');
function signFixture(): PssSignRequest {
  return { key: { role: 'private', modulusBits: 3072 }, message: MESSAGE, hash: 'SHA-256', mgfHash: 'SHA-256', saltLengthBytes: 32 };
}
function verifyFixture(signature: Buffer): PssVerifyRequest {
  return { key: { role: 'public', modulusBits: 3072 }, message: MESSAGE, signature, hash: 'SHA-256', mgfHash: 'SHA-256', saltLengthBytes: 32 };
}

const BACKEND_FACTORIES = [
  { name: 'Chromium', sign: makePssSignChromiumAdapter, verify: makePssVerifyChromiumAdapter, expectedBackend: CHROMIUM_WEBCRYPTO },
  { name: 'Crypto++', sign: makePssSignCryptoppAdapter, verify: makePssVerifyCryptoppAdapter, expectedBackend: CRYPTOPP },
  { name: 'Bouncy Castle', sign: makePssSignBouncyCastleAdapter, verify: makePssVerifyBouncyCastleAdapter, expectedBackend: BOUNCY_CASTLE },
] as const;

for (const { name, sign, verify, expectedBackend } of BACKEND_FACTORIES) {
  test(`Phase A, PSS x ${name}: real local baseline -- Verify_p(m, Sign_p(m)) = true (never signature-byte equality)`, async () => {
    const signEvidence = await executeBaseline('A', `phase-a-pss-sign-${name}`, signFixture(), sign(pssKey));
    assert.equal(signEvidence.outcome.kind, 'accept');
    assert.ok(backendIdentityEquals(signEvidence.subject.backend, expectedBackend));

    const signatureHex = (signEvidence.output as { bytes: string }).bytes;
    const verifyEvidence = await executeBaseline('A', `phase-a-pss-verify-${name}`, verifyFixture(Buffer.from(signatureHex, 'hex')), verify(pssKey));
    assert.equal(verifyEvidence.outcome.kind, 'accept'); // executionStatus/outcome.kind is 'accept' at the evidence-wrapper level regardless of the semantic verified value
    assert.equal((verifyEvidence.output as { bytes: string }).bytes, 'true', `${name} must report Verify_p(m, Sign_p(m)) = true`);
    assert.ok(backendIdentityEquals(verifyEvidence.subject.backend, expectedBackend));
  });
}

test('PSS Phase A: two independent signatures of the SAME message on the SAME backend are DIFFERENT bytes, yet BOTH verify true -- direct defense against ever treating R_byte as applicable to PSS (Applicability(R_byte,PSS)=0)', async () => {
  const s1 = await executeBaseline('A', 'pss-prob-sign-1', signFixture(), makePssSignCryptoppAdapter(pssKey));
  const s2 = await executeBaseline('A', 'pss-prob-sign-2', signFixture(), makePssSignCryptoppAdapter(pssKey));
  const sig1Hex = (s1.output as { bytes: string }).bytes;
  const sig2Hex = (s2.output as { bytes: string }).bytes;
  assert.notEqual(sig1Hex, sig2Hex, 'PSS is probabilistic -- two independent signatures of the same message must differ');

  const v1 = await executeBaseline('A', 'pss-prob-verify-1', verifyFixture(Buffer.from(sig1Hex, 'hex')), makePssVerifyCryptoppAdapter(pssKey));
  const v2 = await executeBaseline('A', 'pss-prob-verify-2', verifyFixture(Buffer.from(sig2Hex, 'hex')), makePssVerifyCryptoppAdapter(pssKey));
  assert.equal((v1.output as { bytes: string }).bytes, 'true');
  assert.equal((v2.output as { bytes: string }).bytes, 'true');
});

test('PSS Phase A: BaselineResult.complete=true, 3/3 cells -- built from real Verify_p(m,Sign_p(m))=true observations, never signature-byte equality', async () => {
  const results: Array<{ backend: typeof CHROMIUM_WEBCRYPTO; ok: boolean }> = [];
  for (const { sign, verify, expectedBackend } of BACKEND_FACTORIES) {
    const signEv = await executeBaseline('A', 'pss-all-sign', signFixture(), sign(pssKey));
    const sigHex = (signEv.output as { bytes: string }).bytes;
    const verifyEv = await executeBaseline('A', 'pss-all-verify', verifyFixture(Buffer.from(sigHex, 'hex')), verify(pssKey));
    results.push({ backend: expectedBackend, ok: (verifyEv.output as { bytes: string }).bytes === 'true' });
  }
  assert.ok(results.every((r) => r.ok));

  const observations = results.map((r) =>
    makeRelationObservation({
      applicable: true, context: { kind: 'baseline', phase: 'A', baselineInstanceId: 'pss-all' }, relation: 'R_val',
      scope: { kind: 'single-backend', backend: r.backend }, status: 'pass', participants: [],
      evaluatorId: 'R_val', basis: 'PSS Phase A local Verify(m,Sign(m))=true, real execution',
    }),
  );
  const baseline: BaselineResult = { baselineInstanceId: 'phase-a-pss-3of3', phase: 'A', operation: 'pss', observations: observations.map((o) => o.observationId), complete: true };
  assert.equal(baseline.complete, true);
  assert.equal(baseline.observations.length, 3);
});
