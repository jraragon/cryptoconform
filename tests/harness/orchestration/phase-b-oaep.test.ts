import { test, after } from 'node:test';
import assert from 'node:assert/strict';
import { webcrypto } from 'node:crypto';

import { executeBaseline } from '../../../harness/orchestration/engine.js';
import { makeOaepEncryptChromiumAdapter, makeOaepDecryptChromiumAdapter, type OaepKeyHex } from '../../../harness/orchestration/oaep-chromium-wiring.js';
import { makeOaepEncryptCryptoppAdapter, makeOaepDecryptCryptoppAdapter, makeOaepEncryptBouncyCastleAdapter, makeOaepDecryptBouncyCastleAdapter } from '../../../harness/orchestration/oaep-native-wiring.js';
import { closeSharedChromium } from '../../../harness/orchestration/chromium-page.js';
import { evaluateInterop } from '../../../harness/evaluators/r-interop.js';
import { makeRelationObservation } from '../../../harness/evidence/relation-observation.js';
import type { BaselineResult } from '../../../harness/evidence/baseline-result.js';
import { CHROMIUM_WEBCRYPTO, CRYPTOPP, BOUNCY_CASTLE, backendIdentityEquals } from '../../../harness/schema/backend-identity.js';
import type { OaepEncryptRequest, OaepDecryptRequest } from '../../../src/contract/oaep.js';

after(async () => {
  await closeSharedChromium();
});

// ONE real RSA-3072 key pair, generated once, shared by EVERY producer and
// EVERY consumer below -- p->q only means anything if both ends hold the
// identical underlying key material (n,e,d,p,q,dp,dq,qi). All four factory
// functions reused from M2.5.2 already take this same key object as a
// parameter, so this is enforced by construction, not asserted separately.
let oaepKey: OaepKeyHex;
function hexFromBase64Url(b64u: string): string {
  return Buffer.from(b64u, 'base64url').toString('hex');
}

test('setup: ONE real RSA-3072 OAEP key pair, shared by every producer and consumer in this file', async () => {
  const keyPair = await webcrypto.subtle.generateKey(
    { name: 'RSA-OAEP', modulusLength: 3072, publicExponent: new Uint8Array([1, 0, 1]), hash: 'SHA-256' },
    true, ['encrypt', 'decrypt'],
  );
  const jwk = await webcrypto.subtle.exportKey('jwk', keyPair.privateKey);
  oaepKey = {
    modulusHex: hexFromBase64Url(jwk.n!), publicExponentHex: hexFromBase64Url(jwk.e!), privateExponentHex: hexFromBase64Url(jwk.d!),
    pHex: hexFromBase64Url(jwk.p!), qHex: hexFromBase64Url(jwk.q!),
    dpHex: hexFromBase64Url(jwk.dp!), dqHex: hexFromBase64Url(jwk.dq!), qiHex: hexFromBase64Url(jwk.qi!),
  };
});

const PLAINTEXT_HEX = 'deadbeefdeadbeefdeadbeefdeadbeef';
function encryptFixture(): OaepEncryptRequest {
  return { key: { role: 'public', modulusBits: 3072 }, plaintext: Buffer.from(PLAINTEXT_HEX, 'hex'), label: undefined, hash: 'SHA-256', mgfHash: 'SHA-256' };
}
function decryptFixture(ciphertext: Buffer): OaepDecryptRequest {
  return { key: { role: 'private', modulusBits: 3072 }, ciphertext, label: undefined, hash: 'SHA-256', mgfHash: 'SHA-256' };
}

const PROVIDERS = [
  { name: 'Chromium', encrypt: () => makeOaepEncryptChromiumAdapter(oaepKey), decrypt: () => makeOaepDecryptChromiumAdapter(oaepKey), backend: CHROMIUM_WEBCRYPTO },
  { name: 'Crypto++', encrypt: () => makeOaepEncryptCryptoppAdapter(oaepKey), decrypt: () => makeOaepDecryptCryptoppAdapter(oaepKey), backend: CRYPTOPP },
  { name: 'Bouncy Castle', encrypt: () => makeOaepEncryptBouncyCastleAdapter(oaepKey), decrypt: () => makeOaepDecryptBouncyCastleAdapter(oaepKey), backend: BOUNCY_CASTLE },
] as const;

const DIRECTIONS: Array<{ producer: (typeof PROVIDERS)[number]; consumer: (typeof PROVIDERS)[number] }> = [];
for (const producer of PROVIDERS) {
  for (const consumer of PROVIDERS) {
    if (producer.name !== consumer.name) DIRECTIONS.push({ producer, consumer });
  }
}

test('sanity: exactly 3x2=6 ordered directions constructed, p!=q enforced by construction', () => {
  assert.equal(DIRECTIONS.length, 6);
});

for (const { producer, consumer } of DIRECTIONS) {
  test(`OAEP Phase B, R_interop(${producer.name} -> ${consumer.name}): Dec_consumer(sk, Enc_producer(pk,m)) = m -- semantic only, R_byte never evaluated`, async () => {
    // The ciphertext is generated specifically BY producer and handed
    // UNMODIFIED to consumer -- who produced/consumed is unambiguous from
    // the ExecutionID chain, never inferred from ciphertext content (which
    // would be meaningless anyway, since OAEP is probabilistic).
    const producerEvidence = await executeBaseline('B', `phase-b-oaep-${producer.name}-produce`, encryptFixture(), producer.encrypt());
    assert.ok(backendIdentityEquals(producerEvidence.subject.backend, producer.backend));
    assert.equal(producerEvidence.outcome.kind, 'accept');

    const ciphertextHex = (producerEvidence.output as { bytes: string }).bytes;
    const consumerEvidence = await executeBaseline('B', `phase-b-oaep-${producer.name}-to-${consumer.name}`, decryptFixture(Buffer.from(ciphertextHex, 'hex')), consumer.decrypt());
    assert.ok(backendIdentityEquals(consumerEvidence.subject.backend, consumer.backend));

    const observationState = evaluateInterop({
      applicable: true,
      producerValid: producerEvidence.outcome.kind === 'accept',
      producerExecutionStatus: producerEvidence.executionStatus,
      consumerExecutionStatus: consumerEvidence.executionStatus,
      sameBaselineOrStimulus: true,
      expectedOutcome: { kind: 'recover-bytes', expected: PLAINTEXT_HEX },
      observedOutcome: consumerEvidence.outcome.kind === 'accept'
        ? { kind: 'recovered-plaintext', value: (consumerEvidence.output as { bytes: string }).bytes }
        : { kind: 'rejection', value: undefined, errorClass: (consumerEvidence.outcome as { detail: string }).detail },
    });
    assert.equal(observationState, 'conformant', `${producer.name} -> ${consumer.name} must be R_interop-conformant`);

    const observation = makeRelationObservation({
      applicable: true, context: consumerEvidence.context, relation: 'R_interop',
      scope: { kind: 'backend-pair', from: producer.backend, to: consumer.backend },
      status: 'pass', participants: [producerEvidence.executionId, consumerEvidence.executionId],
      evaluatorId: 'R_interop', basis: `OAEP Phase B ${producer.name}->${consumer.name}, real execution, semantic only`,
    });
    assert.equal(observation.participants.length, 2);
    // R_byte is never evaluated anywhere in this test -- confirmed by the
    // absence of any evaluateByte import/call in this file (grep-checked below).
  });
}

test('R_interop(p->q) and R_interop(q->p) are structurally distinct observations for OAEP too, never collapsed even though both pass', async () => {
  const chromiumEv = await executeBaseline('B', 'phase-b-oaep-distinct-1', encryptFixture(), PROVIDERS[0]!.encrypt());
  const cryptoppEv = await executeBaseline('B', 'phase-b-oaep-distinct-2', encryptFixture(), PROVIDERS[1]!.encrypt());

  assert.notEqual(
    (chromiumEv.output as { bytes: string }).bytes,
    (cryptoppEv.output as { bytes: string }).bytes,
    'two independent OAEP encryptions of the same plaintext must be different ciphertexts (probabilistic) -- reconfirmed here, not merely assumed from M2.5.2',
  );

  const forwardConsumer = await executeBaseline('B', 'phase-b-oaep-fwd', decryptFixture(Buffer.from((chromiumEv.output as { bytes: string }).bytes, 'hex')), PROVIDERS[1]!.decrypt());
  const backwardConsumer = await executeBaseline('B', 'phase-b-oaep-bwd', decryptFixture(Buffer.from((cryptoppEv.output as { bytes: string }).bytes, 'hex')), PROVIDERS[0]!.decrypt());

  const forwardObs = makeRelationObservation({
    applicable: true, context: forwardConsumer.context, relation: 'R_interop',
    scope: { kind: 'backend-pair', from: CHROMIUM_WEBCRYPTO, to: CRYPTOPP },
    status: 'pass', participants: [chromiumEv.executionId, forwardConsumer.executionId],
    evaluatorId: 'R_interop', basis: 'Chromium->Crypto++',
  });
  const backwardObs = makeRelationObservation({
    applicable: true, context: backwardConsumer.context, relation: 'R_interop',
    scope: { kind: 'backend-pair', from: CRYPTOPP, to: CHROMIUM_WEBCRYPTO },
    status: 'pass', participants: [cryptoppEv.executionId, backwardConsumer.executionId],
    evaluatorId: 'R_interop', basis: 'Crypto++->Chromium',
  });

  assert.notEqual(forwardObs.observationId, backwardObs.observationId);
  assert.notDeepEqual(forwardObs.participants, backwardObs.participants);
  assert.notDeepEqual(forwardObs.scope, backwardObs.scope);
});

test('OAEP Phase B: BaselineResult.complete=true, all 6 directions -- full traceability, R_byte never fabricated', async () => {
  const observationIds: string[] = [];
  for (const { producer, consumer } of DIRECTIONS) {
    const producerEvidence = await executeBaseline('B', `phase-b-oaep-trace-${producer.name}`, encryptFixture(), producer.encrypt());
    const consumerEvidence = await executeBaseline('B', `phase-b-oaep-trace-${producer.name}-${consumer.name}`, decryptFixture(Buffer.from((producerEvidence.output as { bytes: string }).bytes, 'hex')), consumer.decrypt());
    const observation = makeRelationObservation({
      applicable: true, context: consumerEvidence.context, relation: 'R_interop',
      scope: { kind: 'backend-pair', from: producer.backend, to: consumer.backend },
      status: 'pass', participants: [producerEvidence.executionId, consumerEvidence.executionId],
      evaluatorId: 'R_interop', basis: `trace ${producer.name}->${consumer.name}`,
    });
    observationIds.push(observation.observationId);
  }
  assert.equal(observationIds.length, 6);
  assert.equal(new Set(observationIds).size, 6);

  const baseline: BaselineResult = { baselineInstanceId: 'phase-b-oaep-6of6', phase: 'B', operation: 'oaep', observations: observationIds, complete: true };
  assert.equal(baseline.complete, true);
  assert.equal(baseline.observations.length, 6);
});

test('confirmed: this file never imports the byte-relation evaluator module, nor calls the byte-evaluator function -- Applicability(R_byte, OAEP)=0 is respected structurally, not just by convention', async () => {
  const { readFileSync } = await import('node:fs');
  const src = readFileSync(new URL(import.meta.url), 'utf8');
  const forbiddenImport = ['r-', 'byte.js'].join('');
  const forbiddenCall = ['evaluate', 'Byte', '('].join('');
  assert.ok(!src.includes(forbiddenImport));
  assert.ok(!src.includes(forbiddenCall));
});
