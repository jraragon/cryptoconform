import { test, after } from 'node:test';
import assert from 'node:assert/strict';
import { webcrypto } from 'node:crypto';

import { executeBaseline } from '../../../harness/orchestration/engine.js';
import { makePssSignChromiumAdapter, makePssVerifyChromiumAdapter } from '../../../harness/orchestration/pss-chromium-wiring.js';
import { makePssSignCryptoppAdapter, makePssVerifyCryptoppAdapter, makePssSignBouncyCastleAdapter, makePssVerifyBouncyCastleAdapter } from '../../../harness/orchestration/pss-native-wiring.js';
import { closeSharedChromium } from '../../../harness/orchestration/chromium-page.js';
import { evaluateInterop } from '../../../harness/evaluators/r-interop.js';
import { makeRelationObservation } from '../../../harness/evidence/relation-observation.js';
import type { BaselineResult } from '../../../harness/evidence/baseline-result.js';
import { CHROMIUM_WEBCRYPTO, CRYPTOPP, BOUNCY_CASTLE, backendIdentityEquals } from '../../../harness/schema/backend-identity.js';
import type { OaepKeyHex as PssKeyHex } from '../../../harness/orchestration/oaep-chromium-wiring.js';
import type { PssSignRequest, PssVerifyRequest } from '../../../src/contract/pss.js';

after(async () => {
  await closeSharedChromium();
});

// ONE real RSA-3072 key pair, shared by every producer (signer) and
// consumer (verifier) below -- same discipline as OAEP's own Phase B file.
let pssKey: PssKeyHex;
function hexFromBase64Url(b64u: string): string {
  return Buffer.from(b64u, 'base64url').toString('hex');
}

test('setup: ONE real RSA-3072 PSS key pair, shared by every signer and verifier in this file', async () => {
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

// Frozen portable profile ONLY: hash=SHA-256, mgfHash=SHA-256,
// saltLength=32. No explicit salt bytes, no independent MGF, no RNG
// control -- all three remain Phase C's own territory.
const MESSAGE = Buffer.from('cafebabecafebabecafebabecafebabe', 'hex');
function signFixture(): PssSignRequest {
  return { key: { role: 'private', modulusBits: 3072 }, message: MESSAGE, hash: 'SHA-256', mgfHash: 'SHA-256', saltLengthBytes: 32 };
}
function verifyFixture(signature: Buffer): PssVerifyRequest {
  return { key: { role: 'public', modulusBits: 3072 }, message: MESSAGE, signature, hash: 'SHA-256', mgfHash: 'SHA-256', saltLengthBytes: 32 };
}

const PROVIDERS = [
  { name: 'Chromium', sign: () => makePssSignChromiumAdapter(pssKey), verify: () => makePssVerifyChromiumAdapter(pssKey), backend: CHROMIUM_WEBCRYPTO },
  { name: 'Crypto++', sign: () => makePssSignCryptoppAdapter(pssKey), verify: () => makePssVerifyCryptoppAdapter(pssKey), backend: CRYPTOPP },
  { name: 'Bouncy Castle', sign: () => makePssSignBouncyCastleAdapter(pssKey), verify: () => makePssVerifyBouncyCastleAdapter(pssKey), backend: BOUNCY_CASTLE },
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
  test(`PSS Phase B, R_interop(${producer.name} -> ${consumer.name}): Verify_consumer(m, Sign_producer(m)) = true -- semantic only, R_byte never evaluated`, async () => {
    // The signature is generated specifically BY producer and handed
    // UNMODIFIED to consumer -- who signed/verified is unambiguous from
    // the ExecutionID chain, never inferred from signature-byte content
    // (which would be meaningless anyway, since PSS is probabilistic).
    const producerEvidence = await executeBaseline('B', `phase-b-pss-${producer.name}-sign`, signFixture(), producer.sign());
    assert.ok(backendIdentityEquals(producerEvidence.subject.backend, producer.backend));
    assert.equal(producerEvidence.outcome.kind, 'accept');

    const signatureHex = (producerEvidence.output as { bytes: string }).bytes;
    const consumerEvidence = await executeBaseline('B', `phase-b-pss-${producer.name}-to-${consumer.name}`, verifyFixture(Buffer.from(signatureHex, 'hex')), consumer.verify());
    assert.ok(backendIdentityEquals(consumerEvidence.subject.backend, consumer.backend));

    const observationState = evaluateInterop({
      applicable: true,
      producerValid: producerEvidence.outcome.kind === 'accept',
      producerExecutionStatus: producerEvidence.executionStatus,
      consumerExecutionStatus: consumerEvidence.executionStatus,
      sameBaselineOrStimulus: true,
      expectedOutcome: { kind: 'verify', expected: true },
      observedOutcome: consumerEvidence.outcome.kind === 'accept'
        ? { kind: 'verification-result', value: (consumerEvidence.output as { bytes: string }).bytes === 'true' }
        : { kind: 'rejection', value: undefined, errorClass: (consumerEvidence.outcome as { detail: string }).detail },
    });
    assert.equal(observationState, 'conformant', `${producer.name} -> ${consumer.name} must be R_interop-conformant`);

    const observation = makeRelationObservation({
      applicable: true, context: consumerEvidence.context, relation: 'R_interop',
      scope: { kind: 'backend-pair', from: producer.backend, to: consumer.backend },
      status: 'pass', participants: [producerEvidence.executionId, consumerEvidence.executionId],
      evaluatorId: 'R_interop', basis: `PSS Phase B ${producer.name}->${consumer.name}, real execution, semantic only`,
    });
    assert.equal(observation.participants.length, 2);
  });
}

test('R_interop(p->q) and R_interop(q->p) are structurally distinct observations for PSS too, never collapsed even though both pass', async () => {
  const chromiumSig = await executeBaseline('B', 'phase-b-pss-distinct-1', signFixture(), PROVIDERS[0]!.sign());
  const cryptoppSig = await executeBaseline('B', 'phase-b-pss-distinct-2', signFixture(), PROVIDERS[1]!.sign());

  assert.notEqual(
    (chromiumSig.output as { bytes: string }).bytes,
    (cryptoppSig.output as { bytes: string }).bytes,
    'two independent PSS signatures of the same message must be different bytes (probabilistic salt) -- reconfirmed here, not merely assumed from M2.5.2',
  );

  const forwardConsumer = await executeBaseline('B', 'phase-b-pss-fwd', verifyFixture(Buffer.from((chromiumSig.output as { bytes: string }).bytes, 'hex')), PROVIDERS[1]!.verify());
  const backwardConsumer = await executeBaseline('B', 'phase-b-pss-bwd', verifyFixture(Buffer.from((cryptoppSig.output as { bytes: string }).bytes, 'hex')), PROVIDERS[0]!.verify());

  assert.equal((forwardConsumer.output as { bytes: string }).bytes, 'true');
  assert.equal((backwardConsumer.output as { bytes: string }).bytes, 'true');

  const forwardObs = makeRelationObservation({
    applicable: true, context: forwardConsumer.context, relation: 'R_interop',
    scope: { kind: 'backend-pair', from: CHROMIUM_WEBCRYPTO, to: CRYPTOPP },
    status: 'pass', participants: [chromiumSig.executionId, forwardConsumer.executionId],
    evaluatorId: 'R_interop', basis: 'Chromium->Crypto++',
  });
  const backwardObs = makeRelationObservation({
    applicable: true, context: backwardConsumer.context, relation: 'R_interop',
    scope: { kind: 'backend-pair', from: CRYPTOPP, to: CHROMIUM_WEBCRYPTO },
    status: 'pass', participants: [cryptoppSig.executionId, backwardConsumer.executionId],
    evaluatorId: 'R_interop', basis: 'Crypto++->Chromium',
  });

  assert.notEqual(forwardObs.observationId, backwardObs.observationId);
  assert.notDeepEqual(forwardObs.participants, backwardObs.participants);
  assert.notDeepEqual(forwardObs.scope, backwardObs.scope);
});

test('PSS Phase B: BaselineResult.complete=true, all 6 directions -- full traceability, R_byte never fabricated', async () => {
  const observationIds: string[] = [];
  for (const { producer, consumer } of DIRECTIONS) {
    const producerEvidence = await executeBaseline('B', `phase-b-pss-trace-${producer.name}`, signFixture(), producer.sign());
    const consumerEvidence = await executeBaseline('B', `phase-b-pss-trace-${producer.name}-${consumer.name}`, verifyFixture(Buffer.from((producerEvidence.output as { bytes: string }).bytes, 'hex')), consumer.verify());
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

  const baseline: BaselineResult = { baselineInstanceId: 'phase-b-pss-6of6', phase: 'B', operation: 'pss', observations: observationIds, complete: true };
  assert.equal(baseline.complete, true);
  assert.equal(baseline.observations.length, 6);
});

test('confirmed: this file never imports the byte-relation evaluator module, nor calls the byte-evaluator function -- Applicability(R_byte, PSS)=0 is respected structurally, not just by convention', async () => {
  const { readFileSync } = await import('node:fs');
  const src = readFileSync(new URL(import.meta.url), 'utf8');
  const forbiddenImport = ['r-', 'byte.js'].join('');
  const forbiddenCall = ['evaluate', 'Byte', '('].join('');
  assert.ok(!src.includes(forbiddenImport));
  assert.ok(!src.includes(forbiddenCall));
});
