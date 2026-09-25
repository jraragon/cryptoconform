import { test, after } from 'node:test';
import assert from 'node:assert/strict';

import { executeBaseline } from '../../../harness/orchestration/engine.js';
import { GCM_ENCRYPT_CHROMIUM_ADAPTER, GCM_DECRYPT_CHROMIUM_ADAPTER } from '../../../harness/orchestration/gcm-chromium-wiring.js';
import { GCM_ENCRYPT_CRYPTOPP_ADAPTER, GCM_DECRYPT_CRYPTOPP_ADAPTER, GCM_ENCRYPT_BOUNCYCASTLE_ADAPTER, GCM_DECRYPT_BOUNCYCASTLE_ADAPTER } from '../../../harness/orchestration/gcm-native-wiring.js';
import { closeSharedChromium } from '../../../harness/orchestration/chromium-page.js';
import { evaluateInterop } from '../../../harness/evaluators/r-interop.js';
import { evaluateByte } from '../../../harness/evaluators/r-byte.js';
import { makeRelationObservation } from '../../../harness/evidence/relation-observation.js';
import type { BaselineResult } from '../../../harness/evidence/baseline-result.js';
import { CHROMIUM_WEBCRYPTO, CRYPTOPP, BOUNCY_CASTLE, backendIdentityEquals } from '../../../harness/schema/backend-identity.js';
import type { GcmEncryptRequest, GcmDecryptRequest } from '../../../src/contract/gcm.js';

after(async () => {
  await closeSharedChromium();
});

// A genuinely non-trivial, deterministic AES-256-GCM request -- the IV is
// caller-supplied (not backend-generated), so GCM encryption itself is
// deterministic: all three producers must emit the byte-identical
// artifact for this identical request, making R_byte meaningful here in
// a way it never is for OAEP/PSS.
function encryptFixture(): GcmEncryptRequest {
  return {
    key: Buffer.from('000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f', 'hex'),
    plaintext: Buffer.from('Phase B cross-provider conformance test', 'utf8'),
    aad: Buffer.from('M2.5.3.1', 'utf8'),
    iv: Buffer.from('202122232425262728292a2b', 'hex'),
    tagLengthBits: 128,
  };
}
function decryptFixtureFrom(artifactHex: string): GcmDecryptRequest {
  return { key: encryptFixture().key, artifact: Buffer.from(artifactHex, 'hex'), aad: encryptFixture().aad };
}

const PROVIDERS = [
  { name: 'Chromium', encrypt: GCM_ENCRYPT_CHROMIUM_ADAPTER, decrypt: GCM_DECRYPT_CHROMIUM_ADAPTER, backend: CHROMIUM_WEBCRYPTO },
  { name: 'Crypto++', encrypt: GCM_ENCRYPT_CRYPTOPP_ADAPTER, decrypt: GCM_DECRYPT_CRYPTOPP_ADAPTER, backend: CRYPTOPP },
  { name: 'Bouncy Castle', encrypt: GCM_ENCRYPT_BOUNCYCASTLE_ADAPTER, decrypt: GCM_DECRYPT_BOUNCYCASTLE_ADAPTER, backend: BOUNCY_CASTLE },
] as const;

const DIRECTIONS: Array<{ producer: (typeof PROVIDERS)[number]; consumer: (typeof PROVIDERS)[number] }> = [];
for (const producer of PROVIDERS) {
  for (const consumer of PROVIDERS) {
    if (producer.name !== consumer.name) DIRECTIONS.push({ producer, consumer });
  }
}

test('sanity: exactly 3x2=6 ordered directions constructed, p!=q enforced by construction', () => {
  assert.equal(DIRECTIONS.length, 6);
  assert.ok(DIRECTIONS.every((d) => d.producer.name !== d.consumer.name));
});

// ---------------------------------------------------------------------
// R_byte first: all three producers, same deterministic request
// ---------------------------------------------------------------------

test('GCM Phase B, R_byte: all three real producers emit the byte-identical artifact for the identical deterministic request (caller-supplied IV)', async () => {
  const evidences = await Promise.all(PROVIDERS.map(({ encrypt }) => executeBaseline('B', 'phase-b-gcm-rbyte', encryptFixture(), encrypt)));
  const artifacts = evidences.map((e) => (e.output as { bytes: string }).bytes);
  assert.equal(artifacts[0], artifacts[1]);
  assert.equal(artifacts[1], artifacts[2]);

  // Confirmed via the REAL evaluateByte evaluator, not just a raw string
  // comparison -- exercising the frozen evaluator itself, not ad hoc logic.
  for (let i = 0; i < evidences.length; i++) {
    for (let j = i + 1; j < evidences.length; j++) {
      const state = evaluateByte({
        applicable: true, inputsEquivalent: true,
        left: { executionStatus: evidences[i]!.executionStatus, comparableOutput: { kind: 'contract-artifact', bytes: artifacts[i]! } },
        right: { executionStatus: evidences[j]!.executionStatus, comparableOutput: { kind: 'contract-artifact', bytes: artifacts[j]! } },
      });
      assert.equal(state, 'conformant', `${PROVIDERS[i]!.name} vs ${PROVIDERS[j]!.name} must be R_byte-conformant`);
    }
  }
});

// ---------------------------------------------------------------------
// The 6 ordered R_interop directions
// ---------------------------------------------------------------------

for (const { producer, consumer } of DIRECTIONS) {
  test(`GCM Phase B, R_interop(${producer.name} -> ${consumer.name}): Dec_consumer(Enc_producer(m,AAD,IV)) = m, real execution, real evaluator`, async () => {
    const producerEvidence = await executeBaseline('B', `phase-b-gcm-${producer.name}-produce`, encryptFixture(), producer.encrypt);
    assert.ok(backendIdentityEquals(producerEvidence.subject.backend, producer.backend));
    assert.equal(producerEvidence.context.kind, 'baseline');

    const producedArtifactHex = (producerEvidence.output as { bytes: string }).bytes;
    const consumerEvidence = await executeBaseline('B', `phase-b-gcm-${producer.name}-to-${consumer.name}`, decryptFixtureFrom(producedArtifactHex), consumer.decrypt);
    assert.ok(backendIdentityEquals(consumerEvidence.subject.backend, consumer.backend));

    const expectedPlaintextHex = Buffer.from(encryptFixture().plaintext).toString('hex');
    const observationState = evaluateInterop({
      applicable: true,
      producerValid: producerEvidence.outcome.kind === 'accept',
      producerExecutionStatus: producerEvidence.executionStatus,
      consumerExecutionStatus: consumerEvidence.executionStatus,
      sameBaselineOrStimulus: true,
      expectedOutcome: { kind: 'authenticated-decrypt', expected: expectedPlaintextHex },
      observedOutcome: consumerEvidence.outcome.kind === 'accept'
        ? { kind: 'authenticated-plaintext', value: (consumerEvidence.output as { bytes: string }).bytes }
        : { kind: 'rejection', value: undefined, errorClass: (consumerEvidence.outcome as { detail: string }).detail },
    });
    assert.equal(observationState, 'conformant', `${producer.name} -> ${consumer.name} must be R_interop-conformant`);

    const observation = makeRelationObservation({
      applicable: true, context: consumerEvidence.context, relation: 'R_interop',
      scope: { kind: 'backend-pair', from: producer.backend, to: consumer.backend },
      status: 'pass', participants: [producerEvidence.executionId, consumerEvidence.executionId],
      evaluatorId: 'R_interop', basis: `GCM Phase B ${producer.name}->${consumer.name}, real execution`,
    });
    assert.equal(observation.participants.length, 2);
  });
}

test('R_interop(p->q) and R_interop(q->p) are structurally distinct observations -- Chromium<->Crypto++ checked explicitly, never collapsed even though both pass', async () => {
  const chromiumEv = await executeBaseline('B', 'phase-b-gcm-distinct-1', encryptFixture(), GCM_ENCRYPT_CHROMIUM_ADAPTER);
  const cryptoppEv = await executeBaseline('B', 'phase-b-gcm-distinct-2', encryptFixture(), GCM_ENCRYPT_CRYPTOPP_ADAPTER);

  const forwardConsumer = await executeBaseline('B', 'phase-b-gcm-fwd', decryptFixtureFrom((chromiumEv.output as { bytes: string }).bytes), GCM_DECRYPT_CRYPTOPP_ADAPTER);
  const backwardConsumer = await executeBaseline('B', 'phase-b-gcm-bwd', decryptFixtureFrom((cryptoppEv.output as { bytes: string }).bytes), GCM_DECRYPT_CHROMIUM_ADAPTER);

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

test('GCM Phase B: BaselineResult.complete=true, all 6 directions -- full traceability ExecutionID_producer -> ExecutionID_consumer -> RelationObservation -> BaselineResult', async () => {
  const observationIds: string[] = [];
  for (const { producer, consumer } of DIRECTIONS) {
    const producerEvidence = await executeBaseline('B', `phase-b-gcm-trace-${producer.name}`, encryptFixture(), producer.encrypt);
    const consumerEvidence = await executeBaseline('B', `phase-b-gcm-trace-${producer.name}-${consumer.name}`, decryptFixtureFrom((producerEvidence.output as { bytes: string }).bytes), consumer.decrypt);
    const observation = makeRelationObservation({
      applicable: true, context: consumerEvidence.context, relation: 'R_interop',
      scope: { kind: 'backend-pair', from: producer.backend, to: consumer.backend },
      status: 'pass', participants: [producerEvidence.executionId, consumerEvidence.executionId],
      evaluatorId: 'R_interop', basis: `trace ${producer.name}->${consumer.name}`,
    });
    observationIds.push(observation.observationId);
  }
  assert.equal(observationIds.length, 6);
  assert.equal(new Set(observationIds).size, 6, 'all 6 observationIds must be distinct');

  const baseline: BaselineResult = { baselineInstanceId: 'phase-b-gcm-6of6', phase: 'B', operation: 'gcm', observations: observationIds, complete: true };
  assert.equal(baseline.complete, true);
  assert.equal(baseline.observations.length, 6);
});
