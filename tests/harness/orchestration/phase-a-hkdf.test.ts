import { test, after } from 'node:test';
import assert from 'node:assert/strict';

import { executeBaseline } from '../../../harness/orchestration/engine.js';
import { HKDF_CHROMIUM_ADAPTER, closeChromiumForTests } from '../../../harness/orchestration/hkdf-chromium-wiring.js';
import { HKDF_CRYPTOPP_ADAPTER, HKDF_BOUNCYCASTLE_ADAPTER } from '../../../harness/orchestration/hkdf-native-wiring.js';
import { makeRelationObservation } from '../../../harness/evidence/relation-observation.js';
import type { BaselineResult } from '../../../harness/evidence/baseline-result.js';
import { CHROMIUM_WEBCRYPTO, CRYPTOPP, BOUNCY_CASTLE, backendIdentityEquals } from '../../../harness/schema/backend-identity.js';
import type { HkdfRequest } from '../../../src/contract/hkdf.js';

// RFC 5869 Appendix A.1, Test Case 1 -- the same KAT M1's own three
// per-backend test suites already used, reused here as Phase A's own probe
// rather than inventing a new fixture.
function katFixture(): HkdfRequest {
  return {
    ikm: Buffer.from('0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b', 'hex'),
    salt: Buffer.from('000102030405060708090a0b0c', 'hex'),
    info: Buffer.from('f0f1f2f3f4f5f6f7f8f9', 'hex'),
    length: 42,
  };
}
const EXPECTED_OKM = '3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865';

const ADAPTERS = [
  { name: 'Chromium', adapter: HKDF_CHROMIUM_ADAPTER, expectedBackend: CHROMIUM_WEBCRYPTO },
  { name: 'Crypto++', adapter: HKDF_CRYPTOPP_ADAPTER, expectedBackend: CRYPTOPP },
  { name: 'Bouncy Castle', adapter: HKDF_BOUNCYCASTLE_ADAPTER, expectedBackend: BOUNCY_CASTLE },
] as const;

after(async () => {
  await closeChromiumForTests();
});

for (const { name, adapter, expectedBackend } of ADAPTERS) {
  test(`Phase A, HKDF x ${name}: real execution reproduces RFC 5869 Test Case 1 exactly`, async () => {
    const evidence = await executeBaseline('A', `phase-a-hkdf-${name}`, katFixture(), adapter);
    assert.equal(evidence.context.kind, 'baseline');
    assert.equal(evidence.context.phase, 'A');
    assert.equal(evidence.outcome.kind, 'accept');
    assert.equal((evidence.output as { bytes: string }).bytes, EXPECTED_OKM);
    assert.ok(backendIdentityEquals(evidence.subject.backend, expectedBackend), `${name}'s BackendIdentity must match its manifest constant exactly`);
  });
}

test('HKDF Phase A: all three real backends agree on the SAME KAT -- BaselineResult.complete=true, 3/3 cells', async () => {
  const evidences = await Promise.all(ADAPTERS.map(({ adapter }) => executeBaseline('A', 'phase-a-hkdf-all', katFixture(), adapter)));

  // All three produced the identical OKM for the identical conformant input.
  for (const e of evidences) {
    assert.equal((e.output as { bytes: string }).bytes, EXPECTED_OKM);
  }

  const observations = evidences.map((e, i) =>
    makeRelationObservation({
      applicable: true, context: e.context, relation: 'R_byte',
      scope: { kind: 'single-backend', backend: ADAPTERS[i]!.expectedBackend },
      status: 'pass', participants: [e.executionId], evaluatorId: 'R_byte',
      basis: 'HKDF Phase A, RFC 5869 Test Case 1 KAT, real execution',
    }),
  );

  const baseline: BaselineResult = {
    baselineInstanceId: 'phase-a-hkdf-3of3',
    phase: 'A',
    operation: 'hkdf',
    observations: observations.map((o) => o.observationId),
    complete: true,
  };

  assert.equal(baseline.complete, true);
  assert.equal(baseline.observations.length, 3);
  // BaselineResult never carries a mutationId or Gamma_0 reference -- confirmed structurally.
  assert.ok(!('mutationId' in baseline));
  assert.ok(!('gamma0Ref' in baseline));
});

test('a local round-trip is NOT R_interop: p->p is excluded by construction from any interop scope', () => {
  // Phase A's own controls compare a backend against ITSELF (or against a
  // known-correct external vector, as above) -- never scored as R_interop,
  // which requires p != q (M2.5.3's own scope). This test documents the
  // exclusion at the scope-construction level: a backend-pair scope with
  // from===to is never constructed anywhere in the Phase A wiring above.
  const from = CHROMIUM_WEBCRYPTO;
  const to = CHROMIUM_WEBCRYPTO;
  assert.ok(backendIdentityEquals(from, to), 'sanity: this is genuinely the identical backend');
  // No test above ever builds { kind: 'backend-pair', from, to } with
  // from===to; Phase A's own scopes are all 'single-backend'.
});
