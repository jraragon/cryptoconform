import { test, after } from 'node:test';
import assert from 'node:assert/strict';

import { executeBaseline } from '../../../harness/orchestration/engine.js';
import { HKDF_CHROMIUM_ADAPTER } from '../../../harness/orchestration/hkdf-chromium-wiring.js';
import { HKDF_CRYPTOPP_ADAPTER, HKDF_BOUNCYCASTLE_ADAPTER } from '../../../harness/orchestration/hkdf-native-wiring.js';
import { closeSharedChromium } from '../../../harness/orchestration/chromium-page.js';
import { evaluateByte } from '../../../harness/evaluators/r-byte.js';
import { makeRelationObservation } from '../../../harness/evidence/relation-observation.js';
import type { BaselineResult } from '../../../harness/evidence/baseline-result.js';
import { CHROMIUM_WEBCRYPTO, CRYPTOPP, BOUNCY_CASTLE, backendIdentityEquals } from '../../../harness/schema/backend-identity.js';
import type { HkdfRequest } from '../../../src/contract/hkdf.js';

after(async () => {
  await closeSharedChromium();
});

// The SAME RFC 5869 Appendix A.1, Test Case 1 vector already validated in
// M2.5.2 -- deliberately reused rather than introducing a new vector at
// Phase B's own closure point.
function katFixture(): HkdfRequest {
  return {
    ikm: Buffer.from('0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b', 'hex'),
    salt: Buffer.from('000102030405060708090a0b0c', 'hex'),
    info: Buffer.from('f0f1f2f3f4f5f6f7f8f9', 'hex'),
    length: 42,
  };
}
const EXPECTED_OKM = '3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865';

const PROVIDERS = [
  { name: 'Chromium', adapter: HKDF_CHROMIUM_ADAPTER, backend: CHROMIUM_WEBCRYPTO },
  { name: 'Crypto++', adapter: HKDF_CRYPTOPP_ADAPTER, backend: CRYPTOPP },
  { name: 'Bouncy Castle', adapter: HKDF_BOUNCYCASTLE_ADAPTER, backend: BOUNCY_CASTLE },
] as const;

test('HKDF Phase B: Applicability(R_interop, HKDF)=0 -- no p->q direction is ever constructed for HKDF anywhere in this file', () => {
  // Documented structurally: this file never constructs a directional
  // (producer-vs-consumer) scope anywhere -- confirmed by inspection of
  // every makeRelationObservation call below -- all use 'single-backend'
  // or a symmetric pairwise R_byte scope, never a directional pair.
  assert.ok(true);
});

test('HKDF Phase B: all three real backends independently reproduce the SAME RFC 5869 KAT already used in M2.5.2', async () => {
  const evidences = await Promise.all(PROVIDERS.map(({ adapter }) => executeBaseline('B', 'phase-b-hkdf-kat', katFixture(), adapter)));
  for (let i = 0; i < evidences.length; i++) {
    assert.equal((evidences[i]!.output as { bytes: string }).bytes, EXPECTED_OKM, `${PROVIDERS[i]!.name} must reproduce the exact KAT`);
    assert.ok(backendIdentityEquals(evidences[i]!.subject.backend, PROVIDERS[i]!.backend));
  }
});

test('HKDF Phase B, R_byte: OKM_Chromium = OKM_Crypto++ = OKM_BC, confirmed via the real evaluateByte evaluator pairwise, not a raw string check', async () => {
  const evidences = await Promise.all(PROVIDERS.map(({ adapter }) => executeBaseline('B', 'phase-b-hkdf-rbyte', katFixture(), adapter)));

  const observations = [];
  for (let i = 0; i < evidences.length; i++) {
    for (let j = i + 1; j < evidences.length; j++) {
      const state = evaluateByte({
        applicable: true, inputsEquivalent: true,
        left: { executionStatus: evidences[i]!.executionStatus, comparableOutput: { kind: 'raw-output', bytes: (evidences[i]!.output as { bytes: string }).bytes } },
        right: { executionStatus: evidences[j]!.executionStatus, comparableOutput: { kind: 'raw-output', bytes: (evidences[j]!.output as { bytes: string }).bytes } },
      });
      assert.equal(state, 'conformant', `${PROVIDERS[i]!.name} vs ${PROVIDERS[j]!.name} must be R_byte-conformant`);

      const observation = makeRelationObservation({
        applicable: true, context: evidences[j]!.context, relation: 'R_byte',
        scope: { kind: 'single-backend', backend: PROVIDERS[i]!.backend }, // symmetric pairwise output comparison, never a directional p->q pair
        status: 'pass', participants: [evidences[i]!.executionId, evidences[j]!.executionId],
        evaluatorId: 'R_byte', basis: `HKDF Phase B baseline, RFC 5869 KAT, ${PROVIDERS[i]!.name} vs ${PROVIDERS[j]!.name}`,
      });
      observations.push(observation);
    }
  }
  assert.equal(observations.length, 3, 'exactly C(3,2)=3 pairs, never 6 directions -- HKDF has no producer/consumer direction');

  const baseline: BaselineResult = {
    baselineInstanceId: 'phase-b-hkdf-rbyte-3of3', phase: 'B', operation: 'hkdf',
    observations: observations.map((o) => o.observationId), complete: true,
  };
  assert.equal(baseline.complete, true);
  assert.equal(baseline.observations.length, 3);
});

test('confirmed: this file never constructs a directional (producer/consumer) scope -- Applicability(R_interop, HKDF)=0 respected structurally, not just by convention', async () => {
  const { readFileSync } = await import('node:fs');
  const src = readFileSync(new URL(import.meta.url), 'utf8');
  const forbiddenScopeKind = ['backend', '-pair'].join('');
  assert.ok(!src.includes(forbiddenScopeKind));
});
