import { test, after } from 'node:test';
import assert from 'node:assert/strict';

import { executeBaseline, executeMutation } from '../../../harness/orchestration/engine.js';
import { HKDF_CHROMIUM_ADAPTER, closeChromiumForTests } from '../../../harness/orchestration/hkdf-chromium-wiring.js';
import { HKDF_NODE_WEBCRYPTO_ADAPTER } from '../../../harness/orchestration/hkdf-wiring.js';
import { HKDF_INFO_TAMPER } from '../../../harness/mutations/hkdf.js';
import { evaluateByte } from '../../../harness/evaluators/r-byte.js';
import { CHROMIUM_WEBCRYPTO, NODE_WEBCRYPTO_OPENSSL, backendIdentityEquals } from '../../../harness/schema/backend-identity.js';
import type { HkdfRequest } from '../../../src/contract/hkdf.js';

after(async () => {
  await closeChromiumForTests();
});

function baseFixture(): HkdfRequest {
  return { ikm: new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8]), salt: undefined, info: new Uint8Array([9, 9, 9]), length: 32 };
}

test('M2.5.1 CRITICAL: a real execution against actual Chromium/Playwright produces subject.backend === CHROMIUM_WEBCRYPTO, full structural equality', async () => {
  const evidence = await executeBaseline('B', 'chromium-baseline-1', baseFixture(), HKDF_CHROMIUM_ADAPTER);
  assert.equal(evidence.outcome.kind, 'accept');
  assert.ok(backendIdentityEquals(evidence.subject.backend, CHROMIUM_WEBCRYPTO), 'must match the frozen manifest backend exactly');
  assert.deepEqual(evidence.subject.backend, CHROMIUM_WEBCRYPTO);
  assert.ok(evidence.output && (evidence.output as { bytes: string }).bytes.length > 0, 'a real OKM must have been produced by actual Chromium WebCrypto');
});

test('the Chromium execution is NEVER collapsed into NODE_WEBCRYPTO_OPENSSL -- distinct realizations, both real', async () => {
  const evidence = await executeBaseline('B', 'chromium-baseline-2', baseFixture(), HKDF_CHROMIUM_ADAPTER);
  assert.ok(!backendIdentityEquals(evidence.subject.backend, NODE_WEBCRYPTO_OPENSSL));
  assert.notEqual(evidence.subject.backend.sourcePin, NODE_WEBCRYPTO_OPENSSL.sourcePin);
});

test('real Chromium and real Node WebCrypto independently compute the SAME OKM for the SAME conformant input -- both correct implementations of the identical HKDF-SHA-256 standard', async () => {
  const fixture = baseFixture();
  const chromiumEvidence = await executeBaseline('B', 'chromium-baseline-3', fixture, HKDF_CHROMIUM_ADAPTER);
  const nodeEvidence = await executeBaseline('B', 'node-baseline-3', fixture, HKDF_NODE_WEBCRYPTO_ADAPTER);

  const observationState = evaluateByte({
    applicable: true, inputsEquivalent: true,
    left: { executionStatus: chromiumEvidence.executionStatus, comparableOutput: { kind: 'raw-output', bytes: (chromiumEvidence.output as { bytes: string }).bytes } },
    right: { executionStatus: nodeEvidence.executionStatus, comparableOutput: { kind: 'raw-output', bytes: (nodeEvidence.output as { bytes: string }).bytes } },
  });
  assert.equal(observationState, 'conformant', 'a genuinely conformant baseline must NOT show cross-provider divergence -- the M2.5.4 false-positive gate, exercised here for the first real pair');
});

test('executeMutation against real Chromium: HKDF-INFO-TAMPER produces a genuinely different, real OKM', async () => {
  const fixture = baseFixture();
  const baseline = await executeBaseline('B', 'chromium-baseline-4', fixture, HKDF_CHROMIUM_ADAPTER);
  const mutated = await executeMutation(HKDF_INFO_TAMPER, 'default', fixture, HKDF_CHROMIUM_ADAPTER);
  assert.notDeepEqual((baseline.output as { bytes: string }).bytes, (mutated.output as { bytes: string }).bytes);
  assert.equal(mutated.context.kind, 'mutation');
});

test('launched Chromium version matches the frozen manifest apiVersion exactly, confirmed from a real browser instance', async () => {
  // Re-derived from the same executeBaseline call above -- the adapter
  // itself stamps CHROMIUM_WEBCRYPTO.apiVersion, but this test additionally
  // confirms the REAL launched browser reports the identical version string
  // (not merely that our own constant says so).
  const { chromium } = await import('playwright');
  const browser = await chromium.launch();
  const version = browser.version();
  await browser.close();
  assert.equal(version, CHROMIUM_WEBCRYPTO.apiVersion, 'the manifest pin must match what actually launches, not an assumed version');
});
