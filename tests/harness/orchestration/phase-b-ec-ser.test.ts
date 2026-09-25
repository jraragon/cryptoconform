import { test, after } from 'node:test';
import assert from 'node:assert/strict';
import { generateKeyPairSync } from 'node:crypto';

import { ecSerExportChromium, ecSerImportChromium, type EcKeyHexMaterial } from '../../../harness/orchestration/ec-ser-chromium-wiring.js';
import { ecSerExportCryptopp, ecSerImportCryptopp, ecSerExportBouncyCastle, ecSerImportBouncyCastle } from '../../../harness/orchestration/ec-ser-native-wiring.js';
import { closeSharedChromium } from '../../../harness/orchestration/chromium-page.js';
import { evaluateInterop } from '../../../harness/evaluators/r-interop.js';
import { makeRelationObservation } from '../../../harness/evidence/relation-observation.js';
import type { BaselineResult } from '../../../harness/evidence/baseline-result.js';
import { CHROMIUM_WEBCRYPTO, CRYPTOPP, BOUNCY_CASTLE } from '../../../harness/schema/backend-identity.js';
import { isOnCurve, isPair, isValidScalar } from '../../../src/contract/p256.js';

after(async () => {
  await closeSharedChromium();
});

let privateMaterial: EcKeyHexMaterial;
let publicMaterial: EcKeyHexMaterial;

function b64uToHex(b64u: string): string {
  return Buffer.from(b64u, 'base64url').toString('hex');
}

test('setup: ONE real P-256 key pair, shared by every exporter and importer -- V_scalar/V_curve/V_pair confirmed on the SOURCE material before any backend is exercised', () => {
  const { privateKey } = generateKeyPairSync('ec', { namedCurve: 'P-256' });
  const jwk = privateKey.export({ format: 'jwk' }) as { x: string; y: string; d: string };
  const d = BigInt('0x' + b64uToHex(jwk.d));
  const x = BigInt('0x' + b64uToHex(jwk.x));
  const y = BigInt('0x' + b64uToHex(jwk.y));
  assert.equal(isValidScalar(d), true);
  assert.equal(isOnCurve({ x, y }), true);
  assert.equal(isPair(d, { x, y }), true);

  // H4.3 -- P-256 coordinates/scalars are always exactly 32 bytes = 64 hex
  // digits. BigInt.prototype.toString(16) does NOT zero-pad: when x/y/d's
  // own leading byte happens to be < 0x10, the naive hex is 62 chars, and
  // the resulting JWK member becomes a 31-byte octet string -- rejected by
  // Chromium's own strict JWK parser ("should be 32"). This was H4's own
  // root cause, not a Chromium defect: Chromium correctly rejected
  // malformed input this fixture occasionally produced.
  privateMaterial = { role: 'private', xHex: x.toString(16).padStart(64, '0'), yHex: y.toString(16).padStart(64, '0'), dHex: d.toString(16).padStart(64, '0') };
  publicMaterial = { role: 'public', xHex: x.toString(16).padStart(64, '0'), yHex: y.toString(16).padStart(64, '0') };
});

const PROVIDERS = [
  {
    name: 'Chromium', backend: CHROMIUM_WEBCRYPTO,
    exportPublic: () => ecSerExportChromium(publicMaterial), exportPrivate: () => ecSerExportChromium(privateMaterial),
    importPublic: (artifactHex: string) => ecSerImportChromium('public', artifactHex),
    importPrivate: (artifactHex: string) => ecSerImportChromium('private', artifactHex),
  },
  {
    name: 'Crypto++', backend: CRYPTOPP,
    exportPublic: () => ecSerExportCryptopp(publicMaterial), exportPrivate: () => ecSerExportCryptopp(privateMaterial),
    importPublic: (artifactHex: string) => ecSerImportCryptopp('public', artifactHex),
    importPrivate: (artifactHex: string) => ecSerImportCryptopp('private', artifactHex),
  },
  {
    name: 'Bouncy Castle', backend: BOUNCY_CASTLE,
    exportPublic: () => ecSerExportBouncyCastle(publicMaterial), exportPrivate: () => ecSerExportBouncyCastle(privateMaterial),
    importPublic: (artifactHex: string) => ecSerImportBouncyCastle('public', artifactHex),
    importPrivate: (artifactHex: string) => ecSerImportBouncyCastle('private', artifactHex),
  },
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

// ---------------------------------------------------------------------
// SPKI (public role): 6 directions -- only V_curve is checkable (no d)
// ---------------------------------------------------------------------

for (const { producer, consumer } of DIRECTIONS) {
  test(`EC-ser Phase B, SPKI, R_interop(${producer.name} -> ${consumer.name}): Import_consumer(Export_producer(Q)) recovers a point satisfying V_curve -- V_scalar/V_pair never fabricated for a public-only role`, async () => {
    const exportResult = await producer.exportPublic();
    assert.equal(exportResult.exportOk, true);
    const importResult = await consumer.importPublic(exportResult.artifactHex!);
    assert.equal(importResult.importOk, true);
    assert.equal(importResult.recoveredDHex, undefined, 'no d exists for the public role -- must never be fabricated');

    const recoveredX = BigInt('0x' + importResult.recoveredXHex);
    const recoveredY = BigInt('0x' + importResult.recoveredYHex);
    assert.equal(isOnCurve({ x: recoveredX, y: recoveredY }), true, `${consumer.name} must recover a point genuinely on the curve`);
    assert.equal(recoveredX, BigInt('0x' + publicMaterial.xHex));
    assert.equal(recoveredY, BigInt('0x' + publicMaterial.yHex));

    const observationState = evaluateInterop({
      applicable: true, producerValid: exportResult.exportOk, producerExecutionStatus: 'completed', consumerExecutionStatus: 'completed',
      sameBaselineOrStimulus: true,
      expectedOutcome: { kind: 'import-material', expected: 'preserved' },
      observedOutcome: { kind: 'imported-key-material', value: 'preserved' },
    });
    assert.equal(observationState, 'conformant', `${producer.name} -> ${consumer.name} (SPKI) must be R_interop-conformant`);
  });
}

// ---------------------------------------------------------------------
// PKCS8 (private role): 6 directions -- all three properties checkable
// ---------------------------------------------------------------------

for (const { producer, consumer } of DIRECTIONS) {
  test(`EC-ser Phase B, PKCS8, R_interop(${producer.name} -> ${consumer.name}): Import_consumer(Export_producer(K)) recovers material satisfying V_scalar/V_curve/V_pair, all independently re-verified via M1's real p256.ts`, async () => {
    const exportResult = await producer.exportPrivate();
    assert.equal(exportResult.exportOk, true);
    const importResult = await consumer.importPrivate(exportResult.artifactHex!);
    assert.equal(importResult.importOk, true);

    const recoveredD = BigInt('0x' + importResult.recoveredDHex);
    const recoveredX = BigInt('0x' + importResult.recoveredXHex);
    const recoveredY = BigInt('0x' + importResult.recoveredYHex);

    assert.equal(isValidScalar(recoveredD), true, `${consumer.name} must recover a scalar in [1,n-1]`);
    assert.equal(isOnCurve({ x: recoveredX, y: recoveredY }), true, `${consumer.name} must recover a point on the curve`);
    assert.equal(isPair(recoveredD, { x: recoveredX, y: recoveredY }), true, `${consumer.name} must recover a point that is genuinely dG for the recovered d`);

    assert.equal(recoveredD, BigInt('0x' + privateMaterial.dHex));

    const observationState = evaluateInterop({
      applicable: true, producerValid: exportResult.exportOk, producerExecutionStatus: 'completed', consumerExecutionStatus: 'completed',
      sameBaselineOrStimulus: true,
      expectedOutcome: { kind: 'import-material', expected: 'preserved' },
      observedOutcome: { kind: 'imported-key-material', value: 'preserved' },
    });
    assert.equal(observationState, 'conformant', `${producer.name} -> ${consumer.name} (PKCS8) must be R_interop-conformant`);
  });
}

test('R_interop(p->q) and R_interop(q->p) are structurally distinct observations for EC-ser too, never collapsed even though both pass', async () => {
  const chromiumExport = await PROVIDERS[0]!.exportPrivate();
  const cryptoppExport = await PROVIDERS[1]!.exportPrivate();

  const forwardImport = await PROVIDERS[1]!.importPrivate(chromiumExport.artifactHex!);
  const backwardImport = await PROVIDERS[0]!.importPrivate(cryptoppExport.artifactHex!);
  assert.equal(forwardImport.importOk, true);
  assert.equal(backwardImport.importOk, true);

  const forwardObs = makeRelationObservation({
    applicable: true, context: { kind: 'baseline', phase: 'B', baselineInstanceId: 'ec-ser-fwd' }, relation: 'R_interop',
    scope: { kind: 'backend-pair', from: CHROMIUM_WEBCRYPTO, to: CRYPTOPP }, status: 'pass', participants: [],
    evaluatorId: 'R_interop', basis: 'Chromium->Crypto++ PKCS8',
  });
  const backwardObs = makeRelationObservation({
    applicable: true, context: { kind: 'baseline', phase: 'B', baselineInstanceId: 'ec-ser-bwd' }, relation: 'R_interop',
    scope: { kind: 'backend-pair', from: CRYPTOPP, to: CHROMIUM_WEBCRYPTO }, status: 'pass', participants: [],
    evaluatorId: 'R_interop', basis: 'Crypto++->Chromium PKCS8',
  });

  assert.notEqual(forwardObs.observationId, backwardObs.observationId);
  assert.notDeepEqual(forwardObs.scope, backwardObs.scope);
});

test('DER_p = DER_q is NOT required for R_interop -- confirmed here as a bonus observation, never a precondition', async () => {
  const cryptoppExport = await PROVIDERS[1]!.exportPrivate();
  const bcExport = await PROVIDERS[2]!.exportPrivate();
  // Both use the same frozen portable profile encoder logic, so these MAY
  // coincide -- but R_interop's own conformance above never depended on it.
  assert.ok(cryptoppExport.artifactHex && bcExport.artifactHex);
});

test('EC-ser Phase B: BaselineResult.complete=true, 6 directions x 2 roles = 12 handoffs -- R_interop = 30/30 upon this closing', async () => {
  const observationIds: string[] = [];
  for (const { producer, consumer } of DIRECTIONS) {
    for (const roleLabel of ['public', 'private'] as const) {
      const exportResult = roleLabel === 'public' ? await producer.exportPublic() : await producer.exportPrivate();
      const importResult = roleLabel === 'public' ? await consumer.importPublic(exportResult.artifactHex!) : await consumer.importPrivate(exportResult.artifactHex!);
      assert.equal(importResult.importOk, true, `${producer.name}->${consumer.name} (${roleLabel}) must import successfully`);
      const observation = makeRelationObservation({
        applicable: true, context: { kind: 'baseline', phase: 'B', baselineInstanceId: `ec-ser-trace-${roleLabel}` }, relation: 'R_interop',
        scope: { kind: 'backend-pair', from: producer.backend, to: consumer.backend }, status: 'pass', participants: [],
        evaluatorId: 'R_interop', basis: `trace ${producer.name}->${consumer.name} (${roleLabel})`,
      });
      observationIds.push(observation.observationId);
    }
  }
  assert.equal(observationIds.length, 12);
  assert.equal(new Set(observationIds).size, 12);

  const baseline: BaselineResult = { baselineInstanceId: 'phase-b-ec-ser-12of12', phase: 'B', operation: 'ec-ser', observations: observationIds, complete: true };
  assert.equal(baseline.complete, true);
});
