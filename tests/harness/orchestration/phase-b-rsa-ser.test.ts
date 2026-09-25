import { test, after } from 'node:test';
import assert from 'node:assert/strict';
import { generateKeyPairSync } from 'node:crypto';

import { rsaSerExportChromium, rsaSerImportChromium, type RsaKeyHexMaterial } from '../../../harness/orchestration/rsa-ser-chromium-wiring.js';
import { rsaSerExportCryptopp, rsaSerImportCryptopp, rsaSerExportBouncyCastle, rsaSerImportBouncyCastle } from '../../../harness/orchestration/rsa-ser-native-wiring.js';
import { closeSharedChromium } from '../../../harness/orchestration/chromium-page.js';
import { evaluateInterop } from '../../../harness/evaluators/r-interop.js';
import { makeRelationObservation } from '../../../harness/evidence/relation-observation.js';
import type { BaselineResult } from '../../../harness/evidence/baseline-result.js';
import { CHROMIUM_WEBCRYPTO, CRYPTOPP, BOUNCY_CASTLE } from '../../../harness/schema/backend-identity.js';

after(async () => {
  await closeSharedChromium();
});

let privateMaterial: RsaKeyHexMaterial;
let publicMaterial: RsaKeyHexMaterial;

function b64uToHex(b64u: string): string {
  return Buffer.from(b64u, 'base64url').toString('hex');
}

test('setup: ONE real RSA-3072 key pair, shared by every exporter and importer in this file', () => {
  const { privateKey } = generateKeyPairSync('rsa', { modulusLength: 3072 });
  const jwk = privateKey.export({ format: 'jwk' }) as { n: string; e: string; d: string; p: string; q: string; dp: string; dq: string; qi: string };
  privateMaterial = {
    role: 'private', nHex: b64uToHex(jwk.n), eHex: b64uToHex(jwk.e), dHex: b64uToHex(jwk.d),
    pHex: b64uToHex(jwk.p), qHex: b64uToHex(jwk.q), dpHex: b64uToHex(jwk.dp), dqHex: b64uToHex(jwk.dq), qiHex: b64uToHex(jwk.qi),
  };
  publicMaterial = { role: 'public', nHex: privateMaterial.nHex, eHex: privateMaterial.eHex };
});

const PROVIDERS = [
  {
    name: 'Chromium', backend: CHROMIUM_WEBCRYPTO,
    exportPublic: () => rsaSerExportChromium(publicMaterial), exportPrivate: () => rsaSerExportChromium(privateMaterial),
    importPublic: (artifactHex: string) => rsaSerImportChromium('public', artifactHex, publicMaterial),
    importPrivate: (artifactHex: string) => rsaSerImportChromium('private', artifactHex, privateMaterial),
  },
  {
    name: 'Crypto++', backend: CRYPTOPP,
    exportPublic: () => rsaSerExportCryptopp(publicMaterial), exportPrivate: () => rsaSerExportCryptopp(privateMaterial),
    importPublic: (artifactHex: string) => rsaSerImportCryptopp('public', artifactHex, publicMaterial),
    importPrivate: (artifactHex: string) => rsaSerImportCryptopp('private', artifactHex, privateMaterial),
  },
  {
    name: 'Bouncy Castle', backend: BOUNCY_CASTLE,
    exportPublic: () => rsaSerExportBouncyCastle(publicMaterial), exportPrivate: () => rsaSerExportBouncyCastle(privateMaterial),
    importPublic: (artifactHex: string) => rsaSerImportBouncyCastle('public', artifactHex, publicMaterial),
    importPrivate: (artifactHex: string) => rsaSerImportBouncyCastle('private', artifactHex, privateMaterial),
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
// SPKI (public role): 6 directions
// ---------------------------------------------------------------------

for (const { producer, consumer } of DIRECTIONS) {
  test(`RSA-ser Phase B, SPKI, R_interop(${producer.name} -> ${consumer.name}): Import_consumer(Export_producer(K^public)) preserves material -- artifact handed LITERALLY, never re-encoded`, async () => {
    const exportResult = await producer.exportPublic();
    assert.equal(exportResult.exportOk, true);
    const importResult = await consumer.importPublic(exportResult.artifactHex!);
    assert.equal(importResult.importOk, true);
    assert.equal(importResult.materialPreserved, true);

    const observationState = evaluateInterop({
      applicable: true, producerValid: exportResult.exportOk, producerExecutionStatus: 'completed', consumerExecutionStatus: 'completed',
      sameBaselineOrStimulus: true,
      expectedOutcome: { kind: 'import-material', expected: 'preserved' },
      observedOutcome: importResult.importOk ? { kind: 'imported-key-material', value: importResult.materialPreserved ? 'preserved' : 'diverged' } : { kind: 'rejection', value: undefined },
    });
    assert.equal(observationState, 'conformant', `${producer.name} -> ${consumer.name} (SPKI) must be R_interop-conformant`);
  });
}

// ---------------------------------------------------------------------
// PKCS8 (private role): 6 directions -- exercises qInv and CRT invariants
// the public path cannot
// ---------------------------------------------------------------------

for (const { producer, consumer } of DIRECTIONS) {
  test(`RSA-ser Phase B, PKCS8, R_interop(${producer.name} -> ${consumer.name}): Import_consumer(Export_producer(K^private)) preserves material -- exercises qInv/CRT invariants the public path cannot`, async () => {
    const exportResult = await producer.exportPrivate();
    assert.equal(exportResult.exportOk, true);
    const importResult = await consumer.importPrivate(exportResult.artifactHex!);
    assert.equal(importResult.importOk, true);
    assert.equal(importResult.materialPreserved, true);

    const observationState = evaluateInterop({
      applicable: true, producerValid: exportResult.exportOk, producerExecutionStatus: 'completed', consumerExecutionStatus: 'completed',
      sameBaselineOrStimulus: true,
      expectedOutcome: { kind: 'import-material', expected: 'preserved' },
      observedOutcome: importResult.importOk ? { kind: 'imported-key-material', value: importResult.materialPreserved ? 'preserved' : 'diverged' } : { kind: 'rejection', value: undefined },
    });
    assert.equal(observationState, 'conformant', `${producer.name} -> ${consumer.name} (PKCS8) must be R_interop-conformant`);
  });
}

test('R_interop(p->q) and R_interop(q->p) are structurally distinct observations for RSA-ser too, never collapsed even though both pass', async () => {
  const chromiumExport = await PROVIDERS[0]!.exportPrivate();
  const cryptoppExport = await PROVIDERS[1]!.exportPrivate();

  const forwardImport = await PROVIDERS[1]!.importPrivate(chromiumExport.artifactHex!);
  const backwardImport = await PROVIDERS[0]!.importPrivate(cryptoppExport.artifactHex!);
  assert.equal(forwardImport.materialPreserved, true);
  assert.equal(backwardImport.materialPreserved, true);

  const forwardObs = makeRelationObservation({
    applicable: true, context: { kind: 'baseline', phase: 'B', baselineInstanceId: 'rsa-ser-fwd' }, relation: 'R_interop',
    scope: { kind: 'backend-pair', from: CHROMIUM_WEBCRYPTO, to: CRYPTOPP }, status: 'pass', participants: [],
    evaluatorId: 'R_interop', basis: 'Chromium->Crypto++ PKCS8',
  });
  const backwardObs = makeRelationObservation({
    applicable: true, context: { kind: 'baseline', phase: 'B', baselineInstanceId: 'rsa-ser-bwd' }, relation: 'R_interop',
    scope: { kind: 'backend-pair', from: CRYPTOPP, to: CHROMIUM_WEBCRYPTO }, status: 'pass', participants: [],
    evaluatorId: 'R_interop', basis: 'Crypto++->Chromium PKCS8',
  });

  assert.notEqual(forwardObs.observationId, backwardObs.observationId);
  assert.notDeepEqual(forwardObs.scope, backwardObs.scope);
});

test('R_interop=pass does not require DER byte-equality across producers -- representational differences are R_byte/R_ser territory, never an R_interop precondition', async () => {
  const chromiumExport = await PROVIDERS[0]!.exportPrivate();
  const cryptoppExport = await PROVIDERS[1]!.exportPrivate();
  // Deliberately no assertion of artifact equality -- these MAY differ
  // (Chromium's own native PKCS8 writer vs Crypto++'s canonical portable
  // DER writer are architecturally independent) while both still being
  // importable everywhere, which is what was just confirmed above.
  assert.ok(chromiumExport.artifactHex && cryptoppExport.artifactHex);
});

test('RSA-ser Phase B: BaselineResult.complete=true, 6 directions x 2 roles = 12 handoffs -- full traceability', async () => {
  const observationIds: string[] = [];
  for (const { producer, consumer } of DIRECTIONS) {
    for (const roleLabel of ['public', 'private'] as const) {
      const exportResult = roleLabel === 'public' ? await producer.exportPublic() : await producer.exportPrivate();
      const importResult = roleLabel === 'public' ? await consumer.importPublic(exportResult.artifactHex!) : await consumer.importPrivate(exportResult.artifactHex!);
      assert.equal(importResult.materialPreserved, true, `${producer.name}->${consumer.name} (${roleLabel}) must preserve material`);
      const observation = makeRelationObservation({
        applicable: true, context: { kind: 'baseline', phase: 'B', baselineInstanceId: `rsa-ser-trace-${roleLabel}` }, relation: 'R_interop',
        scope: { kind: 'backend-pair', from: producer.backend, to: consumer.backend }, status: 'pass', participants: [],
        evaluatorId: 'R_interop', basis: `trace ${producer.name}->${consumer.name} (${roleLabel})`,
      });
      observationIds.push(observation.observationId);
    }
  }
  assert.equal(observationIds.length, 12);
  assert.equal(new Set(observationIds).size, 12);

  const baseline: BaselineResult = { baselineInstanceId: 'phase-b-rsa-ser-12of12', phase: 'B', operation: 'rsa-ser', observations: observationIds, complete: true };
  assert.equal(baseline.complete, true);
});
