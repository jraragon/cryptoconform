import { test, after } from 'node:test';
import assert from 'node:assert/strict';
import { generateKeyPairSync } from 'node:crypto';

import { rsaSerRoundtripChromium, type RsaKeyHexMaterial } from '../../../harness/orchestration/rsa-ser-chromium-wiring.js';
import { rsaSerRoundtripCryptopp, rsaSerRoundtripBouncyCastle } from '../../../harness/orchestration/rsa-ser-native-wiring.js';
import { closeSharedChromium } from '../../../harness/orchestration/chromium-page.js';
import { makeRelationObservation } from '../../../harness/evidence/relation-observation.js';
import type { BaselineResult } from '../../../harness/evidence/baseline-result.js';
import { CHROMIUM_WEBCRYPTO, CRYPTOPP, BOUNCY_CASTLE } from '../../../harness/schema/backend-identity.js';

after(async () => {
  await closeSharedChromium();
});

// ONE real RSA-3072 key pair, generated once via Node's own crypto,
// shared across all three backends' Phase A round-trip checks.
let privateMaterial: RsaKeyHexMaterial;
let publicMaterial: RsaKeyHexMaterial;

function b64uToHex(b64u: string): string {
  return Buffer.from(b64u, 'base64url').toString('hex');
}

test('setup: generate ONE real RSA-3072 key pair via Node crypto, shared across all three backends', () => {
  const { privateKey } = generateKeyPairSync('rsa', { modulusLength: 3072 });
  const jwk = privateKey.export({ format: 'jwk' }) as { n: string; e: string; d: string; p: string; q: string; dp: string; dq: string; qi: string };
  privateMaterial = {
    role: 'private', nHex: b64uToHex(jwk.n), eHex: b64uToHex(jwk.e), dHex: b64uToHex(jwk.d),
    pHex: b64uToHex(jwk.p), qHex: b64uToHex(jwk.q), dpHex: b64uToHex(jwk.dp), dqHex: b64uToHex(jwk.dq), qiHex: b64uToHex(jwk.qi),
  };
  publicMaterial = { role: 'public', nHex: privateMaterial.nHex, eHex: privateMaterial.eHex };
  assert.equal(privateMaterial.nHex.length, 768);
});

// ---------------------------------------------------------------------
// Private-role round-trip: Export_p(K) -> A_p, Import_p(A_p) -> K'_p, K'_p===K
// ---------------------------------------------------------------------

test('Phase A, RSA-ser x Chromium (private): real native SPKI/PKCS8 round-trip preserves material', async () => {
  const result = await rsaSerRoundtripChromium(privateMaterial);
  assert.equal(result.exportOk, true);
  assert.equal(result.importOk, true);
  assert.equal(result.materialPreserved, true);
  assert.equal(result.backend.sourcePin, CHROMIUM_WEBCRYPTO.sourcePin);
});

test('Phase A, RSA-ser x Crypto++ (private): real Export->Import round-trip preserves material', async () => {
  const result = await rsaSerRoundtripCryptopp(privateMaterial);
  assert.equal(result.exportOk, true);
  assert.equal(result.importOk, true);
  assert.equal(result.materialPreserved, true);
  assert.equal(result.backend.sourcePin, CRYPTOPP.sourcePin);
});

test('Phase A, RSA-ser x Bouncy Castle (private): real Export->Import round-trip preserves material', async () => {
  const result = await rsaSerRoundtripBouncyCastle(privateMaterial);
  assert.equal(result.exportOk, true);
  assert.equal(result.importOk, true);
  assert.equal(result.materialPreserved, true);
  assert.equal(result.backend.sourcePin, BOUNCY_CASTLE.sourcePin);
});

// ---------------------------------------------------------------------
// Public-role round-trip
// ---------------------------------------------------------------------

test('Phase A, RSA-ser public role: all three backends preserve public material through their own real round-trip', async () => {
  const chromium = await rsaSerRoundtripChromium(publicMaterial);
  const cryptopp = await rsaSerRoundtripCryptopp(publicMaterial);
  const bc = await rsaSerRoundtripBouncyCastle(publicMaterial);
  for (const r of [chromium, cryptopp, bc]) {
    assert.equal(r.exportOk, true);
    assert.equal(r.importOk, true);
    assert.equal(r.materialPreserved, true);
  }
});

test('SDK/canonical representation vs native representation: artifacts across backends are NOT required to be byte-identical in Phase A -- that comparison is R_byte/Phase B territory, not a Phase A failure', async () => {
  const cryptopp = await rsaSerRoundtripCryptopp(publicMaterial);
  const bc = await rsaSerRoundtripBouncyCastle(publicMaterial);
  // Deliberately no assertion that artifactHex matches across backends --
  // Phase A only requires each backend's OWN round-trip to preserve
  // material, never cross-backend byte equality.
  assert.ok(cryptopp.artifactHex && bc.artifactHex, 'both backends must have produced SOME artifact');
});

test('RSA-ser Phase A: BaselineResult.complete=true, 3/3 cells -- built from real material-preservation success, never artifact byte-equality', async () => {
  const chromium = await rsaSerRoundtripChromium(privateMaterial);
  const cryptopp = await rsaSerRoundtripCryptopp(privateMaterial);
  const bc = await rsaSerRoundtripBouncyCastle(privateMaterial);
  assert.ok([chromium, cryptopp, bc].every((r) => r.materialPreserved === true));

  const backends = [CHROMIUM_WEBCRYPTO, CRYPTOPP, BOUNCY_CASTLE];
  const observations = backends.map((backend) =>
    makeRelationObservation({
      applicable: true, context: { kind: 'baseline', phase: 'A', baselineInstanceId: 'rsa-ser-all' }, relation: 'R_ser',
      scope: { kind: 'single-backend', backend }, status: 'pass', participants: [],
      evaluatorId: 'R_ser', basis: 'RSA-ser Phase A local Export->Import material preservation, real execution',
    }),
  );
  const baseline: BaselineResult = { baselineInstanceId: 'phase-a-rsa-ser-3of3', phase: 'A', operation: 'rsa-ser', observations: observations.map((o) => o.observationId), complete: true };
  assert.equal(baseline.complete, true);
  assert.equal(baseline.observations.length, 3);
});
