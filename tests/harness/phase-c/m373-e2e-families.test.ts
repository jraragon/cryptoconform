// M3.7.3 -- end-to-end transfer, five families, real backends.
//
// Producer executes, emits a real artifact, the consumer on a DIFFERENT
// backend consumes exactly those bytes, and the transfer record carries both
// execution identities. No mocks: if a family cannot really round-trip
// cross-provider, this fails.

import { test, after } from 'node:test';
import { readFileSync } from 'node:fs';
import assert from 'node:assert/strict';

import { loadFrozenMaterialPool } from '../../../harness/phase-c/material/load.js';
import { bindMaterial } from '../../../harness/phase-c/execution-binding.js';
import {
  realizeEcSerMaterial, realizeRsaKeyHex, realizeRsaSerMaterial, RealizationError,
} from '../../../harness/phase-c/wiring-realization.js';
import { assembleConsumerInput } from '../../../harness/phase-c/consumer-input.js';
import { runTransfer } from '../../../harness/orchestration/interop-transfer.js';
import { executeBaseline } from '../../../harness/orchestration/engine.js';
import { wrapSerializationExecution } from '../../../harness/evidence/serialization-execution.js';
import { GCM_ENCRYPT_CRYPTOPP_ADAPTER, GCM_DECRYPT_BOUNCYCASTLE_ADAPTER } from '../../../harness/orchestration/gcm-native-wiring.js';
import { makeOaepEncryptCryptoppAdapter, makeOaepDecryptBouncyCastleAdapter } from '../../../harness/orchestration/oaep-native-wiring.js';
import { makePssSignCryptoppAdapter, makePssVerifyBouncyCastleAdapter } from '../../../harness/orchestration/pss-native-wiring.js';
import { rsaSerExportCryptopp, rsaSerImportBouncyCastle } from '../../../harness/orchestration/rsa-ser-native-wiring.js';
import { ecSerExportCryptopp, ecSerImportBouncyCastle } from '../../../harness/orchestration/ec-ser-native-wiring.js';
import { BOUNCY_CASTLE, CRYPTOPP } from '../../../harness/schema/backend-identity.js';
import type { ExecutionEvidence } from '../../../harness/evidence/execution-evidence.js';

const pool = loadFrozenMaterialPool();
const rsaKey = realizeRsaKeyHex(bindMaterial('oaep', pool)!);
const executions: ExecutionEvidence[] = [];
const record = (e: ExecutionEvidence) => { executions.push(e); return e; };
const bytesOf = (e: ExecutionEvidence) => (e.output as { bytes: string }).bytes;

after(() => { executions.length = 0; });

/** Asserts the property the whole transfer design exists to guarantee. */
function assertReconstructible(producerId: string, consumerId: string): void {
  const ids = executions.map((e) => e.executionId);
  assert.ok(ids.includes(producerId), 'the producer execution must be in executions[]');
  assert.ok(ids.includes(consumerId), 'the consumer execution must be in executions[]');
  assert.notEqual(producerId, consumerId);
}

test('E2E GCM: Crypto++ encrypts, Bouncy Castle decrypts the SAME artifact', async () => {
  const req = {
    key: Buffer.alloc(32, 7), iv: Buffer.alloc(12, 3),
    plaintext: Buffer.from('deadbeefdeadbeef', 'hex'), aad: Buffer.from('a1a2', 'hex'), tagLengthBits: 128,
  };
  const t = await runTransfer({
    operation: 'gcm', from: CRYPTOPP, to: BOUNCY_CASTLE,
    produce: async () => {
      const e = record(await executeBaseline('B', 'e2e-gcm-enc', req as never, GCM_ENCRYPT_CRYPTOPP_ADAPTER as never));
      return { bytesHex: bytesOf(e), execution: e };
    },
    consume: async (a) => {
      const input = assembleConsumerInput({ operation: 'gcm', producerFixture: req, artifactHex: a.bytesHex }).input;
      return record(await executeBaseline('B', 'e2e-gcm-dec', input as never, GCM_DECRYPT_BOUNCYCASTLE_ADAPTER as never));
    },
  });
  assert.equal(t.consumerExecution.executionStatus, 'completed');
  assert.equal(bytesOf(t.consumerExecution), req.plaintext.toString('hex'), 'the plaintext must round-trip');
  assertReconstructible(t.producerExecution.executionId, t.consumerExecution.executionId);
});

test('E2E OAEP: factories realized from the FROZEN RSA key, Crypto++ -> Bouncy Castle', async () => {
  const enc = makeOaepEncryptCryptoppAdapter(rsaKey);
  const dec = makeOaepDecryptBouncyCastleAdapter(rsaKey);
  const req = {
    key: { role: 'public' as const, modulusBits: 3072 },
    plaintext: Buffer.from('00112233445566778899aabbccddeeff', 'hex'),
    label: undefined, hash: 'SHA-256' as const, mgfHash: 'SHA-256' as const,
  };
  const t = await runTransfer({
    operation: 'oaep', from: CRYPTOPP, to: BOUNCY_CASTLE,
    produce: async () => {
      const e = record(await executeBaseline('B', 'e2e-oaep-enc', req as never, enc as never));
      return { bytesHex: bytesOf(e), execution: e };
    },
    consume: async (a) => {
      const input = assembleConsumerInput({ operation: 'oaep', producerFixture: req, artifactHex: a.bytesHex }).input;
      return record(await executeBaseline('B', 'e2e-oaep-dec', input as never, dec as never));
    },
  });
  assert.equal(bytesOf(t.consumerExecution), req.plaintext.toString('hex'));
  assertReconstructible(t.producerExecution.executionId, t.consumerExecution.executionId);
});

test('E2E PSS: Crypto++ signs with the frozen key, Bouncy Castle verifies', async () => {
  const sign = makePssSignCryptoppAdapter(rsaKey as never);
  const verify = makePssVerifyBouncyCastleAdapter(rsaKey as never);
  const req = {
    key: { role: 'private' as const, modulusBits: 3072 },
    message: Buffer.from('4d33373320505353', 'hex'),
    hash: 'SHA-256' as const, mgfHash: 'SHA-256' as const, saltLengthBytes: 32,
  };
  const t = await runTransfer({
    operation: 'pss', from: CRYPTOPP, to: BOUNCY_CASTLE,
    produce: async () => {
      const e = record(await executeBaseline('B', 'e2e-pss-sign', req as never, sign as never));
      return { bytesHex: bytesOf(e), execution: e };
    },
    consume: async (a) => {
      const input = assembleConsumerInput({ operation: 'pss', producerFixture: req, artifactHex: a.bytesHex }).input;
      return record(await executeBaseline('B', 'e2e-pss-verify', input as never, verify as never));
    },
  });
  assert.equal(t.consumerExecution.outcome.kind, 'accept', 'a real cross-provider PSS signature must verify');
  assertReconstructible(t.producerExecution.executionId, t.consumerExecution.executionId);
});

test('E2E RSA serialization: Crypto++ exports the frozen key, Bouncy Castle imports it', async () => {
  const material = realizeRsaSerMaterial(bindMaterial('rsa-ser', pool)!, 'private');
  const t = await runTransfer({
    operation: 'rsa-ser', from: CRYPTOPP, to: BOUNCY_CASTLE,
    produce: async () => {
      const r = await rsaSerExportCryptopp(material);
      assert.equal(r.exportOk, true, 'Crypto++ must really export the frozen key');
      const e = record(wrapSerializationExecution({
        operation: 'rsa-ser', backend: CRYPTOPP, direction: 'export',
        mutationId: 'E2E', stimulusInstanceId: 'default', inputKind: 'rsa-private-material',
        result: { ok: true, artifactHex: r.artifactHex! },
      }));
      return { bytesHex: r.artifactHex!, execution: e };
    },
    consume: async (a) => {
      const input = assembleConsumerInput({ operation: 'rsa-ser', producerFixture: material, artifactHex: a.bytesHex })
        .input as { artifactHex: string; requestedRole: 'private' };
      const r = await rsaSerImportBouncyCastle(input.requestedRole, input.artifactHex, material);
      assert.equal(r.importOk, true, 'Bouncy Castle must really import it');
      assert.equal(r.materialPreserved, true, 'and the material must survive the round trip');
      return record(wrapSerializationExecution({
        operation: 'rsa-ser', backend: BOUNCY_CASTLE, direction: 'import',
        mutationId: 'E2E', stimulusInstanceId: 'default', inputKind: 'pkcs8-artifact',
        result: { ok: true, extra: { materialPreserved: r.materialPreserved } },
      }));
    },
  });
  assertReconstructible(t.producerExecution.executionId, t.consumerExecution.executionId);
});

test('E2E EC serialization: Crypto++ exports the frozen P-256 key, Bouncy Castle imports it', async () => {
  const material = realizeEcSerMaterial(bindMaterial('ec-ser', pool)!, 'private');
  const t = await runTransfer({
    operation: 'ec-ser', from: CRYPTOPP, to: BOUNCY_CASTLE,
    produce: async () => {
      const r = await ecSerExportCryptopp(material);
      assert.equal(r.exportOk, true, 'Crypto++ must really export the frozen EC key');
      const e = record(wrapSerializationExecution({
        operation: 'ec-ser', backend: CRYPTOPP, direction: 'export',
        mutationId: 'E2E', stimulusInstanceId: 'default', inputKind: 'ec-private-material',
        result: { ok: true, artifactHex: r.artifactHex! },
      }));
      return { bytesHex: r.artifactHex!, execution: e };
    },
    consume: async (a) => {
      const input = assembleConsumerInput({ operation: 'ec-ser', producerFixture: material, artifactHex: a.bytesHex })
        .input as { artifactHex: string; requestedRole: 'private' };
      const r = await ecSerImportBouncyCastle(input.requestedRole, input.artifactHex);
      assert.equal(r.importOk, true, 'Bouncy Castle must really import it');
      return record(wrapSerializationExecution({
        operation: 'ec-ser', backend: BOUNCY_CASTLE, direction: 'import',
        mutationId: 'E2E', stimulusInstanceId: 'default', inputKind: 'pkcs8-artifact',
        result: { ok: true, extra: { recoveredXHex: r.recoveredXHex } },
      }));
    },
  });
  assertReconstructible(t.producerExecution.executionId, t.consumerExecution.executionId);
});

// =====================================================================
// The realization is conversion, never fabrication
// =====================================================================

test('M3.7.3: realization reads the frozen record BY NAME and refuses to fabricate', () => {
  assert.equal(rsaKey.modulusHex.length * 4, 3072, 'the modulus is the frozen one, at its frozen width');
  assert.equal(rsaKey.publicExponentHex, '010001');
  // A record missing a component is refused, not completed.
  assert.throws(
    () => realizeRsaKeyHex({ materialId: 'x', materialType: 'rsa-3072-keypair', value: { n: new Uint8Array([1]) } as never }),
    RealizationError,
  );
  assert.throws(
    () => realizeRsaKeyHex({ materialId: 'x', materialType: 'rsa-3072-keypair', value: { n: new Uint8Array([1]) } as never }),
    /Refusing to fabricate it/,
  );
  // And a record of the wrong type is refused before anything is read.
  assert.throws(
    () => realizeEcSerMaterial(bindMaterial('rsa-ser', pool)!, 'private'),
    /Expected an ec-p256-keypair/,
  );
});

test('M3.7.3: realization selects nothing -- it converts what the binding chose', () => {
  const src = readFileSync(new URL('../../../harness/phase-c/wiring-realization.ts', import.meta.url), 'utf8');
  const imports = src.split('\n').filter((l) => l.trimStart().startsWith('import'));
  for (const line of imports) {
    assert.ok(!line.includes('dispatch'), 'the dispatch remains the authority; this only converts');
    assert.ok(!line.includes('material/load'), 'it never looks material up itself');
  }
  assert.ok(!src.includes('generateKey') && !src.includes('randomBytes'));
});
