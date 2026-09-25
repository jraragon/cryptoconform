// M2.5.2 -- GCM x Crypto++ / Bouncy Castle real execution adapters,
// encrypt and decrypt, invoking the compiled native CLI wrappers
// (harness/orchestration/native-cli/) via subprocess. Both CLIs print the
// real M1 adapter's own JSON EvidenceRecord verbatim.

import { spawn } from 'node:child_process';
import { requireBcJar } from './native-cli-env.js';
import { fileURLToPath } from 'node:url';
import path from 'node:path';
import { toHex, type GcmEncryptEvidenceRecord, type GcmDecryptEvidenceRecord } from '../../src/evidence/record.js';
import type { GcmEncryptRequest, GcmDecryptRequest } from '../../src/contract/gcm.js';
import { CRYPTOPP, BOUNCY_CASTLE } from '../schema/backend-identity.js';
import type { ExecutionAdapter } from './engine.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const NATIVE_BUILD_DIR = path.join(__dirname, 'native-build');
const CRYPTOPP_CLI = path.join(NATIVE_BUILD_DIR, 'gcm-cryptopp-cli');
const BC_CLASSPATH = `${path.join(NATIVE_BUILD_DIR, 'bc-classes')}:${requireBcJar()}`;

function runCli(command: string, args: readonly string[]): Promise<string> {
  return new Promise((resolve, reject) => {
    const child = spawn(command, args, { stdio: ['ignore', 'pipe', 'pipe'] });
    let stdout = '';
    let stderr = '';
    child.stdout.on('data', (d) => { stdout += d.toString(); });
    child.stderr.on('data', (d) => { stderr += d.toString(); });
    child.on('error', reject);
    child.on('close', (code) => {
      if (code !== 0) reject(new Error(`${command} exited ${code}: ${stderr}`));
      else resolve(stdout.trim());
    });
  });
}

function encryptArgs(fixture: GcmEncryptRequest): string[] {
  return [
    'encrypt', toHex(fixture.key), toHex(fixture.plaintext),
    fixture.aad === undefined ? '' : toHex(fixture.aad), fixture.aad === undefined ? '0' : '1',
    toHex(fixture.iv), String(fixture.tagLengthBits),
  ];
}
function decryptArgs(fixture: GcmDecryptRequest): string[] {
  return ['decrypt', toHex(fixture.key), toHex(fixture.artifact), fixture.aad === undefined ? '' : toHex(fixture.aad), fixture.aad === undefined ? '0' : '1'];
}

function encryptEvidenceFields(record: GcmEncryptEvidenceRecord, backend: typeof CRYPTOPP | typeof BOUNCY_CASTLE) {
  return {
    subject: { backend, direction: 'encrypt' as const, path: 'sdk' as const },
    input: { kind: 'gcm-encrypt-request', value: record.input },
    output: record.outcome.kind === 'accept' ? { kind: 'gcm-artifact', bytes: record.outcome.artifactHex } : undefined,
    outcome: record.outcome.kind === 'accept' ? { kind: 'accept' } : { kind: 'reject', detail: `${record.outcome.errorClass}: ${record.outcome.detail}` },
    clauseIdsEvaluated: record.clauseIds, executionStatus: 'completed' as const, nativeObservation: undefined,
  };
}
function decryptEvidenceFields(record: GcmDecryptEvidenceRecord, backend: typeof CRYPTOPP | typeof BOUNCY_CASTLE) {
  return {
    subject: { backend, direction: 'decrypt' as const, path: 'sdk' as const },
    input: { kind: 'gcm-decrypt-request', value: record.input },
    output: record.outcome.kind === 'accept' ? { kind: 'gcm-plaintext', bytes: record.outcome.plaintextHex } : undefined,
    outcome: record.outcome.kind === 'accept' ? { kind: 'accept' } : { kind: 'reject', detail: `${record.outcome.errorClass}: ${record.outcome.detail}` },
    clauseIdsEvaluated: record.clauseIds, executionStatus: 'completed' as const, nativeObservation: undefined,
  };
}

export const GCM_ENCRYPT_CRYPTOPP_ADAPTER: ExecutionAdapter<GcmEncryptRequest, GcmEncryptEvidenceRecord> = {
  operation: 'gcm', backend: CRYPTOPP,
  execute: async (fixture) => JSON.parse(await runCli(CRYPTOPP_CLI, encryptArgs(fixture))) as GcmEncryptEvidenceRecord,
  toEvidenceFields: (_f, record) => encryptEvidenceFields(record, CRYPTOPP),
};
export const GCM_DECRYPT_CRYPTOPP_ADAPTER: ExecutionAdapter<GcmDecryptRequest, GcmDecryptEvidenceRecord> = {
  operation: 'gcm', backend: CRYPTOPP,
  execute: async (fixture) => JSON.parse(await runCli(CRYPTOPP_CLI, decryptArgs(fixture))) as GcmDecryptEvidenceRecord,
  toEvidenceFields: (_f, record) => decryptEvidenceFields(record, CRYPTOPP),
};
export const GCM_ENCRYPT_BOUNCYCASTLE_ADAPTER: ExecutionAdapter<GcmEncryptRequest, GcmEncryptEvidenceRecord> = {
  operation: 'gcm', backend: BOUNCY_CASTLE,
  execute: async (fixture) => JSON.parse(await runCli('java', ['-cp', BC_CLASSPATH, 'GcmBouncyCastleCli', ...encryptArgs(fixture)])) as GcmEncryptEvidenceRecord,
  toEvidenceFields: (_f, record) => encryptEvidenceFields(record, BOUNCY_CASTLE),
};
export const GCM_DECRYPT_BOUNCYCASTLE_ADAPTER: ExecutionAdapter<GcmDecryptRequest, GcmDecryptEvidenceRecord> = {
  operation: 'gcm', backend: BOUNCY_CASTLE,
  execute: async (fixture) => JSON.parse(await runCli('java', ['-cp', BC_CLASSPATH, 'GcmBouncyCastleCli', ...decryptArgs(fixture)])) as GcmDecryptEvidenceRecord,
  toEvidenceFields: (_f, record) => decryptEvidenceFields(record, BOUNCY_CASTLE),
};
