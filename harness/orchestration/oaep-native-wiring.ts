// M2.5.2 -- OAEP x Crypto++ / Bouncy Castle real execution adapters,
// encrypt and decrypt, invoking the compiled native CLI wrappers via
// subprocess. Both CLIs print the real M1 adapter's own JSON
// EvidenceRecord verbatim.

import { parseNativeCliJson } from './native-cli-json.js';
import { spawn } from 'node:child_process';
import { requireBcJar } from './native-cli-env.js';
import { fileURLToPath } from 'node:url';
import path from 'node:path';
import { toHex, type OaepEncryptEvidenceRecord, type OaepDecryptEvidenceRecord } from '../../src/evidence/record.js';
import type { OaepEncryptRequest, OaepDecryptRequest } from '../../src/contract/oaep.js';
import { CRYPTOPP, BOUNCY_CASTLE } from '../schema/backend-identity.js';
import type { ExecutionAdapter } from './engine.js';
import type { OaepKeyHex } from './oaep-chromium-wiring.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const NATIVE_BUILD_DIR = path.join(__dirname, 'native-build');
const CRYPTOPP_CLI = path.join(NATIVE_BUILD_DIR, 'oaep-cryptopp-cli');
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

function encryptArgs(key: OaepKeyHex, fixture: OaepEncryptRequest): string[] {
  return [
    'encrypt', fixture.key.role, key.modulusHex, key.publicExponentHex, '', String(fixture.key.modulusBits),
    toHex(fixture.plaintext), fixture.label === undefined ? '' : toHex(fixture.label), fixture.label === undefined ? '0' : '1',
    fixture.hash, fixture.mgfHash,
  ];
}
function decryptArgs(key: OaepKeyHex, fixture: OaepDecryptRequest): string[] {
  return [
    'decrypt', fixture.key.role, key.modulusHex, key.publicExponentHex, key.privateExponentHex ?? '', String(fixture.key.modulusBits),
    toHex(fixture.ciphertext), fixture.label === undefined ? '' : toHex(fixture.label), fixture.label === undefined ? '0' : '1',
    fixture.hash, fixture.mgfHash,
  ];
}

function encryptEvidenceFields(record: OaepEncryptEvidenceRecord, backend: typeof CRYPTOPP | typeof BOUNCY_CASTLE) {
  return {
    subject: { backend, direction: 'encrypt' as const, path: 'sdk' as const },
    input: { kind: 'oaep-encrypt-request', value: record.input },
    output: record.outcome.kind === 'accept' ? { kind: 'oaep-ciphertext', bytes: record.outcome.ciphertextHex } : undefined,
    outcome: record.outcome.kind === 'accept' ? { kind: 'accept' } : { kind: 'reject', detail: `${record.outcome.errorClass}: ${record.outcome.detail}` },
    clauseIdsEvaluated: record.clauseIds, executionStatus: 'completed' as const, nativeObservation: undefined,
  };
}
function decryptEvidenceFields(record: OaepDecryptEvidenceRecord, backend: typeof CRYPTOPP | typeof BOUNCY_CASTLE) {
  return {
    subject: { backend, direction: 'decrypt' as const, path: 'sdk' as const },
    input: { kind: 'oaep-decrypt-request', value: record.input },
    output: record.outcome.kind === 'accept' ? { kind: 'oaep-plaintext', bytes: record.outcome.plaintextHex } : undefined,
    outcome: record.outcome.kind === 'accept' ? { kind: 'accept' } : { kind: 'reject', detail: `${record.outcome.errorClass}: ${record.outcome.detail}` },
    clauseIdsEvaluated: record.clauseIds, executionStatus: 'completed' as const, nativeObservation: undefined,
  };
}

export function makeOaepEncryptCryptoppAdapter(key: OaepKeyHex): ExecutionAdapter<OaepEncryptRequest, OaepEncryptEvidenceRecord> {
  return {
    operation: 'oaep', backend: CRYPTOPP,
    execute: async (fixture) => parseNativeCliJson(await runCli(CRYPTOPP_CLI, encryptArgs(key, fixture))) as OaepEncryptEvidenceRecord,
    toEvidenceFields: (_f, record) => encryptEvidenceFields(record, CRYPTOPP),
  };
}
export function makeOaepDecryptCryptoppAdapter(key: OaepKeyHex): ExecutionAdapter<OaepDecryptRequest, OaepDecryptEvidenceRecord> {
  return {
    operation: 'oaep', backend: CRYPTOPP,
    execute: async (fixture) => parseNativeCliJson(await runCli(CRYPTOPP_CLI, decryptArgs(key, fixture))) as OaepDecryptEvidenceRecord,
    toEvidenceFields: (_f, record) => decryptEvidenceFields(record, CRYPTOPP),
  };
}
export function makeOaepEncryptBouncyCastleAdapter(key: OaepKeyHex): ExecutionAdapter<OaepEncryptRequest, OaepEncryptEvidenceRecord> {
  return {
    operation: 'oaep', backend: BOUNCY_CASTLE,
    execute: async (fixture) => parseNativeCliJson(await runCli('java', ['-cp', BC_CLASSPATH, 'OaepBouncyCastleCli', ...encryptArgs(key, fixture)])) as OaepEncryptEvidenceRecord,
    toEvidenceFields: (_f, record) => encryptEvidenceFields(record, BOUNCY_CASTLE),
  };
}
export function makeOaepDecryptBouncyCastleAdapter(key: OaepKeyHex): ExecutionAdapter<OaepDecryptRequest, OaepDecryptEvidenceRecord> {
  return {
    operation: 'oaep', backend: BOUNCY_CASTLE,
    execute: async (fixture) => parseNativeCliJson(await runCli('java', ['-cp', BC_CLASSPATH, 'OaepBouncyCastleCli', ...decryptArgs(key, fixture)])) as OaepDecryptEvidenceRecord,
    toEvidenceFields: (_f, record) => decryptEvidenceFields(record, BOUNCY_CASTLE),
  };
}
