// M2.5.2 -- PSS x Crypto++ / Bouncy Castle real execution adapters, sign
// and verify, invoking the compiled native CLI wrappers via subprocess.

import { parseNativeCliJson } from './native-cli-json.js';
import { spawn } from 'node:child_process';
import { requireBcJar } from './native-cli-env.js';
import { fileURLToPath } from 'node:url';
import path from 'node:path';
import { toHex, type PssSignEvidenceRecord, type PssVerifyEvidenceRecord } from '../../src/evidence/record.js';
import type { PssSignRequest, PssVerifyRequest } from '../../src/contract/pss.js';
import { CRYPTOPP, BOUNCY_CASTLE } from '../schema/backend-identity.js';
import type { ExecutionAdapter } from './engine.js';
import type { OaepKeyHex as PssKeyHex } from './oaep-chromium-wiring.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const NATIVE_BUILD_DIR = path.join(__dirname, 'native-build');
const CRYPTOPP_CLI = path.join(NATIVE_BUILD_DIR, 'pss-cryptopp-cli');
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

// M3-reopen-v5: preserve the portable request descriptors across the
// TypeScript -> native CLI -> Crypto++ boundary. Crypto++ realizes the
// frozen SHA-256 / coupled-MGF1 / sLen=32 profile internally, while
// Accept_C validates the caller-presented descriptors before execution.
function cryptoppSignArgs(key: PssKeyHex, fixture: PssSignRequest): string[] {
  return ['sign', fixture.key.role, key.modulusHex, key.publicExponentHex, key.privateExponentHex ?? '', String(fixture.key.modulusBits), toHex(fixture.message), fixture.hash, fixture.mgfHash, String(fixture.saltLengthBytes)];
}
function cryptoppVerifyArgs(key: PssKeyHex, fixture: PssVerifyRequest): string[] {
  return ['verify', fixture.key.role, key.modulusHex, key.publicExponentHex, '', String(fixture.key.modulusBits), toHex(fixture.message), toHex(fixture.signature), fixture.hash, fixture.mgfHash, String(fixture.saltLengthBytes)];
}
function bcSignArgs(key: PssKeyHex, fixture: PssSignRequest): string[] {
  return ['sign', fixture.key.role, key.modulusHex, key.publicExponentHex, key.privateExponentHex ?? '', String(fixture.key.modulusBits), toHex(fixture.message), fixture.hash, fixture.mgfHash, String(fixture.saltLengthBytes)];
}
function bcVerifyArgs(key: PssKeyHex, fixture: PssVerifyRequest): string[] {
  return ['verify', fixture.key.role, key.modulusHex, key.publicExponentHex, '', String(fixture.key.modulusBits), toHex(fixture.message), toHex(fixture.signature), fixture.hash, fixture.mgfHash, String(fixture.saltLengthBytes)];
}

function signEvidenceFields(record: PssSignEvidenceRecord, backend: typeof CRYPTOPP | typeof BOUNCY_CASTLE) {
  return {
    subject: { backend, direction: 'sign' as const, path: 'sdk' as const },
    input: { kind: 'pss-sign-request', value: record.input },
    output: record.outcome.kind === 'accept' ? { kind: 'pss-signature', bytes: record.outcome.signatureHex } : undefined,
    outcome: record.outcome.kind === 'accept' ? { kind: 'accept' } : { kind: 'reject', detail: `${record.outcome.errorClass}: ${record.outcome.detail}` },
    clauseIdsEvaluated: record.clauseIds, executionStatus: 'completed' as const, nativeObservation: undefined,
  };
}
function verifyEvidenceFields(record: PssVerifyEvidenceRecord, backend: typeof CRYPTOPP | typeof BOUNCY_CASTLE) {
  return {
    subject: { backend, direction: 'verify' as const, path: 'sdk' as const },
    input: { kind: 'pss-verify-request', value: record.input },
    output: record.outcome.kind === 'verified' ? { kind: 'pss-verified', bytes: String(record.outcome.valid) } : undefined,
    outcome: record.outcome.kind === 'verified' ? { kind: 'accept' } : { kind: 'reject', detail: `${record.outcome.errorClass}: ${record.outcome.detail}` },
    clauseIdsEvaluated: record.clauseIds, executionStatus: 'completed' as const, nativeObservation: undefined,
  };
}

export function makePssSignCryptoppAdapter(key: PssKeyHex): ExecutionAdapter<PssSignRequest, PssSignEvidenceRecord> {
  return {
    operation: 'pss', backend: CRYPTOPP,
    execute: async (fixture) => parseNativeCliJson(await runCli(CRYPTOPP_CLI, cryptoppSignArgs(key, fixture))) as PssSignEvidenceRecord,
    toEvidenceFields: (_f, record) => signEvidenceFields(record, CRYPTOPP),
  };
}
export function makePssVerifyCryptoppAdapter(key: PssKeyHex): ExecutionAdapter<PssVerifyRequest, PssVerifyEvidenceRecord> {
  return {
    operation: 'pss', backend: CRYPTOPP,
    execute: async (fixture) => parseNativeCliJson(await runCli(CRYPTOPP_CLI, cryptoppVerifyArgs(key, fixture))) as PssVerifyEvidenceRecord,
    toEvidenceFields: (_f, record) => verifyEvidenceFields(record, CRYPTOPP),
  };
}
export function makePssSignBouncyCastleAdapter(key: PssKeyHex): ExecutionAdapter<PssSignRequest, PssSignEvidenceRecord> {
  return {
    operation: 'pss', backend: BOUNCY_CASTLE,
    execute: async (fixture) => parseNativeCliJson(await runCli('java', ['-cp', BC_CLASSPATH, 'PssBouncyCastleCli', ...bcSignArgs(key, fixture)])) as PssSignEvidenceRecord,
    toEvidenceFields: (_f, record) => signEvidenceFields(record, BOUNCY_CASTLE),
  };
}
export function makePssVerifyBouncyCastleAdapter(key: PssKeyHex): ExecutionAdapter<PssVerifyRequest, PssVerifyEvidenceRecord> {
  return {
    operation: 'pss', backend: BOUNCY_CASTLE,
    execute: async (fixture) => parseNativeCliJson(await runCli('java', ['-cp', BC_CLASSPATH, 'PssBouncyCastleCli', ...bcVerifyArgs(key, fixture)])) as PssVerifyEvidenceRecord,
    toEvidenceFields: (_f, record) => verifyEvidenceFields(record, BOUNCY_CASTLE),
  };
}
