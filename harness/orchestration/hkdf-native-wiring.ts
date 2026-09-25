// M2.5.2 -- HKDF x Crypto++ / Bouncy Castle real execution adapters,
// invoking the compiled native CLI wrappers (harness/orchestration/
// native-cli/) via subprocess. Both CLIs print the real M1 adapter's own
// JSON EvidenceRecord verbatim -- this file only spawns the process and
// parses that output, never recomputing or approximating the result.

import { spawn } from 'node:child_process';
import { requireBcJar } from './native-cli-env.js';
import { fileURLToPath } from 'node:url';
import path from 'node:path';
import { toHex, type HkdfEvidenceRecord } from '../../src/evidence/record.js';
import type { HkdfRequest } from '../../src/contract/hkdf.js';
import { CRYPTOPP, BOUNCY_CASTLE } from '../schema/backend-identity.js';
import type { ExecutionAdapter } from './engine.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const NATIVE_BUILD_DIR = path.join(__dirname, 'native-build');
const CRYPTOPP_CLI = path.join(NATIVE_BUILD_DIR, 'hkdf-cryptopp-cli');
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

function hkdfArgs(fixture: HkdfRequest): string[] {
  return [
    toHex(fixture.ikm),
    fixture.salt === undefined ? '' : toHex(fixture.salt),
    fixture.salt === undefined ? '0' : '1',
    toHex(fixture.info),
    String(fixture.length),
  ];
}

function toEvidenceFields(record: HkdfEvidenceRecord, backend: typeof CRYPTOPP | typeof BOUNCY_CASTLE) {
  return {
    subject: { backend, direction: 'derive' as const, path: 'sdk' as const },
    input: { kind: 'hkdf-request', value: record.input },
    output: record.outcome.kind === 'accept' ? { kind: 'hkdf-okm', bytes: record.outcome.okmHex } : undefined,
    outcome: record.outcome.kind === 'accept'
      ? { kind: 'accept' }
      : { kind: 'reject', detail: `${record.outcome.errorClass}: ${record.outcome.detail}` },
    clauseIdsEvaluated: record.clauseIds,
    executionStatus: 'completed' as const,
    nativeObservation: undefined,
  };
}

export const HKDF_CRYPTOPP_ADAPTER: ExecutionAdapter<HkdfRequest, HkdfEvidenceRecord> = {
  operation: 'hkdf',
  backend: CRYPTOPP,
  execute: async (fixture) => {
    const stdout = await runCli(CRYPTOPP_CLI, hkdfArgs(fixture));
    return JSON.parse(stdout) as HkdfEvidenceRecord;
  },
  toEvidenceFields: (_fixture, record) => toEvidenceFields(record, CRYPTOPP),
};

export const HKDF_BOUNCYCASTLE_ADAPTER: ExecutionAdapter<HkdfRequest, HkdfEvidenceRecord> = {
  operation: 'hkdf',
  backend: BOUNCY_CASTLE,
  execute: async (fixture) => {
    const stdout = await runCli('java', ['-cp', BC_CLASSPATH, 'HkdfBouncyCastleCli', ...hkdfArgs(fixture)]);
    return JSON.parse(stdout) as HkdfEvidenceRecord;
  },
  toEvidenceFields: (_fixture, record) => toEvidenceFields(record, BOUNCY_CASTLE),
};
