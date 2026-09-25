// M2.5.2 -- RSA-ser x Crypto++ / Bouncy Castle real round-trip wiring,
// invoking the compiled native CLI wrappers via subprocess. Both CLIs
// build their own JSON (no EvidenceRecord wrapper exists in M1 for this
// operation) around the real Export->Import round trip.

import { spawn } from 'node:child_process';
import { requireBcJar } from './native-cli-env.js';
import { fileURLToPath } from 'node:url';
import path from 'node:path';
import { CRYPTOPP, BOUNCY_CASTLE } from '../schema/backend-identity.js';
import type { RsaKeyHexMaterial } from './rsa-ser-chromium-wiring.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const NATIVE_BUILD_DIR = path.join(__dirname, 'native-build');
const CRYPTOPP_CLI = path.join(NATIVE_BUILD_DIR, 'rsa-ser-cryptopp-cli');
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

function roundtripArgs(material: RsaKeyHexMaterial): string[] {
  return [
    'roundtrip', material.role, material.nHex, material.eHex,
    material.dHex ?? '', material.pHex ?? '', material.qHex ?? '',
    material.dpHex ?? '', material.dqHex ?? '', material.qiHex ?? '',
  ];
}

export interface RsaSerRoundtripResult {
  readonly backend: typeof CRYPTOPP | typeof BOUNCY_CASTLE;
  readonly exportOk: boolean;
  readonly artifactHex?: string;
  readonly importOk?: boolean;
  readonly materialPreserved?: boolean;
  readonly errorClass?: string;
  readonly detail?: string;
}

export async function rsaSerRoundtripCryptopp(material: RsaKeyHexMaterial): Promise<RsaSerRoundtripResult> {
  const raw = JSON.parse(await runCli(CRYPTOPP_CLI, roundtripArgs(material)));
  return { backend: CRYPTOPP, ...raw };
}

export async function rsaSerRoundtripBouncyCastle(material: RsaKeyHexMaterial): Promise<RsaSerRoundtripResult> {
  const raw = JSON.parse(await runCli('java', ['-cp', BC_CLASSPATH, 'RsaSerBouncyCastleCli', ...roundtripArgs(material)]));
  return { backend: BOUNCY_CASTLE, ...raw };
}

// ---------------------------------------------------------------------
// M2.5.3.4 -- separate export/import, for cross-provider Phase B. The
// artifact from exportP is handed LITERALLY to importQ -- never decoded
// and re-encoded by this bridge code in between.
// ---------------------------------------------------------------------

export interface RsaSerExportOnlyResult {
  readonly backend: typeof CRYPTOPP | typeof BOUNCY_CASTLE;
  readonly exportOk: boolean;
  readonly artifactHex?: string;
  readonly exportError?: string;
}
export interface RsaSerImportOnlyResult {
  readonly backend: typeof CRYPTOPP | typeof BOUNCY_CASTLE;
  readonly importOk: boolean;
  readonly materialPreserved?: boolean;
  readonly errorClass?: string;
  readonly detail?: string;
}

export async function rsaSerExportCryptopp(material: RsaKeyHexMaterial): Promise<RsaSerExportOnlyResult> {
  const raw = JSON.parse(await runCli(CRYPTOPP_CLI, ['export', material.role, material.nHex, material.eHex, material.dHex ?? '', material.pHex ?? '', material.qHex ?? '', material.dpHex ?? '', material.dqHex ?? '', material.qiHex ?? '']));
  return { backend: CRYPTOPP, ...raw };
}
export async function rsaSerImportCryptopp(role: 'public' | 'private', artifactHex: string, expected: RsaKeyHexMaterial): Promise<RsaSerImportOnlyResult> {
  const raw = JSON.parse(await runCli(CRYPTOPP_CLI, ['import', role, artifactHex, expected.nHex, expected.eHex, expected.dHex ?? '', expected.pHex ?? '', expected.qHex ?? '']));
  return { backend: CRYPTOPP, ...raw };
}
export async function rsaSerExportBouncyCastle(material: RsaKeyHexMaterial): Promise<RsaSerExportOnlyResult> {
  const raw = JSON.parse(await runCli('java', ['-cp', BC_CLASSPATH, 'RsaSerBouncyCastleCli', 'export', material.role, material.nHex, material.eHex, material.dHex ?? '', material.pHex ?? '', material.qHex ?? '', material.dpHex ?? '', material.dqHex ?? '', material.qiHex ?? '']));
  return { backend: BOUNCY_CASTLE, ...raw };
}
export async function rsaSerImportBouncyCastle(role: 'public' | 'private', artifactHex: string, expected: RsaKeyHexMaterial): Promise<RsaSerImportOnlyResult> {
  const raw = JSON.parse(await runCli('java', ['-cp', BC_CLASSPATH, 'RsaSerBouncyCastleCli', 'import', role, artifactHex, expected.nHex, expected.eHex, expected.dHex ?? '', expected.pHex ?? '']));
  return { backend: BOUNCY_CASTLE, ...raw };
}
