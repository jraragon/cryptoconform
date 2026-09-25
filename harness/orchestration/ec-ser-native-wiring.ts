// M2.5.2 -- EC-ser x Crypto++ / Bouncy Castle real round-trip wiring,
// invoking the compiled native CLI wrappers via subprocess.

import { spawn } from 'node:child_process';
import { requireBcJar } from './native-cli-env.js';
import { fileURLToPath } from 'node:url';
import path from 'node:path';
import { CRYPTOPP, BOUNCY_CASTLE } from '../schema/backend-identity.js';
import type { EcKeyHexMaterial } from './ec-ser-chromium-wiring.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const NATIVE_BUILD_DIR = path.join(__dirname, 'native-build');
const CRYPTOPP_CLI = path.join(NATIVE_BUILD_DIR, 'ec-ser-cryptopp-cli');
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

function roundtripArgs(material: EcKeyHexMaterial): string[] {
  return ['roundtrip', material.role, material.xHex, material.yHex, material.dHex ?? ''];
}

export interface EcSerRoundtripResult {
  readonly backend: typeof CRYPTOPP | typeof BOUNCY_CASTLE;
  readonly exportOk: boolean;
  readonly artifactHex?: string;
  readonly importOk?: boolean;
  readonly normalized?: boolean;
  readonly materialPreserved?: boolean;
  readonly errorClass?: string;
  readonly detail?: string;
}

export async function ecSerRoundtripCryptopp(material: EcKeyHexMaterial): Promise<EcSerRoundtripResult> {
  const raw = JSON.parse(await runCli(CRYPTOPP_CLI, roundtripArgs(material)));
  return { backend: CRYPTOPP, ...raw };
}

export async function ecSerRoundtripBouncyCastle(material: EcKeyHexMaterial): Promise<EcSerRoundtripResult> {
  const raw = JSON.parse(await runCli('java', ['-cp', BC_CLASSPATH, 'EcSerBouncyCastleCli', ...roundtripArgs(material)]));
  return { backend: BOUNCY_CASTLE, ...raw };
}

// ---------------------------------------------------------------------
// M2.5.3.5 -- separate export/import, for cross-provider Phase B. The
// artifact from exportP is handed LITERALLY to importQ -- never decoded
// and re-encoded by this bridge code in between. Echoes back recovered
// x/y/d as hex (never re-deriving V_scalar/V_curve/V_pair itself) so the
// caller can verify them independently via M1's own real p256.ts arithmetic.
// ---------------------------------------------------------------------

export interface EcSerExportOnlyResult {
  readonly backend: typeof CRYPTOPP | typeof BOUNCY_CASTLE;
  readonly exportOk: boolean;
  readonly artifactHex?: string;
  readonly exportError?: string;
}
export interface EcSerImportOnlyResult {
  readonly backend: typeof CRYPTOPP | typeof BOUNCY_CASTLE;
  readonly importOk: boolean;
  readonly normalized?: boolean;
  readonly recoveredXHex?: string;
  readonly recoveredYHex?: string;
  readonly recoveredDHex?: string;
  readonly errorClass?: string;
  readonly detail?: string;
}

export async function ecSerExportCryptopp(material: EcKeyHexMaterial): Promise<EcSerExportOnlyResult> {
  const raw = JSON.parse(await runCli(CRYPTOPP_CLI, ['export', material.role, material.xHex, material.yHex, material.dHex ?? '']));
  return { backend: CRYPTOPP, ...raw };
}
export async function ecSerImportCryptopp(role: 'public' | 'private', artifactHex: string): Promise<EcSerImportOnlyResult> {
  const raw = JSON.parse(await runCli(CRYPTOPP_CLI, ['import', role, artifactHex]));
  if (raw.recoveredDHex === '') raw.recoveredDHex = undefined;
  return { backend: CRYPTOPP, ...raw };
}
export async function ecSerExportBouncyCastle(material: EcKeyHexMaterial): Promise<EcSerExportOnlyResult> {
  const raw = JSON.parse(await runCli('java', ['-cp', BC_CLASSPATH, 'EcSerBouncyCastleCli', 'export', material.role, material.xHex, material.yHex, material.dHex ?? '']));
  return { backend: BOUNCY_CASTLE, ...raw };
}
export async function ecSerImportBouncyCastle(role: 'public' | 'private', artifactHex: string): Promise<EcSerImportOnlyResult> {
  const raw = JSON.parse(await runCli('java', ['-cp', BC_CLASSPATH, 'EcSerBouncyCastleCli', 'import', role, artifactHex]));
  if (raw.recoveredDHex === '') raw.recoveredDHex = undefined;
  return { backend: BOUNCY_CASTLE, ...raw };
}
