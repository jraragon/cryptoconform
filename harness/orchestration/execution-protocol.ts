// Bloque D / M3.4 -- the execution protocol, as an executable contract.
//
// Not installation documentation. Installation Notes v0.11 already describe
// how to build the environment; this module states what the environment must
// BE before a scored execution is permitted, and refuses when it is not.
//
// The governing rule, the same shape as M3.5's own ProjectionError rule:
//
//     EnvironmentMismatch  =>  ABORT before scored execution
//
// An incorrect infrastructure cannot degrade to not-executed, nor to
// insufficient-evidence, nor be quietly recorded in metadata. Those describe
// experimental outcomes; a wrong toolchain describes an invalid experiment,
// and filing it as either would record an infrastructure defect as science.
//
// --- What is pinned, and at what strictness ------------------------------
//
// Two strictnesses, deliberately not one. An EXACT pin is a realization the
// experiment's own identity depends on: change it and the results are not
// comparable to M1's. A MINIMUM is a host requirement whose newer versions
// do not alter observable behaviour. Making everything exact would fail on
// irrelevant patch drift; making everything minimum would let a different
// Chromium produce results attributed to the pinned one.

import { execFileSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { existsSync, readFileSync } from 'node:fs';
import { CHROMIUM_WEBCRYPTO } from '../schema/backend-identity.js';

export class EnvironmentMismatchError extends Error {}

export interface EnvironmentRequirement {
  readonly id: string;
  readonly what: string;
  readonly strictness: 'exact' | 'minimum' | 'present';
  readonly expected: string;
  readonly why: string;
}

/**
 * The frozen requirements. Every value here is one this sandbox actually
 * reproduced, not one copied from a prior machine.
 */
export const ENVIRONMENT_REQUIREMENTS: readonly EnvironmentRequirement[] = Object.freeze([
  {
    id: 'node', what: 'Node.js', strictness: 'minimum', expected: '22.0.0',
    why: 'Host runtime. The harness uses node:test and stable ES2022 output; newer patch levels do not change observable behaviour.',
  },
  {
    id: 'bc-jar', what: 'Bouncy Castle provider jar', strictness: 'exact',
    expected: 'dabb98c24d72c9b9f585633d1df9c5cd58d9ad373d0cd681367e6a603a495d58',
    why: 'A backend under evaluation, pinned by content rather than by filename, since a jar of the same name can differ.',
  },
  {
    id: 'chromium', what: 'Chromium build', strictness: 'exact', expected: CHROMIUM_WEBCRYPTO.apiVersion,
    why: 'A backend under evaluation, and the one whose identity the frozen manifest already carries; a different build '
      + 'would produce results attributed to the pinned one.',
  },
  {
    id: 'jdk', what: 'JDK with javac', strictness: 'present', expected: 'javac',
    why: 'A JRE is NOT enough. Discovered empirically: java was present, javac was not, and the six Bouncy Castle CLI '
      + 'wrappers failed to build while the Crypto++ ones succeeded. javac is part of the effective reconstruction.',
  },
  {
    id: 'gxx', what: 'C++ toolchain', strictness: 'present', expected: 'g++',
    why: 'Required to rebuild the Crypto++ CLI wrappers from the pinned source; native-build/ is gitignored so they '
      + 'must be rebuilt rather than transported.',
  },
  {
    id: 'bc-jar-env', what: 'BC_JAR environment variable', strictness: 'present', expected: 'BC_JAR',
    why: 'A runtime prerequisite with NO default, by design: falling back to a path that existed on one prior machine '
      + 'would turn a missing prerequisite into a confusing downstream class-not-found error instead of an immediate one.',
  },
  {
    id: 'native-build', what: 'Rebuilt native CLI artifacts', strictness: 'present', expected: '12 artifacts',
    why: 'native-build/ is deliberately gitignored and does not travel in the TAR, so R4 must demonstrate the binaries are '
      + 'reproducible from pinned sources rather than carried as residue.',
  },
]);

export interface EnvironmentCheck {
  readonly id: string;
  readonly satisfied: boolean;
  readonly observed: string;
  readonly detail?: string;
}

function tryExec(cmd: string, args: readonly string[]): string | undefined {
  try { return execFileSync(cmd, [...args], { encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] }).trim(); }
  catch { return undefined; }
}

function versionAtLeast(observed: string, minimum: string): boolean {
  const norm = (v: string) => v.replace(/^v/, '').split('.').map((p) => Number.parseInt(p, 10) || 0);
  const [a, b] = [norm(observed), norm(minimum)];
  for (let i = 0; i < 3; i += 1) {
    if ((a[i] ?? 0) > (b[i] ?? 0)) return true;
    if ((a[i] ?? 0) < (b[i] ?? 0)) return false;
  }
  return true;
}

/**
 * Observes the environment. Reports; does not decide. The abort is
 * assertExecutionEnvironment's own job, so a caller cannot inspect the
 * result and choose to continue past a mismatch by accident.
 */
export function checkEnvironment(options: {
  readonly cryptoppDir?: string;
  readonly bcJar?: string;
  readonly nativeBuildDir?: string;
  readonly chromiumVersion?: string;
} = {}): readonly EnvironmentCheck[] {
  const out: EnvironmentCheck[] = [];

  out.push({ id: 'node', satisfied: versionAtLeast(process.version, '22.0.0'), observed: process.version });

  const bcJar = options.bcJar ?? process.env['BC_JAR'];
  let jarHash: string | undefined;
  if (bcJar !== undefined && existsSync(bcJar)) {
    jarHash = createHash('sha256').update(readFileSync(bcJar)).digest('hex');
  }
  out.push({ id: 'bc-jar-env', satisfied: bcJar !== undefined, observed: bcJar ?? '(unset)' });
  out.push({
    id: 'bc-jar',
    satisfied: jarHash === 'dabb98c24d72c9b9f585633d1df9c5cd58d9ad373d0cd681367e6a603a495d58',
    observed: jarHash ?? '(absent)',
  });

  const javac = tryExec('javac', ['-version']);
  out.push({ id: 'jdk', satisfied: javac !== undefined, observed: javac ?? '(javac not found -- a JRE is not enough)' });

  const gxx = tryExec('g++', ['--version']);
  out.push({ id: 'gxx', satisfied: gxx !== undefined, observed: gxx?.split('\n')[0] ?? '(g++ not found)' });

  const chromium = options.chromiumVersion;
  out.push({
    id: 'chromium',
    satisfied: chromium === undefined ? false : chromium.includes(CHROMIUM_WEBCRYPTO.apiVersion),
    observed: chromium ?? '(not probed)',
    detail: 'Probed from the launched browser itself, never from a manifest reading itself.',
  });

  const nativeDir = options.nativeBuildDir;
  const required = [
    'hkdf-cryptopp-cli', 'gcm-cryptopp-cli', 'oaep-cryptopp-cli',
    'pss-cryptopp-cli', 'rsa-ser-cryptopp-cli', 'ec-ser-cryptopp-cli',
  ];
  const present = nativeDir === undefined ? 0 : required.filter((f) => existsSync(`${nativeDir}/${f}`)).length;
  out.push({
    id: 'native-build',
    satisfied: nativeDir !== undefined && present === required.length && existsSync(`${nativeDir}/bc-classes`),
    observed: nativeDir === undefined ? '(not probed)' : `${present}/${required.length} CLIs + bc-classes`,
  });

  return out;
}

/**
 * The gate. Fail-closed, and deliberately with no severity levels: there is
 * no "warn and continue" path, because a warning is exactly how a mismatched
 * toolchain reaches a scored execution.
 */
export function assertExecutionEnvironment(checks: readonly EnvironmentCheck[]): void {
  const failed = checks.filter((c) => !c.satisfied);
  if (failed.length === 0) return;
  const lines = failed.map((c) => {
    const req = ENVIRONMENT_REQUIREMENTS.find((r) => r.id === c.id);
    return `  ${c.id} (${req?.what ?? c.id}): expected ${req?.strictness ?? '?'} '${req?.expected ?? '?'}', observed '${c.observed}'`;
  });
  throw new EnvironmentMismatchError(
    `Environment mismatch -- refusing to begin a scored execution.\n${lines.join('\n')}\n` +
    'An incorrect infrastructure is not an experimental outcome: it cannot become not-executed or ' +
    'insufficient-evidence, and it must not be recorded as metadata alongside results it invalidates.',
  );
}

/** Every requirement must be observable; a pin nobody checks is not a pin. */
export function requirementsWithoutCheck(checks: readonly EnvironmentCheck[]): readonly string[] {
  const checked = new Set(checks.map((c) => c.id));
  return ENVIRONMENT_REQUIREMENTS.filter((r) => !checked.has(r.id)).map((r) => r.id);
}
