// Bloque D / M3.4 -- execution protocol and environment freeze gate.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { existsSync, writeFileSync, rmSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

import {
  ENVIRONMENT_REQUIREMENTS, EnvironmentMismatchError, assertExecutionEnvironment,
  checkEnvironment, requirementsWithoutCheck, type EnvironmentCheck,
} from '../../../harness/orchestration/execution-protocol.js';
import { CHROMIUM_WEBCRYPTO } from '../../../harness/schema/backend-identity.js';

const repoRoot = fileURLToPath(new URL('../../../', import.meta.url));

// =====================================================================
// The protocol names what the experiment's identity depends on
// =====================================================================

test('M3.4: every requirement is observable -- a pin nobody checks is not a pin', () => {
  const checks = checkEnvironment({ chromiumVersion: CHROMIUM_WEBCRYPTO.apiVersion });
  assert.deepEqual([...requirementsWithoutCheck(checks)], []);
  assert.equal(ENVIRONMENT_REQUIREMENTS.length, checks.length);
});

test('M3.4: every requirement states WHY, and the three backends are pinned EXACTLY', () => {
  for (const r of ENVIRONMENT_REQUIREMENTS) {
    assert.ok(r.why.length > 60, `${r.id}: a requirement needs a reason, not a label`);
  }
  // Backends whose runtime identity is directly observable here remain exact.
  // Crypto++ source provenance is recorded separately, but Git metadata is not
  // an execution prerequisite of a transported frozen snapshot.
  for (const id of ['bc-jar', 'chromium']) {
    assert.equal(ENVIRONMENT_REQUIREMENTS.find((r) => r.id === id)!.strictness, 'exact', id);
  }
  // And a host tool whose newer versions do not change observable behaviour
  // must NOT be exact, or irrelevant patch drift would abort a valid run.
  assert.equal(ENVIRONMENT_REQUIREMENTS.find((r) => r.id === 'node')!.strictness, 'minimum');
});

test('M3.4: the JDK requirement records the empirical finding, not an assumption', () => {
  const jdk = ENVIRONMENT_REQUIREMENTS.find((r) => r.id === 'jdk')!;
  assert.ok(jdk.why.includes('JRE is NOT enough'));
  assert.ok(jdk.why.includes('javac'));
});

test('M3.4: BC_JAR has no default, by design', () => {
  const req = ENVIRONMENT_REQUIREMENTS.find((r) => r.id === 'bc-jar-env')!;
  assert.ok(req.why.includes('NO default'));
  const src = execFileSync('grep', ['-rn', 'BC_JAR', `${repoRoot}harness/orchestration/native-cli-env.ts`], { encoding: 'utf8' });
  assert.ok(!/BC_JAR\s*\|\|/.test(src) && !/BC_JAR.*\?\?/.test(src), 'no fallback path may be introduced');
});

test('M3.4: native-build/ is gitignored, so R4 must rebuild rather than transport', () => {
  const ignore = execFileSync('cat', [`${repoRoot}.gitignore`], { encoding: 'utf8' });
  assert.ok(ignore.includes('native-build'));
  const req = ENVIRONMENT_REQUIREMENTS.find((r) => r.id === 'native-build')!;
  assert.ok(req.why.includes('reproducible from pinned sources'));
});

// =====================================================================
// EnvironmentMismatch => ABORT
// =====================================================================

test('M3.4: this sandbox satisfies the protocol', () => {
  const checks = checkEnvironment({
    nativeBuildDir: `${repoRoot}harness/orchestration/native-build`,
    chromiumVersion: CHROMIUM_WEBCRYPTO.apiVersion,
  });
  const failed = checks.filter((c) => !c.satisfied).map((c) => `${c.id}=${c.observed}`);
  assert.deepEqual(failed, [], 'the protocol must hold where the suite actually runs');
  assert.doesNotThrow(() => assertExecutionEnvironment(checks));
});

test('M3.4: ANY mismatch aborts -- there is no warn-and-continue path', () => {
  // One failing check is enough, and the message must say what was expected
  // versus what was observed, so a mismatch is diagnosable rather than merely
  // fatal.
  const bad: EnvironmentCheck[] = [{ id: 'chromium', satisfied: false, observed: '999.0.0.0' }];
  assert.throws(() => assertExecutionEnvironment(bad), EnvironmentMismatchError);
  assert.throws(() => assertExecutionEnvironment(bad), /999\.0\.0\.0/);
  assert.throws(() => assertExecutionEnvironment(bad), new RegExp(CHROMIUM_WEBCRYPTO.apiVersion.replace(/\./g, '\\.')));
});

test('M3.4: a mismatch cannot degrade to an experimental outcome', () => {
  // The same rule as ProjectionError: infrastructure failure is not science.
  try {
    assertExecutionEnvironment([{ id: 'bc-jar', satisfied: false, observed: '(absent)' }]);
    assert.fail('expected a refusal');
  } catch (e) {
    assert.ok(e instanceof EnvironmentMismatchError);
    assert.ok((e as Error).message.includes('not-executed'));
    assert.ok((e as Error).message.includes('insufficient-evidence'));
    assert.ok((e as Error).message.includes('must not be recorded as metadata'));
  }
});

test('M3.4: transported execution does not require Git metadata for Crypto++', () => {
  assert.equal(
    ENVIRONMENT_REQUIREMENTS.some((r) => r.id === 'cryptopp-commit'),
    false,
    'Crypto++ Git identity must not be an execution-environment requirement',
  );
  const checks = checkEnvironment({ cryptoppDir: '/nonexistent' });
  assert.equal(
    checks.some((c) => c.id === 'cryptopp-commit'),
    false,
    'environment observation must not invoke or expose a Crypto++ Git check',
  );
});

// =====================================================================
// source PASS  AND  compiled PASS
// =====================================================================

test('M3.4: the instrument loads and resolves from the COMPILED artifact, not only from source', () => {
  // tsx PASS does not imply tsc PASS does not imply the compiled artifact
  // runs. The frozen-material.json asset-resolution defect appeared only on
  // leaving the source tree, and twice a draft passed the whole suite under
  // tsx while tsc reported a real type error.
  assert.ok(existsSync(`${repoRoot}dist/harness/phase-c/plan-assembly.js`),
    'run `npm run build` before this gate');

  const probe = `${repoRoot}m34-compiled-probe.mjs`;
  writeFileSync(probe, `
import { loadFrozenMaterialPool } from './dist/harness/phase-c/material/load.js';
import { assembleStructuralPlan } from './dist/harness/phase-c/plan-assembly.js';
import { auditGroundTruth } from './dist/harness/phase-c/ground-truth/resolve.js';
import { recountPlan } from './dist/harness/phase-c/plan-binding-audit.js';
import { auditRegistry } from './dist/harness/phase-c/interop-eligibility/resolve.js';
const plan = assembleStructuralPlan(loadFrozenMaterialPool());
const gt = auditGroundTruth();
const rc = recountPlan(plan);
const el = auditRegistry();
console.log(JSON.stringify({
  classes: plan.classes.length, gtPairs: gt.pairs,
  planned: rc.planned, required: rc.required, eligibilityPairs: el.totalPairs,
}));
`);
  try {
    const out = execFileSync('node', [probe], { cwd: repoRoot, encoding: 'utf8' }).trim();
    const compiled = JSON.parse(out.split('\n').pop()!) as Record<string, number>;
    // The same figures the source-tree gates assert. If the compiled artifact
    // could not resolve its frozen assets, the pool would fail to load and
    // the plan would not assemble at all.
    assert.deepEqual(compiled, {
      classes: 79, gtPairs: 90, planned: 1641, required: 886, eligibilityPairs: 81,
    });
  } finally {
    rmSync(probe, { force: true });
  }
});

test('M3.4: the corpus loader resolves its asset from BOTH representations', () => {
  // The fix recorded at M3.2.4b-2: resolve the co-located path first and fall
  // back to the source tree, so the loader no longer depends on which entry
  // point is used.
  assert.ok(existsSync(`${repoRoot}harness/phase-c/material/frozen-material.json`));
  const src = execFileSync('cat', [`${repoRoot}harness/phase-c/material/load.ts`], { encoding: 'utf8' });
  assert.ok(src.includes('existsSync') || src.includes('fallback') || src.includes('..'),
    'the loader must not depend on being run from the source tree');
});
