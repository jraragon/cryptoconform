// M3.7.5 / D15 -- positive scored attestation.
//
// Exercised with SENTINEL content that is unambiguously not M4: the strings
// below are not evidence, and no obligation is executed anywhere in this file.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';

import {
  assertCommitsMatchAttestation, assertIsScoredArtifact, attestationChain, attestScoredRun,
  ScoredAttestationError, verifyScoredAttestation, type ScoredAttestation,
} from '../../../harness/orchestration/scored-attestation.js';
import {
  SCORED_EXECUTION_POLICY_VERSION, digestOf, type BlockCommit,
} from '../../../harness/orchestration/scored-execution-policy.js';
import { makeDryRunBundle } from '../../../harness/orchestration/dry-run.js';

const SENTINEL = '{"sentinel":"M3.7.5 attestation validation -- NOT M4 evidence"}';
const OTHER = '{"sentinel":"a different artifact"}';

const identity = {
  runId: 'run-m375-sentinel',
  policyVersion: SCORED_EXECUTION_POLICY_VERSION,
  instrumentCommit: 'b5a6506',
  plannedObligations: 1641,
  requiredObligations: 1246,
  environmentDigest: digestOf('env-sentinel'),
};

const attestation = attestScoredRun({ identity, serializedContent: SENTINEL });

// =====================================================================
// The positive claim
// =====================================================================

test('D15: a scored run carries a POSITIVE mark, not the absence of one', () => {
  assert.equal(attestation.kind, 'scored');
  assert.equal(attestation.runId, identity.runId);
  assert.equal(attestation.policyVersion, SCORED_EXECUTION_POLICY_VERSION);
  assert.equal(attestation.attestationDigest.length, 64);
  assert.doesNotThrow(() => verifyScoredAttestation(attestation, SENTINEL));
});

test('D15: absence is refused explicitly, and says why', () => {
  assert.throws(() => verifyScoredAttestation(undefined, SENTINEL), ScoredAttestationError);
  assert.throws(() => verifyScoredAttestation(undefined, SENTINEL), /Absence is not a claim/);
  assert.throws(() => verifyScoredAttestation(null, SENTINEL), /Absence is not a claim/);
  assert.throws(() => verifyScoredAttestation({}, SENTINEL), /not 'scored'/);
});

test('D15: the chain is traversable, dataset -> run -> policy -> instrument', () => {
  const c = attestationChain(attestation);
  assert.equal(c.dataset, attestation.contentDigest);
  assert.equal(c.run, identity.runId);
  assert.equal(c.policy, SCORED_EXECUTION_POLICY_VERSION);
  assert.equal(c.instrument, 'b5a6506');
  assert.equal(c.environment, identity.environmentDigest);
});

// =====================================================================
// The negative cases
// =====================================================================

test('D15: a wrong policy identity is refused, on issue and on verification', () => {
  assert.throws(
    () => attestScoredRun({ identity: { ...identity, policyVersion: 'M3.7.4/0' }, serializedContent: SENTINEL }),
    /executes the frozen policy or it is not a scored run/,
  );
  const forged = { ...attestation, policyVersion: 'M3.7.4/0' };
  assert.throws(() => verifyScoredAttestation(forged, SENTINEL), /not 'M3.7.4\/1'/);
});

test('D15: a tampered attestation no longer matches its own fields', () => {
  for (const field of ['runId', 'instrumentCommit', 'environmentDigest'] as const) {
    const forged = { ...attestation, [field]: 'tampered' };
    assert.throws(() => verifyScoredAttestation(forged, SENTINEL), /altered since it was issued/, field);
  }
  const countForged = { ...attestation, requiredObligations: 1 };
  assert.throws(() => verifyScoredAttestation(countForged, SENTINEL), /altered since it was issued/);
});

test('D15: an attestation cannot be moved onto different content', () => {
  assert.throws(() => verifyScoredAttestation(attestation, OTHER), /cannot be moved onto a different dataset/);
  // And re-attesting the other content produces a different digest, so the
  // two are not interchangeable.
  const other = attestScoredRun({ identity, serializedContent: OTHER });
  assert.notEqual(other.contentDigest, attestation.contentDigest);
  assert.notEqual(other.attestationDigest, attestation.attestationDigest);
});

test('D15: a dry-run artifact cannot be presented as scored, whatever it is renamed to', () => {
  const dry = makeDryRunBundle({
    bundleVersion: '2.0', executions: [], observations: [], instanceResults: [],
    mutationResults: [], scientificResults: [], omittedClasses: [],
  });
  assert.throws(() => assertIsScoredArtifact(dry, SENTINEL), ScoredAttestationError);
  assert.throws(() => assertIsScoredArtifact(dry, SENTINEL), /DRY RUN artifact and cannot be presented as scored/);
  // Even with a valid attestation stapled on, the dry-run mark still refuses:
  // the two checks are independent and the dry-run one comes first.
  assert.throws(() => assertIsScoredArtifact({ ...dry, attestation }, SENTINEL), /DRY RUN artifact/);
});

test('D15: an artifact with neither mark is refused too -- silence proves nothing', () => {
  assert.throws(() => assertIsScoredArtifact({ bundle: {} }, SENTINEL), /Absence is not a claim/);
  assert.doesNotThrow(() => assertIsScoredArtifact({ attestation }, SENTINEL));
});

// =====================================================================
// Blocks and the attested run
// =====================================================================

const commit = (over: Partial<BlockCommit> = {}): BlockCommit => ({
  blockId: 'block:gcm', runId: identity.runId, policyVersion: SCORED_EXECUTION_POLICY_VERSION,
  obligationCount: 66, digest: digestOf('block:gcm'), attempt: 1, ...over,
});

test('D15: blocks from another run cannot join an attested dataset', () => {
  assert.doesNotThrow(() => assertCommitsMatchAttestation(attestation, [commit()]));
  assert.throws(() => assertCommitsMatchAttestation(attestation, [commit({ runId: 'run-other' })]),
    /not to the attested run/);
  assert.throws(() => assertCommitsMatchAttestation(attestation, [commit({ policyVersion: 'M3.7.4/0' })]),
    /was produced under policy/);
});

// =====================================================================
// Boundaries
// =====================================================================

test('D15: the attestation decides nothing about what is scored or how it runs', () => {
  const src = readFileSync(new URL('../../../harness/orchestration/scored-attestation.ts', import.meta.url), 'utf8');
  const imports = src.split('\n').filter((l) => l.trimStart().startsWith('import'));
  for (const line of imports) {
    for (const forbidden of ['evidence-export', 'plan-assembly', 'execution-binding', 'aggregation/', 'relation-observation']) {
      assert.ok(!line.includes(forbidden), `D14 settled execution; this only represents identity: ${line.trim()}`);
    }
  }
});

test('D15: the EvidenceBundle gains no field -- one authoritative source', () => {
  const src = readFileSync(new URL('../../../harness/aggregation/evidence-export.ts', import.meta.url), 'utf8');
  assert.ok(!src.includes('attestation'), 'the attestation lives in the envelope, not duplicated in the bundle');
  assert.ok(!src.includes('runKind'), 'and the scientific record gains no run-kind field either');
});

test('D15: no M4 evidence is produced here', () => {
  const src = readFileSync(new URL('./m375-scored-attestation.test.ts', import.meta.url), 'utf8');
  assert.ok(src.includes('NOT M4 evidence'), 'the sentinel says so in its own content');
  for (const forbidden of ['runPhaseC', 'executeBaseline', 'executeMutation', 'runTransfer']) {
    assert.ok(!src.includes(`${forbidden}(`), `no execution may happen in this gate ('${forbidden}')`);
  }
});
