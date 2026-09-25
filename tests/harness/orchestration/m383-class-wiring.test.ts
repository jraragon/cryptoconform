// M3.8.3 -- the class wiring layer: frozen fixture -> dispatch -> adapter.

import { after, test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';

import { assembleStructuralPlan } from '../../../harness/phase-c/plan-assembly.js';
import { loadFrozenMaterialPool } from '../../../harness/phase-c/material/load.js';
import { bindRequiredObligations } from '../../../harness/phase-c/execution-binding.js';
import { wireObligation } from '../../../harness/orchestration/class-wiring.js';
import { realizeAdapter } from '../../../harness/orchestration/serialization-adapter.js';
import { getFixtureResolver } from '../../../harness/phase-c/fixture-index.js';
import { getMutationImplementation } from '../../../harness/phase-c/mutation-index.js';
import { rsaArtifactProducerRole } from '../../../harness/phase-c/fixtures/rsa-ser-artifact.js';
import { ecArtifactProducerRole } from '../../../harness/phase-c/fixtures/ec-ser-artifact.js';
import { closeSharedChromium } from '../../../harness/orchestration/chromium-page.js';

const pool = loadFrozenMaterialPool();
const all = bindRequiredObligations(assembleStructuralPlan(pool), pool);
const wired = all.map((o) => wireObligation(o, pool));

after(async () => {
  await closeSharedChromium();
});

test('M3.8.3: every required obligation wires, over all 73 Required-bearing classes', () => {
  assert.equal(all.length, 886);
  assert.equal(wired.length, 886);
  assert.equal(new Set(wired.map((w) => w.mutationId)).size, 73);
});

test('M3.8.3: 868 operational and 18 declarative -- and the split is by SHAPE', () => {
  const op = wired.filter((w) => w.kind === 'operational');
  const decl = wired.filter((w) => w.kind === 'declarative');
  assert.equal(op.length, 868);
  assert.equal(decl.length, 18);
  assert.equal(op.length + decl.length, 886);
  // A declarative stimulus has no operational input, so it gets no adapter --
  // inventing key material or an artifact role for it would be inventing the
  // experiment.
  for (const w of decl) assert.equal(w.adapters.length, 0, w.mutationId);
  for (const w of op) assert.ok(w.adapters.length > 0, w.mutationId);
});

test('M3.8.3: the fixture is the FROZEN one, never hand-written', () => {
  // The defect this layer exists to close: M3.7.6 built its plan with a
  // hand-written fixture and two hand-picked adapters, for ONE class of an
  // eight-class block, so everything between the frozen corpus and the M1
  // wirings was never exercised.
  const src = readFileSync(new URL('../../../harness/orchestration/class-wiring.ts', import.meta.url), 'utf8');
  assert.ok(src.includes('getFixtureResolver'), 'the fixture comes from the frozen resolver');
  assert.ok(src.includes('materializeDispatch'), 'the adapter comes from the frozen dispatch');
  assert.ok(!src.includes('new Uint8Array(['), 'no fixture may be written here');
  for (const w of wired) assert.ok(w.baseFixture !== undefined, w.mutationId);
});

test('M3.8.3: every adapter names a backend the obligation\'s SCOPE names', () => {
  for (const o of all) {
    const w = wireObligation(o, pool);
    if (w.kind === 'declarative') continue;
    const s = o.scope as { kind: string; backend?: { sourcePin: string }; backends?: { sourcePin: string }[]; from?: { sourcePin: string }; to?: { sourcePin: string } };
    const expected = new Set(
      s.kind === 'cross-backend-set' ? s.backends!.map((b) => b.sourcePin)
        : s.kind === 'backend-pair' ? [s.from!.sourcePin, s.to!.sourcePin]
          : [s.backend!.sourcePin],
    );
    for (const a of w.adapters) {
      assert.ok(expected.has(a.backend.sourcePin),
        `${o.mutationId}/${o.relation}: adapter backend is not one the scope names`);
    }
  }
});

test('M3.8.3: the layer resolves only -- it does not orchestrate or decide', () => {
  const src = readFileSync(new URL('../../../harness/orchestration/class-wiring.ts', import.meta.url), 'utf8');
  const imports = src.split('\n').filter((l) => l.trimStart().startsWith('import'));
  for (const line of imports) {
    for (const forbidden of ['phase-c-orchestrator', 'scored-execution-policy', 'scored-attestation', 'aggregation/']) {
      assert.ok(!line.includes(forbidden), `the layer must resolve, not orchestrate: ${line.trim()}`);
    }
  }
  assert.ok(!src.includes('runPhaseC'));
});

test('M3.8.3: the reopened Required population is preserved by wiring', () => {
  assert.equal(all.length, 886);
});


test('M3-reopen: serialization role-container mutation reaches the real import role', async () => {
  const cases = [
    {
      mutationId: 'RSA-SER-ROLE-CONTAINER-BYPASS',
      operation: 'rsa-ser',
      artifactRole: rsaArtifactProducerRole,
    },
    {
      mutationId: 'EC-ROLE-CONTAINER-MISMATCH',
      operation: 'ec-ser',
      artifactRole: ecArtifactProducerRole,
    },
  ] as const;

  for (const c of cases) {
    const o = all.find((candidate) =>
      candidate.mutationId === c.mutationId
      && candidate.operation === c.operation
      && candidate.relation === 'R_val'
      && candidate.binding.kind === 'single-backend'
    );

    assert.ok(o, `${c.mutationId}: no single-backend R_val obligation found`);

    const b = o.binding;
    assert.equal(b.kind, 'single-backend');
    if (b.kind !== 'single-backend') {
      throw new Error(`${c.mutationId}: unreachable non-single-backend binding`);
    }

    assert.equal(
      b.fixtureRealization,
      'serialization-artifact-import',
      `${c.mutationId}: artifact-side serialization must use import realization`,
    );

    assert.ok(b.material, `${c.mutationId}: serialization import needs bound material`);

    const artifactRole = c.artifactRole(
      o.mutationId,
      o.stimulusInstanceId,
      pool,
    );

    const baseFixture = getFixtureResolver(
      o.mutationId,
      o.stimulusInstanceId,
    )(o.mutationId, o.stimulusInstanceId, pool);

    const mutated = (getMutationImplementation(o.mutationId) as {
      mutate: (fixture: unknown, stimulusInstanceId: string) => unknown;
    }).mutate(baseFixture, o.stimulusInstanceId) as {
      artifact: Uint8Array;
      requestedRole: 'public' | 'private';
    };

    assert.ok(mutated.artifact instanceof Uint8Array);
    assert.ok(
      mutated.requestedRole === 'public' || mutated.requestedRole === 'private',
      `${c.mutationId}: mutation did not provide requestedRole`,
    );

    assert.notEqual(
      mutated.requestedRole,
      artifactRole,
      `${c.mutationId}: role-container mutation must differ from real artifact role`,
    );

    const adapter = realizeAdapter({
      dispatch: b.dispatch,
      material: b.material,
      artifactRole,
      fixtureRealization: b.fixtureRealization,
    });

    // The mutation must reach the native import call as the requested role.
    // A valid container presented under the opposite role must be rejected.
    const mutatedRecord = await adapter.execute(mutated);
    const mutatedEvidence = adapter.toEvidenceFields(mutated, mutatedRecord) as {
      outcome: { kind: string };
    };

    assert.equal(
      mutatedEvidence.outcome.kind,
      'reject',
      `${c.mutationId}: flipped requestedRole did not reach the import semantics`,
    );

    // Same artifact, but with no explicit requestedRole: the adapter must
    // fall back to the frozen artifactRole and the valid container must import.
    const nominal = {
      artifact: mutated.artifact,
    };

    const nominalRecord = await adapter.execute(nominal);
    const nominalEvidence = adapter.toEvidenceFields(nominal, nominalRecord) as {
      outcome: { kind: string };
    };

    assert.equal(
      nominalEvidence.outcome.kind,
      'accept',
      `${c.mutationId}: artifactRole fallback did not import the valid container`,
    );
  }
});
