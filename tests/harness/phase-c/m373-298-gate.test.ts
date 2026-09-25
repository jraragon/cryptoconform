// M3.7.3 -- the closing gate. Every R_interop obligation, real producers.

import { test, after } from 'node:test';
import assert from 'node:assert/strict';

import { assembleStructuralPlan } from '../../../harness/phase-c/plan-assembly.js';
import { loadFrozenMaterialPool } from '../../../harness/phase-c/material/load.js';
import {
  bindRequiredObligations, directedTransferObligations, nonInteropObligations,
} from '../../../harness/phase-c/execution-binding.js';
import { isArtifactBearing } from '../../../harness/phase-c/producer-stimulus-identity.js';
import { mutateFreshArtifact, producerInputFor, realizeConsumerMaterial } from '../../../harness/phase-c/artifact-side-producer.js';
import { assembleConsumerInput } from '../../../harness/phase-c/consumer-input.js';
import { getFixtureResolver } from '../../../harness/phase-c/fixture-index.js';
import { getMutationImplementation } from '../../../harness/phase-c/mutation-index.js';
import { materializeDispatch } from '../../../harness/orchestration/dispatch-materialization.js';
import { executeBaseline } from '../../../harness/orchestration/engine.js';
import { ecArtifactProducerRole } from '../../../harness/phase-c/fixtures/ec-ser-artifact.js';
import { closeChromiumForTests } from '../../../harness/orchestration/hkdf-chromium-wiring.js';
import { rsaArtifactProducerRole } from '../../../harness/phase-c/fixtures/rsa-ser-artifact.js';
import { gcmConsumedArtifactId } from '../../../harness/phase-c/fixtures/gcm-artifact.js';
import { rsaSerExportCryptopp, rsaSerExportBouncyCastle } from '../../../harness/orchestration/rsa-ser-native-wiring.js';
import { rsaSerExportChromium } from '../../../harness/orchestration/rsa-ser-chromium-wiring.js';
import { ecSerExportCryptopp, ecSerExportBouncyCastle } from '../../../harness/orchestration/ec-ser-native-wiring.js';
import { ecSerExportChromium } from '../../../harness/orchestration/ec-ser-chromium-wiring.js';

/* eslint-disable @typescript-eslint/no-explicit-any */
const pool = loadFrozenMaterialPool();
const all = bindRequiredObligations(assembleStructuralPlan(pool), pool);
const interop = directedTransferObligations(all);

const EXPORTERS: any = {
  'rsa-ser': { chromium: rsaSerExportChromium, cryptopp: rsaSerExportCryptopp, bouncycastle: rsaSerExportBouncyCastle },
  'ec-ser': { chromium: ecSerExportChromium, cryptopp: ecSerExportCryptopp, bouncycastle: ecSerExportBouncyCastle },
};

interface Outcome { resolved: boolean; op: string; producerId: string; why?: string }

/**
 * Drives every obligation through the real chain: frozen producer inputs ->
 * a REAL execution on scope.from -> the FROZEN mutation applied to what it
 * produced -> consumer-input assembly. No cache, so no A_0 can be shared
 * between obligations that must not share one.
 */
async function driveAll(): Promise<Outcome[]> {
  const out: Outcome[] = [];
  const registered: string[] = [];
  for (const o of interop) {
    try {
      const f0 = getFixtureResolver(o.mutationId, o.stimulusInstanceId)(o.mutationId, o.stimulusInstanceId, pool);
      const impl = getMutationImplementation(o.mutationId) as any;
      const mutated = impl.mutate(f0, o.stimulusInstanceId);
      const b = o.binding as any;
      let producerFixture: unknown = mutated;
      let producerId = `${o.mutationId}::${b.from.family}::request-side`;
      if (isArtifactBearing(mutated)) {
        // The producer role is PROPAGATED from the frozen artifact selection,
        // per operation, never defaulted and never read from the DER.
        const role = o.operation === 'ec-ser' ? ecArtifactProducerRole(o.mutationId, o.stimulusInstanceId, pool)
          : o.operation === 'rsa-ser' ? rsaArtifactProducerRole(o.mutationId, o.stimulusInstanceId, pool) : undefined;
        const consumesArtifactId = o.operation === 'gcm' ? gcmConsumedArtifactId(o.mutationId, pool) : undefined;
        const input = producerInputFor({
          operation: o.operation, material: b.material,
          ...(role === undefined ? {} : { producerRole: role }),
          ...(consumesArtifactId === undefined ? {} : { consumesArtifactId }),
        }) as any;
        const m = materializeDispatch(o.operation, b.from, b.producerRole);
        let a0: string;
        if (m.entry.shape === 'execution-adapter') {
          const e = await executeBaseline('B', `p-${o.mutationId}-${b.from.family}`, input, m.wiring as never);
          a0 = (e.output as any).bytes;
          producerId = e.executionId;
        } else {
          const r = await EXPORTERS[o.operation][b.from.family](input);
          if (!r.exportOk) throw new Error(`${o.operation}/${b.from.family} export failed`);
          a0 = r.artifactHex;
          producerId = `${o.mutationId}::${b.from.family}::${o.operation}-export`;
        }
        producerFixture = mutateFreshArtifact({
          operation: o.operation, baseFixture: f0, freshArtifactHex: a0,
          stimulusInstanceId: o.stimulusInstanceId, mutate: (f, s) => impl.mutate(f, s),
        });
      }
      registered.push(producerId);
      assembleConsumerInput({
        operation: o.operation, producerFixture, artifactHex: 'aabbcc',
        ...(b.material ? { boundMaterial: realizeConsumerMaterial(o.operation, b.material) } : {}),
      });
      out.push({ resolved: true, op: o.operation, producerId });
    } catch (e) {
      out.push({ resolved: false, op: o.operation, producerId: '', why: `${o.mutationId}: ${(e as Error).message}` });
    }
  }
  return out;
}

// The gate drives real Chromium producers, so the browser must be closed or
// the process never exits -- a hang, not a failure, but just as blocking.
after(async () => { await closeChromiumForTests(); });

const driven = await driveAll();
/* eslint-enable @typescript-eslint/no-explicit-any */

test('M3.7.3 CLOSING: 216 obligations, 216 resolved, 0 unresolved', () => {
  assert.equal(interop.length, 216);
  assert.deepEqual(driven.filter((d) => !d.resolved).map((d) => d.why), []);
  assert.equal(driven.filter((d) => d.resolved).length, 216);
});

test('M3.7.3 CLOSING: the per-operation breakdown', () => {
  const byOp: Record<string, number> = {};
  for (const d of driven) if (d.resolved) byOp[d.op] = (byOp[d.op] ?? 0) + 1;
  assert.deepEqual(byOp, { gcm: 66, oaep: 18, pss: 18, 'rsa-ser': 66, 'ec-ser': 48 });
});

test('M3.7.3 CLOSING: 886 required obligations, 670 + 216', () => {
  assert.equal(all.length, 886);
  assert.equal(nonInteropObligations(all).length, 670);
  assert.equal(nonInteropObligations(all).length + interop.length, all.length);
});

test('M3.7.3 CLOSING: every obligation names a producer identity', () => {
  assert.equal(driven.filter((d) => d.resolved && d.producerId.length > 0).length, 216);
});

test('M3.7.3: the producer role is DERIVED per operation, not defaulted', () => {
  // The regression the 24 EC and 12 RSA failures earned: if either route ever
  // imposes a single role for all artifact-side obligations, both roles can no
  // longer appear, and this fails.
  const ecRoles = new Set<string>();
  const rsaRoles = new Set<string>();
  for (const o of interop) {
    const f0 = getFixtureResolver(o.mutationId, o.stimulusInstanceId)(o.mutationId, o.stimulusInstanceId, pool) as { artifact?: Uint8Array };
    if (f0.artifact === undefined) continue;
    if (o.operation === 'ec-ser') ecRoles.add(ecArtifactProducerRole(o.mutationId, o.stimulusInstanceId, pool));
    if (o.operation === 'rsa-ser') rsaRoles.add(rsaArtifactProducerRole(o.mutationId, o.stimulusInstanceId, pool));
  }
  assert.deepEqual([...ecRoles].sort(), ['private', 'public'], 'EC-ser must resolve BOTH roles');
  assert.deepEqual([...rsaRoles].sort(), ['private', 'public'], 'RSA-ser must resolve BOTH roles');
});
