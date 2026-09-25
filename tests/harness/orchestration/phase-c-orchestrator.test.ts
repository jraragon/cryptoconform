import { test } from 'node:test';
import assert from 'node:assert/strict';

import { runPhaseC, ExecutabilityPlanMismatchError, type EntryExecutability, type MutationClassPlan, type StimulusInstancePlan, CapabilityIndependenceViolationError, BaselinePolicyViolationError, type ExecutionPlan, type PlanEntry } from '../../../harness/orchestration/phase-c-orchestrator.js';
import { HKDF_NODE_WEBCRYPTO_ADAPTER } from '../../../harness/orchestration/hkdf-wiring.js';
import { HKDF_INFO_TAMPER } from '../../../harness/mutations/hkdf.js';
import { evaluateByte } from '../../../harness/evaluators/r-byte.js';
import { makeRelationObservation } from '../../../harness/evidence/relation-observation.js';
import { NODE_WEBCRYPTO_OPENSSL } from '../../../harness/schema/backend-identity.js';
import type { RelationApplicability, ExpectedSpectrum } from '../../../harness/schema/registry-types.js';
import type { HkdfRequest } from '../../../src/contract/hkdf.js';
import type { HkdfEvidenceRecord } from '../../../src/evidence/record.js';

// M3-H6: executability now lives on the stimulus instance, one decision per
// structural entry. These helpers build the map from the entries themselves,
// so a test cannot silently disagree with its own plan.
const REQ = { kind: 'required' } as const;
const NX = { kind: 'structurally-not-executable', reason: 'backend-capability-absent' } as const;
function execAll(entries: readonly { relation: unknown; scope: unknown }[], state: typeof REQ | typeof NX = REQ): EntryExecutability[] {
  return entries.map((e) => ({ relation: e.relation, scope: e.scope, state })) as EntryExecutability[];
}
// Fills each stimulus instance's executability from the class's OWN entries,
// so a test plan cannot disagree with itself. Test-only convenience: the
// production type keeps the field required, since M3-H6 exists precisely
// because a default would hide stimulus-sensitive differences.
type LoosePlan<TFixture, TNative> = Omit<MutationClassPlan<TFixture, TNative>, 'stimulusInstances'> & {
  readonly stimulusInstances: readonly (Omit<StimulusInstancePlan<TFixture>, 'executability'>
    & { readonly executability?: readonly EntryExecutability[] })[];
};
function withExec<TFixture, TNative>(classPlan: LoosePlan<TFixture, TNative>): MutationClassPlan<TFixture, TNative> {
  return {
    ...classPlan,
    stimulusInstances: classPlan.stimulusInstances.map((si) => ({
      ...si,
      executability: si.executability ?? execAll(classPlan.entries),
    })),
  } as MutationClassPlan<TFixture, TNative>;
}

function baseFixture(): HkdfRequest {
  return { ikm: new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8]), salt: undefined, info: new Uint8Array([9, 9, 9]), length: 32 };
}

const HKDF_INFO_TAMPER_APPLICABILITY: RelationApplicability = { R_byte: true, R_interop: false, R_ser: false, R_val: false, R_err: false, R_cap: false };
const HKDF_INFO_TAMPER_EXPECTED: ExpectedSpectrum = {
  R_byte: { expectation: 'detect' }, R_interop: { expectation: 'n/a' }, R_ser: { expectation: 'n/a' },
  R_val: { expectation: 'n/a' }, R_err: { expectation: 'n/a' }, R_cap: { expectation: 'n/a' },
};

function makeRByteEntry(): PlanEntry<HkdfRequest, HkdfEvidenceRecord> {
  return {
    relation: 'R_byte', scope: { kind: 'single-backend', backend: NODE_WEBCRYPTO_OPENSSL },
    resolve: async (ctx) => {
      const baseline = await ctx.getBaseline(HKDF_NODE_WEBCRYPTO_ADAPTER);
      const mutated = await ctx.runMutation(HKDF_NODE_WEBCRYPTO_ADAPTER);
      const state = evaluateByte({
        applicable: true, inputsEquivalent: true,
        left: { executionStatus: baseline.executionStatus, comparableOutput: { kind: 'raw-output', bytes: (baseline.output as { bytes: string }).bytes } },
        right: { executionStatus: mutated.executionStatus, comparableOutput: { kind: 'raw-output', bytes: (mutated.output as { bytes: string }).bytes } },
      });
      return makeRelationObservation({
        applicable: true, context: mutated.context, relation: 'R_byte',
        scope: { kind: 'single-backend', backend: NODE_WEBCRYPTO_OPENSSL },
        status: state === 'divergent' ? 'fail' : 'pass', participants: [baseline.executionId, mutated.executionId],
        evaluatorId: 'R_byte', basis: 'M3.2.3 skeleton validation, real HKDF-INFO-TAMPER',
      });
    },
  };
}

test('M3.2.3: the orchestrator skeleton, exercised against the ONE real precedent (HKDF-INFO-TAMPER), reproduces exactly what the hand-written engine.test.ts already demonstrated', async () => {
  const plan: ExecutionPlan = {
    classes: [withExec({
      mutation: HKDF_INFO_TAMPER, operation: 'hkdf', gamma0Ref: 'HKDF-INFO-TAMPER',
      applicability: HKDF_INFO_TAMPER_APPLICABILITY, expectedSpectrum: HKDF_INFO_TAMPER_EXPECTED,
      stimulusInstances: [{ stimulusInstanceId: 'default', baseFixture: baseFixture(), executability: execAll([makeRByteEntry()]) }],
      entries: [makeRByteEntry()],
    })],
  };

  const result = await runPhaseC(plan);

  assert.equal(result.executions.length, 2, 'exactly one baseline + one mutation execution, both real');
  assert.equal(result.observations.length, 1);
  assert.equal(result.instances.length, 1, 'I1: exactly one MutationInstanceResult for the one stimulusInstanceId');
  assert.equal(result.instances[0]!.stimulusInstanceId, 'default');
  assert.equal(result.instances[0]!.complete, true);
  assert.equal(result.mutations.length, 1);
  assert.equal(result.mutations[0]!.observedSpectrum.R_byte, 'fail', 'a genuinely different info field must produce a genuinely divergent OKM, exactly as engine.test.ts already demonstrated by hand');
  assert.equal(result.mutations[0]!.complete, true);
  assert.equal(result.mutations[0]!.detectionSupport.evaluatedInstances, 1);
  assert.equal(result.mutations[0]!.detectionSupport.divergentInstances, 1);
});

test('M3.2.3: the baseline cache reuses a single execution across multiple stimulus instances sharing the identical (operation,backend,fixture)', async () => {
  const fixture = baseFixture();
  const plan: ExecutionPlan = {
    classes: [withExec({
      mutation: HKDF_INFO_TAMPER, operation: 'hkdf', gamma0Ref: 'HKDF-INFO-TAMPER',
      applicability: HKDF_INFO_TAMPER_APPLICABILITY, expectedSpectrum: HKDF_INFO_TAMPER_EXPECTED,
      stimulusInstances: [
        { stimulusInstanceId: 'instance-a', baseFixture: fixture, executability: execAll([makeRByteEntry()]) },
        { stimulusInstanceId: 'instance-b', baseFixture: fixture, executability: execAll([makeRByteEntry()]) },
      ],
      entries: [makeRByteEntry()],
    })],
  };

  const result = await runPhaseC(plan);

  assert.equal(result.instances.length, 2, 'two distinct MutationInstanceResult, one per stimulusInstanceId (I1)');
  assert.equal(result.executions.length, 3, 'baseline reused once across both instances; mutation always executed fresh per instance');
});

test('M3.2.3: I5 -- an R_cap observation referencing the SAME execution for both roles is rejected fail-closed by the orchestrator itself, never merely trusted to the plan', async () => {
  const plan: ExecutionPlan = {
    classes: [withExec({
      mutation: HKDF_INFO_TAMPER, operation: 'hkdf', gamma0Ref: 'HKDF-INFO-TAMPER',
      applicability: { R_byte: false, R_interop: false, R_ser: false, R_val: false, R_err: false, R_cap: true },
      expectedSpectrum: { R_byte: { expectation: 'n/a' }, R_interop: { expectation: 'n/a' }, R_ser: { expectation: 'n/a' }, R_val: { expectation: 'n/a' }, R_err: { expectation: 'n/a' }, R_cap: { expectation: 'detect' } },
      stimulusInstances: [{ stimulusInstanceId: 'default', baseFixture: baseFixture() }],
      entries: [{
        relation: 'R_cap', scope: { kind: 'manifest', backend: NODE_WEBCRYPTO_OPENSSL, apiSurface: 'x' },
        resolve: async (ctx) => {
          const onlyExecution = await ctx.runMutation(HKDF_NODE_WEBCRYPTO_ADAPTER);
          return makeRelationObservation({
            applicable: true, context: onlyExecution.context, relation: 'R_cap',
            scope: { kind: 'manifest', backend: NODE_WEBCRYPTO_OPENSSL, apiSurface: 'x' }, status: 'pass',
            participants: [onlyExecution.executionId, onlyExecution.executionId],
            evaluatorId: 'R_cap', basis: 'I5 violation fixture',
          });
        },
      }],
    })],
  };

  await assert.rejects(() => runPhaseC(plan), CapabilityIndependenceViolationError);
});

test("M3.2.3: I5' -- two distinct executions are NOT sufficient; the basis must be disjoint", async () => {
  // INVERTED DELIBERATELY at M3.8.2, with its reason recorded here.
  //
  // The original pin asserted that two distinct executions constituted a
  // genuinely independent R_cap observation. That was OUR invariant, not the
  // freeze's -- 'I5' appears nowhere in Harness v0.26, nor does any demand
  // for two executions. And it checked the wrong property: two identities of
  // ONE mechanism passed it, which is precisely the tautology M3.8.2 found.
  //
  //     two distinct executions      =/=>  valid independence
  //     declarationBasisRef not in participants  ==>  I5' satisfied
  //
  // The frozen rule (M2.3.4) is disjointness over concrete evidence identity.
  // The declared side is grounded in M1 evidence recorded in v0.13 and is not
  // an M4 execution, so it is named by declarationBasisRef rather than
  // executed again.
  const mkPlan = (withBasis: boolean): ExecutionPlan => ({
    classes: [withExec({
      mutation: HKDF_INFO_TAMPER, operation: 'hkdf', gamma0Ref: 'HKDF-INFO-TAMPER',
      applicability: { R_byte: false, R_interop: false, R_ser: false, R_val: false, R_err: false, R_cap: true },
      expectedSpectrum: { R_byte: { expectation: 'n/a' }, R_interop: { expectation: 'n/a' }, R_ser: { expectation: 'n/a' }, R_val: { expectation: 'n/a' }, R_err: { expectation: 'n/a' }, R_cap: { expectation: 'detect' } },
      stimulusInstances: [{ stimulusInstanceId: 'default', baseFixture: baseFixture() }],
      entries: [{
        relation: 'R_cap', scope: { kind: 'manifest', backend: NODE_WEBCRYPTO_OPENSSL, apiSurface: 'x' },
        resolve: async (ctx) => {
          const scored = await ctx.runMutation(HKDF_NODE_WEBCRYPTO_ADAPTER as never);
          return makeRelationObservation({
            applicable: true, context: scored.context, relation: 'R_cap',
            scope: { kind: 'manifest', backend: NODE_WEBCRYPTO_OPENSSL, apiSurface: 'x' }, status: 'pass',
            participants: [scored.executionId],
            ...(withBasis ? { declarationBasisRef: 'manifest:m1-reference-evidence:hkdf.provider.support' } : {}),
            evaluatorId: 'R_cap', basis: 'M3.8.2 I5-prime',
          });
        },
      }],
    })],
  } as unknown as ExecutionPlan);

  // ONE scored execution plus a named declaration basis is accepted: the
  // declared side was never an M4 execution to begin with.
  await assert.doesNotReject(() => runPhaseC(mkPlan(true)));
  // And an observation with no declared side to contrast is refused.
  await assert.rejects(() => runPhaseC(mkPlan(false)), CapabilityIndependenceViolationError);
});

test('M3.2.3: a structurally-not-executable entry is never resolved and never blocks completeness', async () => {
  const plan: ExecutionPlan = {
    classes: [withExec({
      mutation: HKDF_INFO_TAMPER, operation: 'hkdf', gamma0Ref: 'HKDF-INFO-TAMPER',
      applicability: { R_byte: true, R_interop: false, R_ser: false, R_val: false, R_err: false, R_cap: false },
      expectedSpectrum: HKDF_INFO_TAMPER_EXPECTED,
      // M3-H6: executability is now stated PER STIMULUS, so this test names
      // it explicitly rather than relying on a class-level default.
      stimulusInstances: [{
        stimulusInstanceId: 'default', baseFixture: baseFixture(),
        executability: [
          { relation: 'R_byte', scope: { kind: 'single-backend', backend: NODE_WEBCRYPTO_OPENSSL }, state: REQ },
          { relation: 'R_interop', scope: { kind: 'backend-pair', from: NODE_WEBCRYPTO_OPENSSL, to: NODE_WEBCRYPTO_OPENSSL }, state: NX },
        ],
      }],
      entries: [
        makeRByteEntry(),
        {
          relation: 'R_interop', scope: { kind: 'backend-pair', from: NODE_WEBCRYPTO_OPENSSL, to: NODE_WEBCRYPTO_OPENSSL },
          resolve: async () => { throw new Error('must never be called for a structurally-not-executable entry'); },
        },
      ],
    })],
  };

  const result = await runPhaseC(plan);
  assert.equal(result.observations.length, 1, 'only the required R_byte entry was resolved');
  assert.equal(result.instances[0]!.complete, true);
});

// ---------------------------------------------------------------------
// Baseline eligibility policy regression (M3.2.2's own contract clause):
//   NeedBaseline(i,p) <=> p.relation = 'R_byte'
// Previously this lived only in a comment: getBaseline was exposed to every
// PlanEntry's resolve(), so ANY relation could obtain (and thereby reuse) a
// cached baseline. Demonstrated concretely before the fix -- an R_val entry
// successfully obtained a baseline, producing 2 recorded executions where
// the contract requires 1. The cache's entire safety argument rests on the
// R_byte-only restriction (R_byte applies only to deterministic operations,
// so memoizing is indistinguishable from re-executing); any other relation
// receiving a reused baseline would silently break that argument.
// ---------------------------------------------------------------------

function planWithBaselineRequestFrom(relation: PlannedRelationForProbe): ExecutionPlan {
  return {
    classes: [withExec({
      mutation: HKDF_INFO_TAMPER, operation: 'hkdf', gamma0Ref: 'HKDF-INFO-TAMPER',
      applicability: { R_byte: false, R_interop: false, R_ser: false, R_val: true, R_err: true, R_cap: false },
      expectedSpectrum: {
        R_byte: { expectation: 'n/a' }, R_interop: { expectation: 'n/a' }, R_ser: { expectation: 'n/a' },
        R_val: { expectation: 'detect' }, R_err: { expectation: 'detect' }, R_cap: { expectation: 'n/a' },
      },
      stimulusInstances: [{ stimulusInstanceId: 'default', baseFixture: baseFixture() }],
      entries: [{
        relation, scope: { kind: 'single-backend', backend: NODE_WEBCRYPTO_OPENSSL },
        resolve: async (ctx) => {
          await ctx.getBaseline(HKDF_NODE_WEBCRYPTO_ADAPTER); // must be refused
          throw new Error('unreachable: the baseline request should have been refused');
        },
      }],
    })],
  };
}

type PlannedRelationForProbe = 'R_val' | 'R_cap';

test('M3.2.3: NeedBaseline <=> R_byte -- an R_val entry requesting a baseline is refused fail-closed', async () => {
  await assert.rejects(() => runPhaseC(planWithBaselineRequestFrom('R_val')), BaselinePolicyViolationError);
});

test('M3.2.3: NeedBaseline <=> R_byte -- an R_cap entry requesting a baseline is refused fail-closed', async () => {
  // Retargeted from R_err by M3-H13: for HKDF-INFO-TAMPER the contract
  // determines no error class, so R_err is now structurally non-comparable
  // and the runner never resolves it -- which would make this assertion
  // vacuous. R_cap carries the same baseline policy and does resolve.
  await assert.rejects(() => runPhaseC(planWithBaselineRequestFrom('R_cap')), BaselinePolicyViolationError);
});

test('M3.2.3: the declaration-probe primitive is R_cap-only -- an R_val entry requesting one is refused fail-closed', async () => {
  const plan: ExecutionPlan = {
    classes: [withExec({
      mutation: HKDF_INFO_TAMPER, operation: 'hkdf', gamma0Ref: 'HKDF-INFO-TAMPER',
      applicability: { R_byte: false, R_interop: false, R_ser: false, R_val: true, R_err: false, R_cap: false },
      expectedSpectrum: {
        R_byte: { expectation: 'n/a' }, R_interop: { expectation: 'n/a' }, R_ser: { expectation: 'n/a' },
        R_val: { expectation: 'detect' }, R_err: { expectation: 'n/a' }, R_cap: { expectation: 'n/a' },
      },
      stimulusInstances: [{ stimulusInstanceId: 'default', baseFixture: baseFixture() }],
      entries: [{
        relation: 'R_val', scope: { kind: 'single-backend', backend: NODE_WEBCRYPTO_OPENSSL },
        resolve: async (ctx) => {
          await ctx.runDeclarationProbe(
            HKDF_NODE_WEBCRYPTO_ADAPTER,
            baseFixture(),
          ); // must be refused
          throw new Error('unreachable: the declaration-probe request should have been refused');
        },
      }],
    })],
  };
  await assert.rejects(() => runPhaseC(plan), BaselinePolicyViolationError);
});

test("M3.2.3: R_cap's own declaration probe is a FRESH execution, never served from the baseline cache", async () => {
  const plan: ExecutionPlan = {
    classes: [withExec({
      mutation: HKDF_INFO_TAMPER, operation: 'hkdf', gamma0Ref: 'HKDF-INFO-TAMPER',
      applicability: { R_byte: false, R_interop: false, R_ser: false, R_val: false, R_err: false, R_cap: true },
      expectedSpectrum: {
        R_byte: { expectation: 'n/a' }, R_interop: { expectation: 'n/a' }, R_ser: { expectation: 'n/a' },
        R_val: { expectation: 'n/a' }, R_err: { expectation: 'n/a' }, R_cap: { expectation: 'detect' },
      },
      // TWO stimulus instances with the IDENTICAL fixture: if the declaration
      // probe were served from the baseline cache, both instances would share
      // one execution identity. It must not.
      stimulusInstances: [
        { stimulusInstanceId: 's1', baseFixture: baseFixture() },
        { stimulusInstanceId: 's2', baseFixture: baseFixture() },
      ],
      entries: [{
        relation: 'R_cap', scope: { kind: 'manifest', backend: NODE_WEBCRYPTO_OPENSSL, apiSurface: 'x' },
        resolve: async (ctx) => {
          const declaration = await ctx.runDeclarationProbe(
            HKDF_NODE_WEBCRYPTO_ADAPTER,
            baseFixture(),
          );
          const scored = await ctx.runMutation(HKDF_NODE_WEBCRYPTO_ADAPTER);
          return makeRelationObservation({
            applicable: true, context: scored.context, relation: 'R_cap',
            scope: { kind: 'manifest', backend: NODE_WEBCRYPTO_OPENSSL, apiSurface: 'x' }, status: 'pass',
            participants: [declaration.executionId, scored.executionId],
            // I5' still needs a named declared side: this test is about the
            // probe being FRESH, not about what the declaration is.
            declarationBasisRef: 'manifest:m1-reference-evidence:hkdf.provider.support',
            evaluatorId: 'R_cap', basis: 'fresh declaration probe',
          });
        },
      }],
    })],
  };

  const result = await runPhaseC(plan);
  // Two instances x (1 declaration + 1 scored) = 4 distinct executions.
  assert.equal(result.executions.length, 4);
  assert.equal(new Set(result.executions.map((e) => e.executionId)).size, 4, 'every execution identity is distinct -- nothing was reused');
});

// ---------------------------------------------------------------------
// M3-H6: Keys(ExecMap_{c,s}) = Entries_c, enforced fail-closed.
// A missing decision would silently drop a planned observation; a surplus
// one would describe an entry that does not exist. Both are refused.
// ---------------------------------------------------------------------

test('M3-H6: a stimulus with FEWER executability decisions than entries is refused', async () => {
  const plan: ExecutionPlan = {
    classes: [{
      mutation: HKDF_INFO_TAMPER, operation: 'hkdf', gamma0Ref: 'HKDF-INFO-TAMPER',
      applicability: { R_byte: true, R_interop: false, R_ser: false, R_val: false, R_err: false, R_cap: false },
      expectedSpectrum: HKDF_INFO_TAMPER_EXPECTED,
      stimulusInstances: [{ stimulusInstanceId: 'default', baseFixture: baseFixture(), executability: [] }],
      entries: [makeRByteEntry()],
    }],
  };
  await assert.rejects(() => runPhaseC(plan), ExecutabilityPlanMismatchError);
});

test('M3-H6: a stimulus with a decision for an entry that does not exist is refused', async () => {
  const plan: ExecutionPlan = {
    classes: [{
      mutation: HKDF_INFO_TAMPER, operation: 'hkdf', gamma0Ref: 'HKDF-INFO-TAMPER',
      applicability: { R_byte: true, R_interop: false, R_ser: false, R_val: false, R_err: false, R_cap: false },
      expectedSpectrum: HKDF_INFO_TAMPER_EXPECTED,
      stimulusInstances: [{
        stimulusInstanceId: 'default', baseFixture: baseFixture(),
        executability: [
          { relation: 'R_byte', scope: { kind: 'single-backend', backend: NODE_WEBCRYPTO_OPENSSL }, state: REQ },
          { relation: 'R_val', scope: { kind: 'single-backend', backend: NODE_WEBCRYPTO_OPENSSL }, state: REQ },
        ],
      }],
      entries: [makeRByteEntry()],
    }],
  };
  await assert.rejects(() => runPhaseC(plan), ExecutabilityPlanMismatchError);
});

test('M3-H6: two stimuli of one class may carry DIFFERENT executability -- the whole point', async () => {
  const fixture = baseFixture();
  let resolved = 0;
  const plan: ExecutionPlan = {
    classes: [{
      mutation: HKDF_INFO_TAMPER, operation: 'hkdf', gamma0Ref: 'HKDF-INFO-TAMPER',
      applicability: { R_byte: true, R_interop: false, R_ser: false, R_val: false, R_err: false, R_cap: false },
      expectedSpectrum: HKDF_INFO_TAMPER_EXPECTED,
      stimulusInstances: [
        {
          stimulusInstanceId: 'executable-here', baseFixture: fixture,
          executability: [{ relation: 'R_byte', scope: { kind: 'single-backend', backend: NODE_WEBCRYPTO_OPENSSL }, state: REQ }],
        },
        {
          stimulusInstanceId: 'not-executable-here', baseFixture: fixture,
          executability: [{ relation: 'R_byte', scope: { kind: 'single-backend', backend: NODE_WEBCRYPTO_OPENSSL }, state: NX }],
        },
      ],
      entries: [{
        relation: 'R_byte',
        scope: { kind: 'single-backend', backend: NODE_WEBCRYPTO_OPENSSL },
        resolve: async (ctx) => {
          resolved += 1;
          const baseline = await ctx.getBaseline(HKDF_NODE_WEBCRYPTO_ADAPTER);
          const mutated = await ctx.runMutation(HKDF_NODE_WEBCRYPTO_ADAPTER);
          return makeRelationObservation({
            applicable: true, context: mutated.context, relation: 'R_byte',
            scope: { kind: 'single-backend', backend: NODE_WEBCRYPTO_OPENSSL }, status: 'fail',
            participants: [baseline.executionId, mutated.executionId],
            evaluatorId: 'R_byte', basis: 'H6 per-stimulus fixture',
          });
        },
      }],
    }],
  };

  const result = await runPhaseC(plan);
  assert.equal(resolved, 1, 'resolved for the executable stimulus only');
  assert.equal(result.observations.length, 1);
  // Both instances exist and both are complete: the not-executable one is
  // legitimately empty, never a completeness failure.
  assert.equal(result.instances.length, 2);
  for (const i of result.instances) assert.equal(i.complete, true);
});
