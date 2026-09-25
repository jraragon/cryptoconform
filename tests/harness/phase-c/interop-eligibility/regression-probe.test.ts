// M3-H9.3a-3.2.5b -- the independent regression probe.
//
//     Derived(c,s) != Registry(c,s)  =>  FAIL
//
// and never Registry <- Derived. This file re-derives InteropEligibility
// from first principles -- resolve the real fixture, run the real mutate(),
// feed the result to the contractual consumer -- and uses the result ONLY
// to refute the pre-registered table. It imports the registry to compare
// against it, never to seed itself, and it writes nothing.
//
// That asymmetry is the whole reason the strategy decision chose a
// pre-derived registry over derive-at-plan-build: if the derivation were
// the source, a change in the contract or in a mutate() would silently
// reshape the plan. Here it makes a test fail loudly instead.
//
// TWO NATURES OF DERIVATION, deliberately kept apart:
//
//   CONTRACTUAL -- for producer-contractually-blocked and for every
//     eligible pair: run Accept_C on the mutated fixture, using the
//     validator that accepts EXACTLY that fixture's type. No coercion, no
//     field extraction: the rule added in H9.3a-1 after three adapter
//     fixtures fed to a request validator tripped a length clause merely
//     because the field was absent.
//
//   STRUCTURAL -- for no-operational-input: no contract is consulted at
//     all, because none governs the claim. The fixture's own shape decides,
//     which is exactly why that state carries no contractual provenance.

import { test } from 'node:test';
import assert from 'node:assert/strict';

import { MUTATION_REGISTRY } from '../../../../harness/registry/mutations.js';
import { loadFrozenMaterialPool } from '../../../../harness/phase-c/material/load.js';
import { getFixtureResolver } from '../../../../harness/phase-c/fixture-index.js';
import { getMutationImplementation } from '../../../../harness/phase-c/mutation-index.js';
import {
  interopApplicablePairs,
  resolveInteropEligibility,
} from '../../../../harness/phase-c/interop-eligibility/resolve.js';
import * as GCM from '../../../../src/contract/gcm.js';
import * as OAEP from '../../../../src/contract/oaep.js';
import * as PSS from '../../../../src/contract/pss.js';
import * as RSA from '../../../../src/contract/rsa-ser.js';
import * as EC from '../../../../src/contract/ec-ser.js';

const pool = loadFrozenMaterialPool();

type DerivedKind = 'eligible' | 'producer-contractually-blocked' | 'no-operational-input';
interface Derived { readonly kind: DerivedKind; readonly clauseIds?: readonly string[]; readonly how: string; }

interface Rejection { readonly clauseIds: readonly string[] }
function attempt(f: () => void): Rejection | undefined {
  try { f(); return undefined; } catch (e: unknown) {
    const err = e as { clauseIds?: readonly string[] };
    if (err.clauseIds === undefined) throw e; // a harness error is not a contractual rejection
    return { clauseIds: err.clauseIds };
  }
}

// eslint-disable-next-line @typescript-eslint/no-explicit-any
function shapeKey(v: any): string {
  return v && typeof v === 'object' && !(v instanceof Uint8Array) ? Object.keys(v).sort().join(',') : typeof v;
}

// --- STRUCTURAL nature -----------------------------------------------
//
// A capability declaration and an error-mapping intervention carry no
// operational input at all, so no producer-to-consumer flow can begin from
// either. Recognised by SHAPE, never by mutationId spelling.
const CAPABILITY_SHAPE = 'capabilityId,kind,support';
const ERROR_MAPPING_SHAPE = 'declaredErrorClass,triggeringCondition';

// eslint-disable-next-line @typescript-eslint/no-explicit-any
function derive(operation: string, Fm: any): Derived {
  const k = shapeKey(Fm);
  if (k === CAPABILITY_SHAPE) return { kind: 'no-operational-input', how: 'structural: capability declaration fixture' };
  if (k === ERROR_MAPPING_SHAPE) return { kind: 'no-operational-input', how: 'structural: error-mapping fixture' };

  const blocked = (r: Rejection): Derived =>
    ({ kind: 'producer-contractually-blocked', clauseIds: r.clauseIds, how: 'contractual: Accept_C rejects the producer input' });
  const flows = (how: string): Derived => ({ kind: 'eligible', how });

  switch (operation) {
    case 'gcm': {
      if (k === 'aad,iv,key,plaintext,tagLengthBits') {
        const r = attempt(() => GCM.validateGcmEncryptRequest(Fm));
        return r ? blocked(r) : flows('contractual: producer accepted, artifact is produced');
      }
      // Artifact-transform: the artifact is supplied, not produced by a
      // mutated producer. Whether authentication then fails is
      // expectedOutcome's question, never eligibility's.
      if (k === 'aad,artifact' || k === 'artifact') return flows('contractual: consumer-side artifact, no producer step to block');
      break;
    }
    case 'oaep': {
      if (k === 'hash,key,label,mgfHash,plaintext') {
        const r = attempt(() => OAEP.validateOaepEncryptRequest(Fm));
        return r ? blocked(r) : flows('contractual: producer accepted');
      }
      if (k === 'kind,request') {
        if (Fm.kind === 'encrypt') {
          const r = attempt(() => OAEP.validateOaepEncryptRequest(Fm.request));
          return r ? blocked(r) : flows('contractual: producer accepted');
        }
        // ProducerReject != ConsumerReject: the producer is not mutated at
        // all here, so the flow exists even though the consumer rejects.
        return flows('contractual: consumer-side request; the producer is unmutated');
      }
      if (k === 'externalRandomnessProvided,request') {
        const r = attempt(() => OAEP.validateOaepEncryptRequest(Fm.request));
        return r ? blocked(r) : flows('contractual: interface leak, embedded request untouched');
      }
      break;
    }
    case 'pss': {
      if (k === 'hash,key,message,mgfHash,saltLengthBytes') {
        const r = attempt(() => PSS.validatePssSignRequest(Fm));
        return r ? blocked(r) : flows('contractual: producer accepted');
      }
      if (k === 'hash,key,message,mgfHash,saltLengthBytes,signature') return flows('contractual: consumer-side verify request');
      if (k === 'kind,request') {
        if (Fm.kind === 'sign') {
          const r = attempt(() => PSS.validatePssSignRequest(Fm.request));
          return r ? blocked(r) : flows('contractual: producer accepted');
        }
        return flows('contractual: consumer-side request; the producer is unmutated');
      }
      if (k.includes('explicitSaltBytesProvided')) {
        const r = attempt(() => PSS.validatePssSignRequest(Fm.request));
        return r ? blocked(r) : flows('contractual: interface leak, embedded request untouched');
      }
      if (k === 'message,signature' || k === 'alternateSignature,message,signature') {
        return flows('contractual: pre-established signature, consumer-side');
      }
      break;
    }
    case 'rsa-ser': {
      // exportRsaSer is a PURE ENCODER: the producer has no precondition at
      // all in the serialization operations, which is why not one of these
      // classes can be producer-blocked.
      if (k.includes('role') && !k.includes('artifact')) {
        const r = attempt(() => { RSA.exportRsaSer(Fm); });
        return r ? blocked(r) : flows('contractual: pure encoder, producer cannot reject');
      }
      if (k === 'artifact' || k === 'artifact,requestedRole') return flows('contractual: consumer-side artifact');
      break;
    }
    case 'ec-ser': {
      if (k === 'q,role' || k === 'd,q,role') {
        const r = attempt(() => { EC.exportEcSer(Fm); });
        return r ? blocked(r) : flows('contractual: pure encoder, producer cannot reject');
      }
      if (k === 'artifact' || k === 'artifact,requestedRole') return flows('contractual: consumer-side artifact');
      if (k === 'adapterReconstructsPubkey,material') {
        const r = attempt(() => { EC.exportEcSer(Fm.material); });
        return r ? blocked(r) : flows('contractual: interface leak, embedded material untouched');
      }
      break;
    }
  }
  // Fail-closed: an unrecognised shape is never quietly called eligible.
  throw new Error(`No valid probe for shape '${k}' in operation '${operation}'; refusing to guess.`);
}

interface ProbeRow {
  readonly mutationId: string;
  readonly stimulusInstanceId: string;
  readonly operation: string;
  readonly derived: Derived;
}

function probeAll(): readonly ProbeRow[] {
  return interopApplicablePairs().map(({ mutationId, stimulusInstanceId }) => {
    const resolver = getFixtureResolver(mutationId, stimulusInstanceId);
    const F0 = resolver(mutationId, stimulusInstanceId, pool);
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const impl = getMutationImplementation(mutationId) as any;
    const Fm = impl.mutate(F0, stimulusInstanceId);
    // The operation comes from the frozen registry, never from the
    // mutationId's spelling: EC-ser's own classes are prefixed 'EC-' while
    // their operation is 'ec-ser', and inferring one from the other would
    // make the probe depend on a naming convention that was never
    // contractual.
    const frozen = MUTATION_REGISTRY.find((e) => e.mutationId === mutationId);
    if (frozen === undefined) throw new Error(`No frozen registry entry for '${mutationId}'.`);
    const operation = frozen.operation;
    return { mutationId, stimulusInstanceId, operation, derived: derive(operation, Fm) };
  });
}

const rows = probeAll();

// ---------------------------------------------------------------------
// The refutation
// ---------------------------------------------------------------------

test('the probe reaches all 81 pairs and guesses at none', () => {
  assert.equal(rows.length, 81);
});

test('Derived(c,s) === Registry(c,s) for every one of the 81 pairs', () => {
  const mismatches: string[] = [];
  for (const row of rows) {
    const registered = resolveInteropEligibility(row.mutationId, row.stimulusInstanceId).eligibility;
    const registeredKind: DerivedKind = registered.kind === 'eligible' ? 'eligible' : registered.reason;
    if (registeredKind !== row.derived.kind) {
      mismatches.push(
        `${row.mutationId}::${row.stimulusInstanceId}  registry=${registeredKind}  derived=${row.derived.kind} (${row.derived.how})`,
      );
    }
  }
  assert.deepEqual(mismatches, [], 'the registry is refuted by an independent derivation');
});

test('the 16 contractual blocks cite exactly the clause the contract actually raised', () => {
  const derivedBlocked = rows.filter((r) => r.derived.kind === 'producer-contractually-blocked');
  assert.equal(derivedBlocked.length, 16);
  for (const row of derivedBlocked) {
    const e = resolveInteropEligibility(row.mutationId, row.stimulusInstanceId).eligibility;
    assert.ok(e.kind === 'non-eligible' && e.reason === 'producer-contractually-blocked');
    if (e.kind !== 'non-eligible' || e.reason !== 'producer-contractually-blocked') throw new Error('unreachable');
    assert.deepEqual(
      [...e.provenance.clauseIds], [...(row.derived.clauseIds ?? [])],
      `${row.mutationId}::${row.stimulusInstanceId}: registered provenance must be the clause the contract raised, ` +
      'not a plausible-looking one',
    );
  }
});

test('the 10 structural cases are derived WITHOUT consulting the contract at all', () => {
  const structural = rows.filter((r) => r.derived.kind === 'no-operational-input');
  assert.equal(structural.length, 10);
  for (const row of structural) {
    assert.ok(row.derived.how.startsWith('structural:'), `${row.mutationId}: must not be contract-derived`);
    assert.equal(row.derived.clauseIds, undefined, `${row.mutationId}: a structural fact cites no clause`);
  }
});

test('the population partition is reproduced by derivation, not merely restated', () => {
  const count = (k: DerivedKind) => rows.filter((r) => r.derived.kind === k).length;
  assert.equal(count('eligible'), 55);
  assert.equal(count('producer-contractually-blocked'), 16);
  assert.equal(count('no-operational-input'), 10);
});

test('the probe is deterministic: a second full derivation agrees with the first', () => {
  const again = probeAll();
  assert.deepEqual(
    again.map((r) => `${r.mutationId}::${r.stimulusInstanceId}::${r.derived.kind}`),
    rows.map((r) => `${r.mutationId}::${r.stimulusInstanceId}::${r.derived.kind}`),
  );
});

test('the two RSA-ser/EC-ser operations produce no producer block at all -- a structural consequence', () => {
  // Not a coincidence worth restating as a constant: exportRsaSer and
  // exportEcSer are pure encoders, and every validity check lives inside
  // the importer. Asserted from the derivation so a future contract change
  // that moved a check to the producer would surface here.
  const serRows = rows.filter((r) => r.operation === 'rsa-ser' || r.operation === 'ec-ser');
  assert.equal(serRows.length, 35);
  assert.equal(serRows.filter((r) => r.derived.kind === 'producer-contractually-blocked').length, 0);
});
