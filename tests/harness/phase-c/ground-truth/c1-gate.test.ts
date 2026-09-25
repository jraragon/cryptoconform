// Bloque C1 -- ground-truth gate.
//
// The independent probe re-derives every contract-anchored entry from
// fixture -> mutation -> contract and REFUTES the table. It never seeds it.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';

import {
  auditGroundTruth, provenanceOf, resolveGroundTruth, GroundTruthError,
} from '../../../../harness/phase-c/ground-truth/resolve.js';
import { GROUND_TRUTH_TABLE } from '../../../../harness/phase-c/ground-truth/table.js';
import { GROUND_TRUTH_RULES } from '../../../../harness/phase-c/ground-truth/types.js';
import { MUTATION_REGISTRY } from '../../../../harness/registry/mutations.js';
import { APPLICABILITY_MATRIX } from '../../../../harness/applicability/matrix.js';
import { resolveInteropEligibility } from '../../../../harness/phase-c/interop-eligibility/resolve.js';
import { loadFrozenMaterialPool } from '../../../../harness/phase-c/material/load.js';
import { getFixtureResolver } from '../../../../harness/phase-c/fixture-index.js';
import { getMutationImplementation } from '../../../../harness/phase-c/mutation-index.js';
import * as HKDF from '../../../../src/contract/hkdf.js';
import * as GCM from '../../../../src/contract/gcm.js';
import * as OAEP from '../../../../src/contract/oaep.js';
import * as PSS from '../../../../src/contract/pss.js';
import * as RSA from '../../../../src/contract/rsa-ser.js';
import * as EC from '../../../../src/contract/ec-ser.js';

const pool = loadFrozenMaterialPool();
// eslint-disable-next-line @typescript-eslint/no-explicit-any
const keys = (v: any) => (v && typeof v === 'object' && !(v instanceof Uint8Array)) ? Object.keys(v).sort().join(',') : typeof v;

// eslint-disable-next-line @typescript-eslint/no-explicit-any
function contractualConsumer(op: string, Fm: any): (() => void) | null {
  const k = keys(Fm);
  if (k === 'capabilityId,kind,support' || k === 'declaredErrorClass,triggeringCondition') return null;
  switch (op) {
    case 'hkdf':
      if (k === 'ikm,info,length,salt') return () => HKDF.validateHkdfRequest(Fm);
      if (k === 'effectiveHash,request') return () => HKDF.validateHkdfRequest(Fm.request);
      break;
    case 'gcm':
      if (k === 'aad,iv,key,plaintext,tagLengthBits') return () => GCM.validateGcmEncryptRequest(Fm);
      if (k === 'aad,artifact') return () => { GCM.parseAeadArtifact(Fm.artifact); GCM.validateGcmDecryptAad(Fm); };
      if (k === 'artifact') return () => { GCM.parseAeadArtifact(Fm.artifact); };
      break;
    case 'oaep':
      if (k === 'hash,key,label,mgfHash,plaintext') return () => OAEP.validateOaepEncryptRequest(Fm);
      if (k === 'kind,request') return Fm.kind === 'encrypt'
        ? () => OAEP.validateOaepEncryptRequest(Fm.request) : () => OAEP.validateOaepDecryptRequest(Fm.request);
      if (k === 'externalRandomnessProvided,request') return () => OAEP.validateOaepEncryptRequest(Fm.request);
      break;
    case 'pss':
      if (k === 'hash,key,message,mgfHash,saltLengthBytes') return () => PSS.validatePssSignRequest(Fm);
      if (k === 'hash,key,message,mgfHash,saltLengthBytes,signature') return () => PSS.validatePssVerifyRequest(Fm);
      if (k === 'kind,request') return Fm.kind === 'sign'
        ? () => PSS.validatePssSignRequest(Fm.request) : () => PSS.validatePssVerifyRequest(Fm.request);
      if (k.includes('explicitSaltBytesProvided')) return () => PSS.validatePssSignRequest(Fm.request);
      break;
    case 'rsa-ser':
      if (k.includes('role') && !k.includes('artifact')) return () => { RSA.importRsaSer(RSA.exportRsaSer(Fm), Fm.role); };
      if (k === 'artifact,requestedRole') return () => { RSA.importRsaSer(Fm.artifact, Fm.requestedRole); };
      if (k === 'artifact') return () => {
        try { RSA.importRsaSer(Fm.artifact, 'private'); } catch (e: unknown) {
          const err = e as { clauseIds?: readonly string[] };
          if ((err.clauseIds ?? []).includes('rsa-ser.role-container')) { RSA.importRsaSer(Fm.artifact, 'public'); return; }
          throw e;
        }
      };
      break;
    case 'ec-ser':
      if (k === 'q,role' || k === 'd,q,role') return () => { EC.importEcSer(EC.exportEcSer(Fm), Fm.role); };
      if (k === 'artifact,requestedRole') return () => { EC.importEcSer(Fm.artifact, Fm.requestedRole); };
      if (k === 'artifact') return () => { try { EC.importEcSer(Fm.artifact, 'private'); } catch { EC.importEcSer(Fm.artifact, 'public'); } };
      if (k === 'adapterReconstructsPubkey,material') return () => { EC.importEcSer(EC.exportEcSer(Fm.material), Fm.material.role); };
      break;
  }
  return null;
}

interface Verdict { readonly decision: 'accept' | 'reject'; readonly errorClass?: string; readonly clauseIds?: readonly string[] }
function derive(mutationId: string, stimulusInstanceId: string, operation: string): Verdict | null {
  const F0 = getFixtureResolver(mutationId, stimulusInstanceId)(mutationId, stimulusInstanceId, pool);
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const Fm = (getMutationImplementation(mutationId) as any).mutate(F0, stimulusInstanceId);
  const consumer = contractualConsumer(operation, Fm);
  if (consumer === null) return null;
  try { consumer(); return { decision: 'accept' }; } catch (e: unknown) {
    const err = e as { errorClass?: string; clauseIds?: readonly string[] };
    if (err.errorClass === undefined) throw e;
    return { decision: 'reject', errorClass: err.errorClass, clauseIds: err.clauseIds ?? [] };
  }
}

// The five entries the contract determines documentarily rather than through
// an executable validator: src/contract holds no cryptographic primitive, so
// the value comes from the frozen clause text, never from a provider.
const CRYPTOGRAPHIC = new Set([
  'GCM-AUTHENTICATION-BYPASS::TAG-TAMPER', 'GCM-AUTHENTICATION-BYPASS::AAD-TAMPER',
  'GCM-AUTHENTICATION-BYPASS::IV-TAMPER', 'GCM-AUTHENTICATION-BYPASS::CIPHERTEXT-TAMPER',
  'GCM-ARTIFACT-C-T-SWAP::default',
]);

// =====================================================================
// Cardinality and the three structural invariants
// =====================================================================

test('C1: 90/90 pairs resolve exactly one row, with no orphans', () => {
  const a = auditGroundTruth();
  assert.equal(a.pairs, 90);
  assert.equal(GROUND_TRUTH_TABLE.size, 90);
});

test('C1: the per-premise counts', () => {
  const a = auditGroundTruth();
  assert.deepEqual(a.expectedValidation, { present: 79, absent: 11, contractDerived: 79, m3Decision: 0 });
  assert.deepEqual(a.errorExpectation, { present: 90, contractDerived: 49, m3Decision: 41 });
  assert.deepEqual(a.checksRequired, { present: 53, both: 47, representationOnly: 6 });
  assert.deepEqual(a.expectedOutcome, { present: 55, absentNonEligible: 26, contractDerived: 31, m3Decision: 24 });
});

test('I-GT2/I-GT3: presence follows the relation, and absence is never a default', () => {
  // auditGroundTruth throws on any violation; this asserts the specific
  // absences are the intended ones rather than merely tolerated.
  const declarative = ['capabilityId,kind,support', 'declaredErrorClass,triggeringCondition'];
  let absent = 0;
  for (const e of MUTATION_REGISTRY) {
    for (const si of e.stimulusInstances) {
      const { row } = resolveGroundTruth(e.mutationId, si.stimulusInstanceId);
      if (row.expectedValidation === undefined) {
        absent += 1;
        const F0 = getFixtureResolver(e.mutationId, si.stimulusInstanceId)(e.mutationId, si.stimulusInstanceId, pool);
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        const Fm = (getMutationImplementation(e.mutationId) as any).mutate(F0, si.stimulusInstanceId);
        assert.ok(declarative.includes(keys(Fm)),
          `${e.mutationId}: expectedValidation absent for a fixture that HAS operational input`);
      }
    }
  }
  assert.equal(absent, 11, '6 capability + 5 error-mapping fixtures');
});

test('a non-eligible pair carries NO expectedOutcome -- no fabricated reject', () => {
  let checked = 0;
  for (const e of MUTATION_REGISTRY) {
    if (!APPLICABILITY_MATRIX[e.operation].R_interop) continue;
    for (const si of e.stimulusInstances) {
      if (resolveInteropEligibility(e.mutationId, si.stimulusInstanceId).eligibility.kind === 'eligible') continue;
      assert.equal(resolveGroundTruth(e.mutationId, si.stimulusInstanceId).row.expectedOutcome, undefined);
      checked += 1;
    }
  }
  assert.equal(checked, 26);
});

// =====================================================================
// The independent probe: Derive != Registry => FAIL
// =====================================================================

test('PROBE: every contract-anchored expectedValidation is reproduced by derivation', () => {
  const mismatches: string[] = [];
  let reproduced = 0;
  for (const e of MUTATION_REGISTRY) {
    for (const si of e.stimulusInstances) {
      const k = `${e.mutationId}::${si.stimulusInstanceId}`;
      const { row } = resolveGroundTruth(e.mutationId, si.stimulusInstanceId);
      if (row.expectedValidation === undefined) continue;
      const v = derive(e.mutationId, si.stimulusInstanceId, e.operation);
      if (v === null) { assert.ok(CRYPTOGRAPHIC.has(k) || row.expectedValidation.decision.kind === 'verified'); continue; }
      const expected = v.decision === 'accept' ? 'accept' : 'reject';
      if (row.expectedValidation.decision.kind !== expected) mismatches.push(`${k}: table=${row.expectedValidation.decision.kind} derived=${expected}`);
      else reproduced += 1;
    }
  }
  assert.deepEqual(mismatches, []);
  assert.equal(reproduced, 77, '33 accept + 44 reject');
});

test('PROBE: every cited rejection clause is the one the contract actually raised', () => {
  let checked = 0;
  for (const e of MUTATION_REGISTRY) {
    for (const si of e.stimulusInstances) {
      const k = `${e.mutationId}::${si.stimulusInstanceId}`;
      if (CRYPTOGRAPHIC.has(k)) continue; // no executable validator; see the documentary test below
      const { row } = resolveGroundTruth(e.mutationId, si.stimulusInstanceId);
      const ee = row.errorExpectation;
      if (ee === undefined || ee.kind !== 'error-expected') continue;
      const v = derive(e.mutationId, si.stimulusInstanceId, e.operation);
      assert.ok(v !== null && v.decision === 'reject', `${k}: table expects an error the contract does not raise`);
      assert.equal(ee.errorClass, v.errorClass, `${k}: error class`);
      assert.deepEqual([...ee.clauseIds], [...(v.clauseIds ?? [])], `${k}: cited clause`);
      checked += 1;
    }
  }
  assert.equal(checked, 44);
});

test('PROBE: no-error-expected is reproduced -- the contract accepts, or there is no input at all', () => {
  let checked = 0;
  for (const e of MUTATION_REGISTRY) {
    for (const si of e.stimulusInstances) {
      const { row } = resolveGroundTruth(e.mutationId, si.stimulusInstanceId);
      const ee = row.errorExpectation;
      if (ee === undefined || ee.kind !== 'no-error-expected') continue;
      const v = derive(e.mutationId, si.stimulusInstanceId, e.operation);
      assert.ok(v === null || v.decision === 'accept',
        `${e.mutationId}: no error expected, yet the contract rejects it`);
      assert.ok(ee.ruleId in GROUND_TRUTH_RULES);
      checked += 1;
    }
  }
  assert.equal(checked, 41);
});

// =====================================================================
// No provider was used as an oracle
// =====================================================================

test('NO ORACLE: neither the table nor the resolver reaches an adapter or a backend', () => {
  for (const f of ['table.ts', 'types.ts', 'resolve.ts']) {
    const src = readFileSync(new URL(`../../../../harness/phase-c/ground-truth/${f}`, import.meta.url), 'utf8');
    for (const forbidden of ['adapters/', 'webcrypto', 'subtle', 'cryptopp', 'bouncycastle', 'BC_JAR', 'native-build', 'playwright']) {
      assert.ok(!src.toLowerCase().includes(forbidden.toLowerCase()), `${f} must not reach for '${forbidden}'`);
    }
  }
});

test('NO ORACLE: the five cryptographic entries rest on the frozen clause, not on execution', () => {
  for (const k of CRYPTOGRAPHIC) {
    const [m, s] = k.split('::') as [string, string];
    const { row } = resolveGroundTruth(m, s);
    assert.equal(row.errorExpectation?.kind, 'error-expected');
    if (row.errorExpectation?.kind !== 'error-expected') throw new Error('unreachable');
    assert.equal(row.errorExpectation.errorClass, 'authentication_failure');
    assert.deepEqual([...row.errorExpectation.clauseIds], ['gcm.authentication']);
    // The stronger statement: the executable contract ACCEPTS these
    // structurally -- parseAeadArtifact passes on a well-formed tampered
    // artifact -- so 'authentication_failure' provably did NOT come from
    // running a validator. It comes from the clause, which says any
    // modification to IV/AAD/C/T must not authenticate. This is
    // ConsumerAccept =/=> NormalOutcome made concrete.
    const e = MUTATION_REGISTRY.find((x) => x.mutationId === m)!;
    const v = derive(m, s, e.operation);
    assert.equal(v?.decision, 'accept', 'structural acceptance');
    assert.equal(row.expectedValidation?.decision.kind, 'accept');
    assert.equal(row.expectedOutcome?.kind, 'reject', 'and the outcome is still a rejection');
  }
});

// =====================================================================
// Provenance discipline
// =====================================================================

test('every premise resolves exactly one provenance kind, and neither can be forged', () => {
  assert.throws(() => provenanceOf({}), /must cite either a clause or a rule/);
  assert.throws(() => provenanceOf({ clauseIds: [] }), /without a clause is unconstructible/);
  assert.throws(() => provenanceOf({ clauseIds: ['gcm.key'], ruleId: 'GT-SER-BOTH' }), /cannot be both/);
  assert.equal(provenanceOf({ clauseIds: ['gcm.key'] }).kind, 'contract-derived');
  assert.equal(provenanceOf({ ruleId: 'GT-SER-BOTH' }).kind, 'm3-normative-decision');
});

test('every rule cited by the table exists and carries a rationale', () => {
  const cited = new Set<string>();
  for (const row of GROUND_TRUTH_TABLE.values()) {
    if (row.errorExpectation?.kind === 'no-error-expected') cited.add(row.errorExpectation.ruleId);
    if (row.checksRequired) cited.add(row.checksRequired.ruleId);
    if (row.expectedOutcome?.kind === 'normal') cited.add(row.expectedOutcome.ruleId);
  }
  for (const r of cited) {
    const rule = GROUND_TRUTH_RULES[r as keyof typeof GROUND_TRUTH_RULES];
    assert.ok(rule !== undefined, `rule ${r} is cited but not stated`);
    assert.ok(rule.rationale.length > 80, `rule ${r} needs a real rationale, not a label`);
  }
  assert.ok(cited.size >= 4);
});

test('checksRequired: the rule first, the exception structural', () => {
  const a = auditGroundTruth();
  assert.equal(a.checksRequired.both, 47, 'GT-SER-BOTH is the default');
  assert.equal(a.checksRequired.representationOnly, 6, 'and the exception is exactly the declarative fixtures');
});

// =====================================================================
// Fail-closed
// =====================================================================

test('an unknown class, an unknown stimulus and a missing row are all refused', () => {
  assert.throws(() => resolveGroundTruth('NOPE', 'default'), /Unknown class/);
  assert.throws(() => resolveGroundTruth('GCM-AAD-IGNORED', 'no-such-stimulus'), /declares no stimulus/);
});

test('the table hard-codes no default and no fallback', () => {
  const src = readFileSync(new URL('../../../../harness/phase-c/ground-truth/resolve.ts', import.meta.url), 'utf8');
  assert.ok(!src.includes('?? {'), 'no silent default');
  assert.ok(src.includes('Refusing to supply a default'));
});
