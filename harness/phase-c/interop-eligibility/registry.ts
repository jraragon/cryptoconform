// M3-H9.3a-3.2.5b -- the pre-derived normative registry.
//
// This module is the SOURCE OF TRUTH for InteropEligibility. It is a
// pre-registration, not a computation:
//
//     Registry(c,s) -> InteropEligibility(c,s)
//
// The independent regression probe re-derives the same property from
// fixture -> mutation -> contract and REFUTES this table:
//
//     Derived(c,s) != Registry(c,s)  =>  TEST FAIL
//
// never
//
//     Registry <- Derived
//
// so a recomputation can never quietly become the normative source. That
// asymmetry is the whole point of the M3-H9.3a-3.2 strategy decision: the
// derivation is an independent consistency check, and this file is what it
// checks against.
//
// The `import type` below is erased at compile time; this module has no
// runtime dependency on src/contract/, and neither the assembler nor
// anything on the plan path may acquire one (I_iso).

import type { ClauseId } from '../../../src/contract/clause-ids.js';
import type { InteropEligibility, InteropEligibilityRegistry, ClassEligibilityEntry } from './types.js';

const AUDIT = 'M3-H9.3a-3.2.2 population reconstruction; clause confirmed by direct contractual probe in M3-H9.3a-3.2.5';

const ELIGIBLE: InteropEligibility = Object.freeze({ kind: 'eligible' });

// The fixture carries no operational input at all -- a capability
// declaration {capabilityId, kind, support} or an error-mapping
// intervention {triggeringCondition, declaredErrorClass}. Neither can begin
// a producer-to-consumer flow, so no provenance is claimed: see types.ts.
const NO_OPERATIONAL_INPUT: InteropEligibility = Object.freeze({
  kind: 'non-eligible',
  reason: 'no-operational-input',
});

// Accept_C rejects the MUTATED producer input, so no artifact is ever
// produced and there is nothing for a consumer to receive. Each clause was
// obtained by feeding the real resolved fixture through mutate() into the
// contractual validator that accepts exactly that fixture's type -- no
// coercion, no field extraction (the rule added in H9.3a-1 after a false
// positive). 16/16 produced exactly one clause.
function producerBlocked(clauseId: ClauseId): InteropEligibility {
  return Object.freeze({
    kind: 'non-eligible',
    reason: 'producer-contractually-blocked',
    provenance: Object.freeze({ kind: 'contract-derived', clauseIds: Object.freeze([clauseId]), note: AUDIT }),
  }) as InteropEligibility;
}

const gcm = (mutationId: string, classDefault: InteropEligibility): ClassEligibilityEntry =>
  ({ mutationId, operation: 'gcm', classDefault });
const oaep = (mutationId: string, classDefault: InteropEligibility): ClassEligibilityEntry =>
  ({ mutationId, operation: 'oaep', classDefault });
const pss = (mutationId: string, classDefault: InteropEligibility): ClassEligibilityEntry =>
  ({ mutationId, operation: 'pss', classDefault });
const rsaSer = (mutationId: string, classDefault: InteropEligibility): ClassEligibilityEntry =>
  ({ mutationId, operation: 'rsa-ser', classDefault });
const ecSer = (mutationId: string, classDefault: InteropEligibility): ClassEligibilityEntry =>
  ({ mutationId, operation: 'ec-ser', classDefault });

// ---------------------------------------------------------------------
// HKDF is deliberately ABSENT in its entirety.
//
// Applicability(hkdf, R_interop) = 0, and I_abs refuses any entry for a
// class whose operation does not have the relation. A pseudo-eligibility
// for HKDF's 8 classes / 9 pairs would answer a question the protocol
// never asks -- exactly the Applicability-vs-Eligibility conflation the
// layering audit rejected.
// ---------------------------------------------------------------------

export const INTEROP_ELIGIBILITY_REGISTRY: InteropEligibilityRegistry = Object.freeze([
  // --- AES-GCM: 13 classes, 18 pairs -------------------------------------
  gcm('GCM-PLAINTEXT-NORMALIZATION', ELIGIBLE),
  gcm('GCM-AAD-ABSENT-EMPTY-DIVERGENCE', ELIGIBLE),
  gcm('GCM-AAD-IGNORED', ELIGIBLE),
  gcm('GCM-IV-INTERPRETATION-DIVERGENCE', ELIGIBLE),
  gcm('GCM-CIPHERTEXT-COMPUTATION-DIVERGENCE', ELIGIBLE),
  // All four tamper stimuli rebuild a STRUCTURALLY WELL-FORMED artifact
  // (buildAeadArtifact, correct widths) or perturb the AAD, which is not
  // part of the artifact at all. parseAeadArtifact accepts every one, so
  // the flow exists; whether authentication then fails is R_interop's own
  // expectedOutcome, not an eligibility question.
  gcm('GCM-AUTHENTICATION-BYPASS', ELIGIBLE),
  gcm('GCM-ARTIFACT-C-T-SWAP', ELIGIBLE),
  gcm('GCM-ARTIFACT-STRUCTURE-CORRUPTION', ELIGIBLE),
  gcm('GCM-KEY-PROFILE-BOUNDARY-BYPASS', producerBlocked('gcm.key')),
  gcm('GCM-IV-PROFILE-BOUNDARY-BYPASS', producerBlocked('gcm.iv')),
  // Contract-uniform across all three stimuli even though M3-H6 found them
  // capability-MIXED (Bouncy Castle admits 80 bits, rejects below the
  // floor). The portable profile fixes tagLength at exactly 128, so 80, 16
  // and 0 all fail the same clause. Executability(c,s) and
  // InteropEligibility(c,s) vary independently: this class is the evidence.
  gcm('GCM-TAGLENGTH-PROFILE-BOUNDARY-BYPASS', producerBlocked('gcm.tagLength')),
  gcm('GCM-PROVIDER-CAPABILITY-MISMATCH', NO_OPERATIONAL_INPUT),
  gcm('GCM-ERROR-MISCLASSIFICATION', NO_OPERATIONAL_INPUT),

  // --- RSA-OAEP: 12 classes, 13 pairs ------------------------------------
  oaep('OAEP-MESSAGE-NORMALIZATION', ELIGIBLE),
  oaep('OAEP-CIPHERTEXT-COMPUTATION-DIVERGENCE', ELIGIBLE),
  oaep('OAEP-CIPHERTEXT-LENGTH-DIVERGENCE', ELIGIBLE),
  oaep('OAEP-MODULUS-PROFILE-BYPASS', producerBlocked('oaep.modulus')),
  oaep('OAEP-HASH-PROFILE-BYPASS', producerBlocked('oaep.hash')),
  oaep('OAEP-MGF-COUPLING-BYPASS', producerBlocked('oaep.mgfCoupling')),
  oaep('OAEP-LABEL-PROFILE-BYPASS', producerBlocked('oaep.label')),
  oaep('OAEP-MESSAGE-BOUNDARY-BYPASS', producerBlocked('oaep.message')),
  // THE one genuine override in the whole registry (M3-H9.3a-3.2.1).
  //
  // Both stimuli are rejected with invalid_key citing oaep.key, so no table
  // indexed on (clauseId, errorClass) could tell them apart. What separates
  // them is POSITION in Dec_q(Enc_p(m)):
  //   encrypt-with-private -> the PRODUCER is rejected; no ciphertext is
  //                           ever produced, so no flow exists.
  //   decrypt-with-public  -> the producer is not mutated at all; the
  //                           rejection falls on the CONSUMER. The flow
  //                           exists and its expected outcome is reject.
  // ProducerReject != ConsumerReject is part of R_interop's semantics, and
  // this is the only class in which the two occur under one mutationId.
  {
    ...oaep('OAEP-KEY-ROLE-BYPASS', producerBlocked('oaep.key')),
    stimulusOverrides: Object.freeze({ 'decrypt-with-public': ELIGIBLE }),
  },
  // Interface leaks: the intervention lives outside the portable request
  // (native RNG injection), and the embedded request is provably untouched,
  // so the producer runs and the flow exists.
  oaep('OAEP-RANDOMNESS-INTERFACE-LEAK', ELIGIBLE),
  oaep('OAEP-DECRYPT-ERROR-DISCLOSURE', NO_OPERATIONAL_INPUT),
  oaep('OAEP-PROVIDER-CAPABILITY-MISREPORT', NO_OPERATIONAL_INPUT),

  // --- RSA-PSS: 15 classes, 15 pairs -------------------------------------
  pss('PSS-SIGN-MESSAGE-NORMALIZATION', ELIGIBLE),
  pss('PSS-VERIFY-MESSAGE-NORMALIZATION', ELIGIBLE),
  pss('PSS-SIGNATURE-COMPUTATION-DIVERGENCE', ELIGIBLE),
  pss('PSS-SIGNATURE-LENGTH-DIVERGENCE', ELIGIBLE),
  pss('PSS-MODULUS-PROFILE-BYPASS', producerBlocked('pss.modulus')),
  pss('PSS-HASH-PROFILE-BYPASS', producerBlocked('pss.hash')),
  pss('PSS-MGF-COUPLING-BYPASS', producerBlocked('pss.mgfCoupling')),
  pss('PSS-SALTLENGTH-PROFILE-BYPASS', producerBlocked('pss.saltLength')),
  pss('PSS-KEY-ROLE-BYPASS', producerBlocked('pss.key')),
  pss('PSS-RNG-INTERFACE-LEAK', ELIGIBLE),
  pss('PSS-SALT-BYTES-INTERFACE-LEAK', ELIGIBLE),
  pss('PSS-VERIFICATION-FALSE-ACCEPT', ELIGIBLE),
  pss('PSS-VERIFICATION-FALSE-REJECT', ELIGIBLE),
  pss('PSS-ERROR-MISCLASSIFICATION', NO_OPERATIONAL_INPUT),
  pss('PSS-PROVIDER-CAPABILITY-MISREPORT', NO_OPERATIONAL_INPUT),

  // --- RSA-ser: 17 classes, 21 pairs -------------------------------------
  //
  // NOT ONE producer-blocked class, and that is structural rather than
  // accidental: exportRsaSer is a pure encoder. checkPrivateDomain and
  // checkPrivateRelations live exclusively inside importRsaSer. In the
  // serialization operations the producer has no precondition at all, so
  // every mutation exports successfully and the consumer decides.
  rsaSer('RSA-SER-PUBLIC-MATERIAL-DIVERGENCE', ELIGIBLE),
  rsaSer('RSA-SER-PRIVATE-MATERIAL-DIVERGENCE', ELIGIBLE),
  rsaSer('RSA-SER-DER-IMPORT-BYPASS', ELIGIBLE),
  rsaSer('RSA-SER-DER-EXPORT-DIVERGENCE', ELIGIBLE),
  rsaSer('RSA-SER-CONTAINER-IMPORT-BYPASS', ELIGIBLE),
  rsaSer('RSA-SER-CONTAINER-EXPORT-DIVERGENCE', ELIGIBLE),
  rsaSer('RSA-SER-TRAILING-DATA-BYPASS', ELIGIBLE),
  rsaSer('RSA-SER-ROLE-CONTAINER-BYPASS', ELIGIBLE),
  rsaSer('RSA-SER-OID-IMPORT-PROFILE-BYPASS', ELIGIBLE),
  rsaSer('RSA-SER-OID-EXPORT-DIVERGENCE', ELIGIBLE),
  rsaSer('RSA-SER-PARAMETERS-IMPORT-PROFILE-BYPASS', ELIGIBLE),
  rsaSer('RSA-SER-PARAMETERS-EXPORT-CANONICALIZATION-DIVERGENCE', ELIGIBLE),
  rsaSer('RSA-SER-PUBLIC-VALIDITY-BYPASS', ELIGIBLE),
  rsaSer('RSA-SER-PRIVATE-DOMAIN-BYPASS', ELIGIBLE),
  // All five stimuli export cleanly and are rejected on import by the same
  // clause. Uniform, hence a class default and no override.
  rsaSer('RSA-SER-PRIVATE-RELATIONAL-BYPASS', ELIGIBLE),
  rsaSer('RSA-SER-ERROR-MISCLASSIFICATION', NO_OPERATIONAL_INPUT),
  rsaSer('RSA-SER-PROVIDER-CAPABILITY-MISREPORT', NO_OPERATIONAL_INPUT),

  // --- EC-ser: 14 classes, 14 pairs --------------------------------------
  ecSer('EC-ROLE-CONTAINER-MISMATCH', ELIGIBLE),
  ecSer('EC-CURVE-SUBSTITUTION', ELIGIBLE),
  ecSer('EC-PUBLIC-POINT-ENCODING', ELIGIBLE),
  ecSer('EC-PUBLIC-OFF-CURVE', ELIGIBLE),
  ecSer('EC-PRIVATE-SCALAR-RANGE', ELIGIBLE),
  ecSer('EC-PRIVATE-PAIR-MISMATCH', ELIGIBLE),
  ecSer('EC-PUBLIC-DER-MALFORMED', ELIGIBLE),
  ecSer('EC-PRIVATE-DER-MALFORMED', ELIGIBLE),
  ecSer('EC-PRIVATE-PARAMS-ABSENT', ELIGIBLE),
  ecSer('EC-PRIVATE-PARAMS-MISMATCH', ELIGIBLE),
  ecSer('EC-PRIVATE-PUBKEY-ABSENT', ELIGIBLE),
  ecSer('EC-NATIVE-EXPORT-LEAK', ELIGIBLE),
  ecSer('EC-ERROR-MAP-SWAP', NO_OPERATIONAL_INPUT),
  ecSer('EC-CAPABILITY-MANIFEST-MISMATCH', NO_OPERATIONAL_INPUT),
]);
