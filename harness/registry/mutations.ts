// M2.4.2 -- static materialization only. Metadata for all 79 frozen
// mutation classes. NO mutate() bodies -- that is M2.4.6's own deliverable.
// Source: Paper_4_Experimental_Harness v0.21, §2 (audited: 8+13+12+15+17+14=79,
// GCM's own 13-vs-"12" discrepancy resolved in favor of the literal table, §2.1).
//
// M2.4.6a correction: every entry now also carries a first-pass
// MutationMechanism classification (request/adapter/capability/artifact
// transform). This is metadata only -- it changes neither gamma0 nor
// mutationId for any of the 79 classes. Classification is exact and
// implementation-verified for HKDF (all 8); for the remaining five
// families it is a reasoned first pass, to be re-audited when each family
// is actually implemented (M2.4.6a's own stated scope).

import type { MutationRegistryEntry, ExpectedRelationSpec, MutationMechanism } from '../schema/registry-types.js';

const NA: ExpectedRelationSpec = { expectation: 'n/a' };
const NX: ExpectedRelationSpec = { expectation: 'not-expected' };
const DET: ExpectedRelationSpec = { expectation: 'detect' };
const cond = (condition: string): ExpectedRelationSpec => ({ expectation: 'conditional', condition });

function entry(
  mutationId: string,
  operation: MutationRegistryEntry['operation'],
  gamma0: string[],
  mechanism: MutationMechanism,
  spectrum: Partial<MutationRegistryEntry['expectedSpectrum']>,
  stimulusInstances: string[] = ['default'],
  notes?: string,
): MutationRegistryEntry {
  return {
    mutationId,
    operation,
    gamma0,
    mechanism,
    expectedSpectrum: {
      R_byte: NX, R_interop: NX, R_ser: NX, R_val: NX, R_err: NX, R_cap: NX,
      ...spectrum,
    },
    stimulusInstances: stimulusInstances.map((id) => ({ stimulusInstanceId: id, description: id })),
    notes,
  };
}

export const MUTATION_REGISTRY: readonly MutationRegistryEntry[] = Object.freeze([
  // ---------------- HKDF (8) ----------------
  entry('HKDF-NULL-VS-EMPTY-SALT', 'hkdf', ['hkdf.salt', 'hkdf.output'], 'request-transform',
    { R_byte: DET, R_val: cond('only if a backend rejects one case') }),
  entry('HKDF-INFO-TAMPER', 'hkdf', ['hkdf.info', 'hkdf.output'], 'request-transform', { R_byte: DET }),
  entry('HKDF-IKM-NORMALIZATION', 'hkdf', ['hkdf.ikm', 'hkdf.output'], 'request-transform', { R_byte: DET }),
  entry('HKDF-HASH-MISMATCH', 'hkdf', ['hkdf.hash', 'hkdf.output', 'hkdf.cap'], 'adapter-transform', { R_byte: DET, R_cap: DET }),
  entry('HKDF-LENGTH-WITHIN-DOMAIN-PERTURBATION', 'hkdf', ['hkdf.length', 'hkdf.output'], 'request-transform', { R_byte: DET }),
  entry('HKDF-LENGTH-BOUNDARY-CROSSING', 'hkdf', ['hkdf.length', 'hkdf.validation', 'hkdf.error'], 'request-transform',
    { R_val: DET, R_err: DET }, ['L=0', 'L=8161']),
  entry('HKDF-UNSUPPORTED-HASH-DECLARATION', 'hkdf', ['hkdf.hash', 'hkdf.cap', 'hkdf.validation', 'hkdf.error'], 'adapter-transform',
    { R_cap: DET, R_val: DET, R_err: DET }),
  entry('HKDF-CAPABILITY-BOUNDARY-MISMATCH', 'hkdf', ['hkdf.cap', 'hkdf.validation', 'hkdf.error'], 'capability-transform',
    { R_cap: DET, R_val: DET, R_err: DET }),

  // ---------------- AES-GCM (13) ----------------
  entry('GCM-PLAINTEXT-NORMALIZATION', 'gcm', ['gcm.plaintext', 'gcm.ciphertext'], 'request-transform', { R_byte: DET, R_interop: DET }),
  entry('GCM-AAD-ABSENT-EMPTY-DIVERGENCE', 'gcm', ['gcm.aad'], 'request-transform', { R_byte: DET }),
  entry('GCM-AAD-IGNORED', 'gcm', ['gcm.aad', 'gcm.authentication'], 'request-transform', { R_interop: DET }),
  entry('GCM-IV-INTERPRETATION-DIVERGENCE', 'gcm', ['gcm.iv', 'gcm.ciphertext'], 'request-transform', { R_byte: DET }),
  entry('GCM-CIPHERTEXT-COMPUTATION-DIVERGENCE', 'gcm', ['gcm.ciphertext'], 'request-transform', { R_byte: DET }),
  entry('GCM-AUTHENTICATION-BYPASS', 'gcm', ['gcm.authentication', 'gcm.validation'], 'artifact-transform',
    { R_val: DET, R_interop: cond('cross-provider authenticated decryption only') },
    ['TAG-TAMPER', 'AAD-TAMPER', 'IV-TAMPER', 'CIPHERTEXT-TAMPER']),
  entry('GCM-ARTIFACT-C-T-SWAP', 'gcm', ['gcm.artifact'], 'artifact-transform', { R_ser: DET }),
  entry('GCM-ARTIFACT-STRUCTURE-CORRUPTION', 'gcm', ['gcm.artifact', 'gcm.validation'], 'artifact-transform', { R_ser: DET, R_val: DET }),
  entry('GCM-KEY-PROFILE-BOUNDARY-BYPASS', 'gcm', ['gcm.key', 'gcm.validation', 'gcm.cap.portable'], 'request-transform', { R_val: DET, R_cap: DET }),
  entry('GCM-IV-PROFILE-BOUNDARY-BYPASS', 'gcm', ['gcm.iv', 'gcm.validation', 'gcm.cap.portable'], 'request-transform', { R_val: DET, R_cap: DET }),
  entry('GCM-TAGLENGTH-PROFILE-BOUNDARY-BYPASS', 'gcm', ['gcm.tagLength', 'gcm.validation', 'gcm.cap.portable'], 'request-transform',
    { R_val: DET, R_cap: DET }, ['tagLength-80', 'tagLength-below-floor-16', 'tagLength-below-floor-0']),
  entry('GCM-PROVIDER-CAPABILITY-MISMATCH', 'gcm', ['gcm.cap.provider'], 'capability-transform', { R_cap: DET }),
  entry('GCM-ERROR-MISCLASSIFICATION', 'gcm', ['gcm.error'], 'adapter-transform', { R_err: DET }),

  // ---------------- RSA-OAEP (12) ----------------
  entry('OAEP-MESSAGE-NORMALIZATION', 'oaep', ['oaep.message', 'oaep.ciphertext'], 'request-transform', { R_interop: DET }),
  entry('OAEP-CIPHERTEXT-COMPUTATION-DIVERGENCE', 'oaep', ['oaep.ciphertext'], 'request-transform', { R_interop: DET }),
  entry('OAEP-CIPHERTEXT-LENGTH-DIVERGENCE', 'oaep', ['oaep.ciphertextLength'], 'request-transform', { R_interop: DET }),
  entry('OAEP-MODULUS-PROFILE-BYPASS', 'oaep', ['oaep.modulus', 'oaep.validation', 'oaep.cap.portable'], 'request-transform', { R_val: DET, R_cap: DET }),
  entry('OAEP-HASH-PROFILE-BYPASS', 'oaep', ['oaep.hash', 'oaep.validation', 'oaep.cap.portable'], 'request-transform', { R_val: DET, R_cap: DET }),
  entry('OAEP-MGF-COUPLING-BYPASS', 'oaep', ['oaep.mgfCoupling', 'oaep.validation', 'oaep.cap.portable'], 'request-transform',
    { R_val: DET, R_cap: DET }, ['default'], 'Materially executable only against Bouncy Castle'),
  entry('OAEP-LABEL-PROFILE-BYPASS', 'oaep', ['oaep.label', 'oaep.validation', 'oaep.cap.portable'], 'request-transform', { R_val: DET, R_cap: DET }),
  entry('OAEP-MESSAGE-BOUNDARY-BYPASS', 'oaep', ['oaep.message', 'oaep.validation'], 'request-transform', { R_val: DET }),
  entry('OAEP-KEY-ROLE-BYPASS', 'oaep', ['oaep.key', 'oaep.validation'], 'request-transform', { R_val: DET },
    ['encrypt-with-private', 'decrypt-with-public']),
  entry('OAEP-RANDOMNESS-INTERFACE-LEAK', 'oaep', ['oaep.randomness', 'oaep.cap.portable'], 'adapter-transform', { R_cap: DET },
    ['default'], 'Materially executable only against Crypto++/Bouncy Castle'),
  entry('OAEP-DECRYPT-ERROR-DISCLOSURE', 'oaep', ['oaep.error'], 'adapter-transform', { R_err: DET }),
  entry('OAEP-PROVIDER-CAPABILITY-MISREPORT', 'oaep', ['oaep.cap.provider'], 'capability-transform', { R_cap: DET }),

  // ---------------- RSA-PSS (15) ----------------
  entry('PSS-SIGN-MESSAGE-NORMALIZATION', 'pss', ['pss.message', 'pss.signature'], 'request-transform', { R_interop: DET }),
  entry('PSS-VERIFY-MESSAGE-NORMALIZATION', 'pss', ['pss.message', 'pss.verification'], 'request-transform', { R_interop: DET }),
  entry('PSS-SIGNATURE-COMPUTATION-DIVERGENCE', 'pss', ['pss.signature'], 'request-transform', { R_interop: DET }),
  entry('PSS-SIGNATURE-LENGTH-DIVERGENCE', 'pss', ['pss.signatureLength'], 'request-transform', { R_interop: DET }),
  entry('PSS-MODULUS-PROFILE-BYPASS', 'pss', ['pss.modulus', 'pss.validation', 'pss.cap.portable'], 'request-transform', { R_val: DET, R_cap: DET }),
  entry('PSS-HASH-PROFILE-BYPASS', 'pss', ['pss.hash', 'pss.validation', 'pss.cap.portable'], 'request-transform', { R_val: DET, R_cap: DET }),
  entry('PSS-MGF-COUPLING-BYPASS', 'pss', ['pss.mgfCoupling', 'pss.validation', 'pss.cap.portable'], 'request-transform',
    { R_val: DET, R_cap: DET }, ['default'], 'Materially executable only against Bouncy Castle (D-040)'),
  entry('PSS-SALTLENGTH-PROFILE-BYPASS', 'pss', ['pss.saltLength', 'pss.validation', 'pss.cap.portable'], 'request-transform',
    { R_val: DET, R_cap: DET }, ['default'], 'Materially executable only against Chromium/WebCrypto and Bouncy Castle (D-041, derived)'),
  entry('PSS-KEY-ROLE-BYPASS', 'pss', ['pss.key', 'pss.validation'], 'request-transform', { R_val: DET }),
  entry('PSS-RNG-INTERFACE-LEAK', 'pss', ['pss.rngControl', 'pss.cap.portable'], 'adapter-transform', { R_cap: DET },
    ['default'], 'Materially executable only against Crypto++/Bouncy Castle'),
  entry('PSS-SALT-BYTES-INTERFACE-LEAK', 'pss', ['pss.saltBytes', 'pss.cap.portable'], 'adapter-transform', { R_cap: DET },
    ['default'], 'Materially executable only against Bouncy Castle, recent versions (D-042)'),
  entry('PSS-VERIFICATION-FALSE-ACCEPT', 'pss', ['pss.verification'], 'artifact-transform', { R_val: DET }),
  entry('PSS-VERIFICATION-FALSE-REJECT', 'pss', ['pss.verification'], 'artifact-transform', { R_interop: DET, R_val: DET }),
  entry('PSS-ERROR-MISCLASSIFICATION', 'pss', ['pss.error'], 'adapter-transform', { R_err: DET }),
  entry('PSS-PROVIDER-CAPABILITY-MISREPORT', 'pss', ['pss.cap.provider'], 'capability-transform', { R_cap: DET }),

  // ---------------- RSA-ser (17) ----------------
  entry('RSA-SER-PUBLIC-MATERIAL-DIVERGENCE', 'rsa-ser', ['public-material'], 'artifact-transform', { R_ser: DET, R_interop: cond('conditional on cross-provider export/import chain') }),
  entry('RSA-SER-PRIVATE-MATERIAL-DIVERGENCE', 'rsa-ser', ['private-material'], 'artifact-transform', { R_ser: DET, R_interop: cond('conditional on cross-provider export/import chain') }),
  entry('RSA-SER-DER-IMPORT-BYPASS', 'rsa-ser', ['der-syntax'], 'artifact-transform', { R_val: DET }),
  entry('RSA-SER-DER-EXPORT-DIVERGENCE', 'rsa-ser', ['der-syntax'], 'artifact-transform', { R_ser: DET }),
  entry('RSA-SER-CONTAINER-IMPORT-BYPASS', 'rsa-ser', ['container'], 'artifact-transform', { R_val: DET }),
  entry('RSA-SER-CONTAINER-EXPORT-DIVERGENCE', 'rsa-ser', ['container'], 'artifact-transform', { R_ser: DET }),
  entry('RSA-SER-TRAILING-DATA-BYPASS', 'rsa-ser', ['exact-consumption'], 'artifact-transform', { R_val: DET }),
  entry('RSA-SER-ROLE-CONTAINER-BYPASS', 'rsa-ser', ['role-container'], 'artifact-transform', { R_val: DET }),
  entry('RSA-SER-OID-IMPORT-PROFILE-BYPASS', 'rsa-ser', ['algorithm-id'], 'artifact-transform', { R_val: DET }),
  entry('RSA-SER-OID-EXPORT-DIVERGENCE', 'rsa-ser', ['algorithm-id'], 'artifact-transform', { R_ser: DET }),
  entry('RSA-SER-PARAMETERS-IMPORT-PROFILE-BYPASS', 'rsa-ser', ['algorithm-params'], 'artifact-transform', { R_val: DET }),
  entry('RSA-SER-PARAMETERS-EXPORT-CANONICALIZATION-DIVERGENCE', 'rsa-ser', ['algorithm-params'], 'artifact-transform', { R_ser: DET }),
  entry('RSA-SER-PUBLIC-VALIDITY-BYPASS', 'rsa-ser', ['public-validity'], 'artifact-transform', { R_val: DET }),
  entry('RSA-SER-PRIVATE-DOMAIN-BYPASS', 'rsa-ser', ['private-domain'], 'artifact-transform', { R_val: DET }),
  entry('RSA-SER-PRIVATE-RELATIONAL-BYPASS', 'rsa-ser', ['private-relations'], 'artifact-transform', { R_val: DET },
    ['n-neq-pq', 'ed-not-1', 'edP-not-1', 'edQ-not-1', 'qqInv-not-1']),
  entry('RSA-SER-ERROR-MISCLASSIFICATION', 'rsa-ser', ['error'], 'adapter-transform', { R_err: DET }),
  entry('RSA-SER-PROVIDER-CAPABILITY-MISREPORT', 'rsa-ser', ['cap'], 'capability-transform', { R_cap: DET }),

  // ---------------- EC-ser (14) ----------------
  entry('EC-ROLE-CONTAINER-MISMATCH', 'ec-ser', ['ec-ser.key.role', 'ec-ser.validation.semantic', 'ec-ser.error'], 'artifact-transform', { R_val: DET, R_err: DET }),
  entry('EC-CURVE-SUBSTITUTION', 'ec-ser', ['ec-ser.curve', 'ec-ser.public.asn1-or-private.asn1', 'ec-ser.validation.semantic', 'ec-ser.error'], 'artifact-transform', { R_val: DET, R_err: DET }),
  entry('EC-PUBLIC-POINT-ENCODING', 'ec-ser', ['ec-ser.public.point', 'ec-ser.validation.semantic', 'ec-ser.error'], 'artifact-transform', { R_val: DET, R_err: DET }),
  entry('EC-PUBLIC-OFF-CURVE', 'ec-ser', ['ec-ser.curveMembership', 'ec-ser.validation.semantic', 'ec-ser.error'], 'artifact-transform', { R_val: DET, R_err: DET }),
  entry('EC-PRIVATE-SCALAR-RANGE', 'ec-ser', ['ec-ser.private.scalar', 'ec-ser.validation.semantic', 'ec-ser.error'], 'artifact-transform', { R_val: DET, R_err: DET }),
  entry('EC-PRIVATE-PAIR-MISMATCH', 'ec-ser', ['ec-ser.pairConsistency', 'ec-ser.validation.semantic', 'ec-ser.error'], 'artifact-transform', { R_val: DET, R_err: DET }),
  entry('EC-PUBLIC-DER-MALFORMED', 'ec-ser', ['ec-ser.public.asn1', 'ec-ser.validation.syntax', 'ec-ser.error'], 'artifact-transform', { R_val: DET, R_err: DET }),
  entry('EC-PRIVATE-DER-MALFORMED', 'ec-ser', ['ec-ser.private.asn1', 'ec-ser.validation.syntax', 'ec-ser.error'], 'artifact-transform', { R_val: DET, R_err: DET }),
  entry('EC-PRIVATE-PARAMS-ABSENT', 'ec-ser', ['ec-ser.validation.semantic', 'ec-ser.export'], 'artifact-transform', { R_val: DET, R_ser: DET },
    ['default'], 'NOT ec-ser.private.asn1 -- corrected before freeze, microaudit'),
  entry('EC-PRIVATE-PARAMS-MISMATCH', 'ec-ser', ['ec-ser.curve', 'ec-ser.private.asn1', 'ec-ser.validation.semantic', 'ec-ser.error'], 'artifact-transform', { R_val: DET, R_err: DET }),
  entry('EC-PRIVATE-PUBKEY-ABSENT', 'ec-ser', ['ec-ser.private.asn1', 'ec-ser.validation.semantic', 'ec-ser.error'], 'artifact-transform', { R_val: DET, R_err: DET }),
  entry('EC-NATIVE-EXPORT-LEAK', 'ec-ser', ['ec-ser.export', 'ec-ser.public.asn1-or-private.asn1'], 'adapter-transform', { R_ser: DET }),
  entry('EC-ERROR-MAP-SWAP', 'ec-ser', ['ec-ser.error'], 'adapter-transform', { R_err: DET }),
  entry('EC-CAPABILITY-MANIFEST-MISMATCH', 'ec-ser', ['ec-ser.cap'], 'capability-transform', { R_cap: DET }),
]);
