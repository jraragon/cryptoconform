// M2.4.2 -- static materialization only.
// Source: Paper_4_Experimental_Harness v0.21, §10.2-§10.6.

import type { ProviderCapabilityDeclaration, CapabilityDeclarationBasisRef } from '../../harness/schema/capability.js';
import { CRYPTOPP } from '../../harness/schema/backend-identity.js';

const m1 = (sectionRef: string, evidenceRef?: string): CapabilityDeclarationBasisRef => ({
  kind: 'm1-reference-evidence',
  documentId: 'paper4-experimental-evidence-base', version: 'v0.13', sectionRef,
  evidenceRef, contentHash: 'PENDING-M2.4.2-HASH-STEP',
});
const doc = (sourceRef: string, sourceType: 'specification' | 'source-code' | 'api-documentation' = 'source-code'): CapabilityDeclarationBasisRef => ({
  kind: 'backend-documentation', sourceType, sourceRef, versionOrPin: CRYPTOPP.sourcePin,
});

// Crypto++'s own generic API path: 0 <= t <= 128 bits, t mod 8 = 0, no GCM-specific floor.
const CRYPTOPP_TAG_LENGTHS = [0, 8, 16, 24, 32, 40, 48, 56, 64, 72, 80, 88, 96, 104, 112, 120, 128];

export const CRYPTOPP_DECLARATIONS: readonly ProviderCapabilityDeclaration[] = Object.freeze([
  { capabilityId: 'hkdf.provider.support', operation: 'hkdf', kind: 'provider-support', usage: 'r-cap-claim', apiSurface: 'cryptopp-generic-api', support: 'supported', clauseIds: ['hkdf.cap'], basis: m1('15', 'HKDF x Crypto++ closed') },
  { capabilityId: 'gcm.provider.support', operation: 'gcm', kind: 'provider-support', usage: 'r-cap-claim', apiSurface: 'cryptopp-generic-api', support: 'supported', clauseIds: ['gcm.cap.provider'], basis: m1('16', 'AES-GCM x Crypto++ 7/7 check groups') },
  { capabilityId: 'gcm.provider.tag-length-range', operation: 'gcm', kind: 'provider-domain', usage: 'both', apiSurface: 'cryptopp-generic-api', supportedDomain: { kind: 'integer-set', values: CRYPTOPP_TAG_LENGTHS, unit: 'bits' }, clauseIds: ['gcm.tagLength', 'gcm.cap.provider'], basis: doc('ThrowIfInvalidTruncatedSize in cryptlib.cpp, confirmed against pinned commit') },
  { capabilityId: 'oaep.provider.support', operation: 'oaep', kind: 'provider-support', usage: 'r-cap-claim', apiSurface: 'cryptopp-generic-api', support: 'supported', clauseIds: ['oaep.cap.provider'], basis: m1('17', 'RSA-OAEP x Crypto++ 9/9 check groups') },
  { capabilityId: 'oaep.provider.independent-mgf-hash', operation: 'oaep', kind: 'provider-support', usage: 'both', apiSurface: 'cryptopp-generic-api', support: 'unsupported', clauseIds: ['oaep.mgfCoupling'], basis: doc('No decoupled-digest constructor documented for OAEP path; registry confirms BC-only executability') },
  { capabilityId: 'oaep.provider.external-randomness-control', operation: 'oaep', kind: 'provider-support', usage: 'both', apiSurface: 'cryptopp-generic-api', support: 'supported', clauseIds: ['oaep.randomness'], basis: m1('17', "RNG injection (RandomNumberGenerator&, required by Crypto++'s own API) is used normally but never surfaces as a request or EvidenceRecord field") },
  { capabilityId: 'pss.provider.support', operation: 'pss', kind: 'provider-support', usage: 'r-cap-claim', apiSurface: 'cryptopp-generic-api', support: 'supported', clauseIds: ['pss.cap.provider'], basis: m1('18', 'RSA-PSS x Crypto++ 8/8') },
  { capabilityId: 'pss.provider.independent-mgf-hash', operation: 'pss', kind: 'provider-support', usage: 'both', apiSurface: 'cryptopp-generic-api', support: 'unsupported', clauseIds: ['pss.mgfCoupling'], basis: doc('No decoupled-digest constructor documented for PSS path; registry confirms BC-only executability, D-040') },
  { capabilityId: 'pss.provider.rng-control', operation: 'pss', kind: 'provider-support', usage: 'both', apiSurface: 'cryptopp-generic-api', support: 'supported', clauseIds: ['pss.rngControl'], basis: doc('RSASS<PSS,H>::Signer::Sign() requires a RandomNumberGenerator& parameter structurally, same API pattern as OAEP Encrypt()') },
  { capabilityId: 'pss.provider.explicit-salt-bytes', operation: 'pss', kind: 'provider-support', usage: 'both', apiSurface: 'cryptopp-generic-api', support: 'unsupported', clauseIds: ['pss.saltBytes'], basis: doc('Registry confirms this class executable only against Bouncy Castle') },
  { capabilityId: 'pss.provider.variable-salt-length', operation: 'pss', kind: 'provider-support', usage: 'both', apiSurface: 'cryptopp-generic-api', support: 'unsupported', clauseIds: ['pss.saltLength'], basis: doc('D-041: fixed at hLen on the audited surface') },
  { capabilityId: 'rsa-ser.provider.support', operation: 'rsa-ser', kind: 'provider-support', usage: 'r-cap-claim', apiSurface: 'cryptopp-generic-api', support: 'supported', clauseIds: ['cap'], basis: m1('19', 'RSA-ser x Crypto++ 7/7, R1 reproduced (v0.13 §21)') },
  { capabilityId: 'ec-ser.provider.support', operation: 'ec-ser', kind: 'provider-support', usage: 'r-cap-claim', apiSurface: 'cryptopp-generic-api', support: 'supported', clauseIds: ['ec-ser.cap'], basis: m1('20', 'EC-ser x Crypto++ 8/8, R2 reproduced (v0.13 §21)') },
]);

export const CRYPTOPP_MANIFEST_ID = 'provider-cap-manifest-cryptopp';
export const CRYPTOPP_MANIFEST_VERSION = 'v1.0';
