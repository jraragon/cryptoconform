// M2.4.2 -- static materialization only.
// Source: Paper_4_Experimental_Harness v0.21, §10.2-§10.6.

import type { ProviderCapabilityDeclaration, CapabilityDeclarationBasisRef } from '../../harness/schema/capability.js';
import { BOUNCY_CASTLE } from '../../harness/schema/backend-identity.js';

const m1 = (sectionRef: string, evidenceRef?: string): CapabilityDeclarationBasisRef => ({
  kind: 'm1-reference-evidence',
  documentId: 'paper4-experimental-evidence-base', version: 'v0.13', sectionRef,
  evidenceRef, contentHash: 'PENDING-M2.4.2-HASH-STEP',
});
const doc = (sourceRef: string, sourceType: 'specification' | 'source-code' | 'api-documentation' = 'source-code'): CapabilityDeclarationBasisRef => ({
  kind: 'backend-documentation', sourceType, sourceRef, versionOrPin: BOUNCY_CASTLE.sourcePin,
});

// Bouncy Castle: 32 <= t <= 128 bits, t mod 8 = 0.
const BC_TAG_LENGTHS = [32, 40, 48, 56, 64, 72, 80, 88, 96, 104, 112, 120, 128];

export const BC_DECLARATIONS: readonly ProviderCapabilityDeclaration[] = Object.freeze([
  { capabilityId: 'hkdf.provider.support', operation: 'hkdf', kind: 'provider-support', usage: 'r-cap-claim', apiSurface: 'bc-java-lightweight-and-jca', support: 'supported', clauseIds: ['hkdf.cap'], basis: m1('15', 'HKDF x Bouncy Castle closed') },
  { capabilityId: 'gcm.provider.support', operation: 'gcm', kind: 'provider-support', usage: 'r-cap-claim', apiSurface: 'bc-java-lightweight-and-jca', support: 'supported', clauseIds: ['gcm.cap.provider'], basis: m1('16', 'AES-GCM x Bouncy Castle 7/7 check groups') },
  { capabilityId: 'gcm.provider.tag-length-range', operation: 'gcm', kind: 'provider-domain', usage: 'both', apiSurface: 'bc-java-lightweight-and-jca', supportedDomain: { kind: 'integer-set', values: BC_TAG_LENGTHS, unit: 'bits' }, clauseIds: ['gcm.tagLength', 'gcm.cap.provider'], basis: doc('bc-java source, v0.6 tag-length matrix') },
  { capabilityId: 'oaep.provider.support', operation: 'oaep', kind: 'provider-support', usage: 'r-cap-claim', apiSurface: 'bc-java-lightweight-and-jca', support: 'supported', clauseIds: ['oaep.cap.provider'], basis: m1('17', 'RSA-OAEP x Bouncy Castle 10/10 check groups') },
  { capabilityId: 'oaep.provider.independent-mgf-hash', operation: 'oaep', kind: 'provider-support', usage: 'both', apiSurface: 'bc-java-lightweight-and-jca', support: 'supported', clauseIds: ['oaep.mgfCoupling'], basis: doc('Bouncy Castle is the only backend whose native API can represent H_OAEP != H_MGF1 (4-argument constructor accepting two independent Digest objects)') },
  { capabilityId: 'oaep.provider.external-randomness-control', operation: 'oaep', kind: 'provider-support', usage: 'both', apiSurface: 'bc-java-lightweight-and-jca', support: 'supported', clauseIds: ['oaep.randomness'], basis: doc('Registry confirms OAEP-RANDOMNESS-INTERFACE-LEAK executable against Crypto++/Bouncy Castle') },
  { capabilityId: 'pss.provider.support', operation: 'pss', kind: 'provider-support', usage: 'r-cap-claim', apiSurface: 'bc-java-lightweight-and-jca', support: 'supported', clauseIds: ['pss.cap.provider'], basis: m1('18', 'RSA-PSS x Bouncy Castle 7/7') },
  { capabilityId: 'pss.provider.independent-mgf-hash', operation: 'pss', kind: 'provider-support', usage: 'both', apiSurface: 'bc-java-lightweight-and-jca', support: 'supported', clauseIds: ['pss.mgfCoupling'], basis: doc('Bouncy Castle is also the only backend whose native API can represent H_PSS != H_MGF1 (4-argument PSSSigner constructor)') },
  { capabilityId: 'pss.provider.rng-control', operation: 'pss', kind: 'provider-support', usage: 'both', apiSurface: 'bc-java-lightweight-and-jca', support: 'supported', clauseIds: ['pss.rngControl'], basis: doc('Registry confirms PSS-RNG-INTERFACE-LEAK executable against Crypto++/Bouncy Castle') },
  { capabilityId: 'pss.provider.explicit-salt-bytes', operation: 'pss', kind: 'provider-support', usage: 'both', apiSurface: 'bc-java-lightweight-and-jca', support: 'supported', clauseIds: ['pss.saltBytes'], basis: doc('D-042, explicitly scoped to recent versions of BC -- confirmed applicable to this exact pinned jar, not to Bouncy Castle in general; kept distinct from rng-control per D-048') },
  { capabilityId: 'pss.provider.variable-salt-length', operation: 'pss', kind: 'provider-support', usage: 'both', apiSurface: 'bc-java-lightweight-and-jca', support: 'supported', clauseIds: ['pss.saltLength'], basis: doc('D-041: WebCrypto/Bouncy Castle runtime-flexible') },
  { capabilityId: 'rsa-ser.provider.support', operation: 'rsa-ser', kind: 'provider-support', usage: 'r-cap-claim', apiSurface: 'bc-java-lightweight-and-jca', support: 'supported', clauseIds: ['cap'], basis: m1('19', 'RSA-ser x Bouncy Castle 8/8, R1 reproduced (v0.13 §21)') },
  { capabilityId: 'ec-ser.provider.support', operation: 'ec-ser', kind: 'provider-support', usage: 'r-cap-claim', apiSurface: 'bc-java-lightweight-and-jca', support: 'supported', clauseIds: ['ec-ser.cap'], basis: m1('20', 'EC-ser x Bouncy Castle 9/9, R2 reproduced (v0.13 §21)') },
]);

export const BC_MANIFEST_ID = 'provider-cap-manifest-bc';
export const BC_MANIFEST_VERSION = 'v1.0';
