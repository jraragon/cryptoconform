// M2.4.2 -- static materialization only.
// Source: Paper_4_Experimental_Harness v0.21, §10.2 (HKDF), §10.3 (GCM),
// §10.4 (OAEP), §10.5 (PSS), §10.6 (RSA-ser/EC-ser).

import type { ProviderCapabilityDeclaration, CapabilityDeclarationBasisRef } from '../../harness/schema/capability.js';
import { CHROMIUM_WEBCRYPTO } from '../../harness/schema/backend-identity.js';

const m1 = (sectionRef: string, evidenceRef?: string): CapabilityDeclarationBasisRef => ({
  kind: 'm1-reference-evidence',
  documentId: 'paper4-experimental-evidence-base', version: 'v0.13', sectionRef,
  evidenceRef, contentHash: 'PENDING-M2.4.2-HASH-STEP',
});
const doc = (sourceRef: string, sourceType: 'specification' | 'source-code' | 'api-documentation' = 'specification'): CapabilityDeclarationBasisRef => ({
  kind: 'backend-documentation', sourceType, sourceRef, versionOrPin: CHROMIUM_WEBCRYPTO.sourcePin,
});

export const CHROMIUM_DECLARATIONS: readonly ProviderCapabilityDeclaration[] = Object.freeze([
  { capabilityId: 'hkdf.provider.support', operation: 'hkdf', kind: 'provider-support', usage: 'r-cap-claim', apiSurface: 'webcrypto-subtlecrypto', support: 'supported', clauseIds: ['hkdf.cap'], basis: m1('15', 'HKDF x WebCrypto 14/14') },
  { capabilityId: 'gcm.provider.support', operation: 'gcm', kind: 'provider-support', usage: 'r-cap-claim', apiSurface: 'webcrypto-subtlecrypto', support: 'supported', clauseIds: ['gcm.cap.provider'], basis: m1('16', 'AES-GCM x WebCrypto 14/14') },
  { capabilityId: 'gcm.provider.tag-length-range', operation: 'gcm', kind: 'provider-domain', usage: 'both', apiSurface: 'webcrypto-subtlecrypto', supportedDomain: { kind: 'integer-set', values: [32, 64, 96, 104, 112, 120, 128], unit: 'bits' }, clauseIds: ['gcm.tagLength', 'gcm.cap.provider'], basis: doc('W3C WebCrypto spec, tagLength discrete set') },
  { capabilityId: 'oaep.provider.support', operation: 'oaep', kind: 'provider-support', usage: 'r-cap-claim', apiSurface: 'webcrypto-subtlecrypto', support: 'supported', clauseIds: ['oaep.cap.provider'], basis: m1('17', 'RSA-OAEP x WebCrypto 14/14') },
  { capabilityId: 'oaep.provider.independent-mgf-hash', operation: 'oaep', kind: 'provider-support', usage: 'both', apiSurface: 'webcrypto-subtlecrypto', support: 'unsupported', clauseIds: ['oaep.mgfCoupling'], basis: doc("W3C WebCrypto's OAEP API exposes a single hash parameter, no independent MGF digest choice") },
  { capabilityId: 'oaep.provider.external-randomness-control', operation: 'oaep', kind: 'provider-support', usage: 'both', apiSurface: 'webcrypto-subtlecrypto', support: 'unsupported', clauseIds: ['oaep.randomness'], basis: doc("subtle.encrypt's OAEP path exposes no seed/RNG parameter in the W3C API surface") },
  { capabilityId: 'pss.provider.support', operation: 'pss', kind: 'provider-support', usage: 'r-cap-claim', apiSurface: 'webcrypto-subtlecrypto', support: 'supported', clauseIds: ['pss.cap.provider'], basis: m1('18', 'RSA-PSS x WebCrypto 11/11') },
  { capabilityId: 'pss.provider.independent-mgf-hash', operation: 'pss', kind: 'provider-support', usage: 'both', apiSurface: 'webcrypto-subtlecrypto', support: 'unsupported', clauseIds: ['pss.mgfCoupling'], basis: doc("W3C WebCrypto's PSS API exposes a single hash parameter, no independent MGF digest choice") },
  { capabilityId: 'pss.provider.rng-control', operation: 'pss', kind: 'provider-support', usage: 'both', apiSurface: 'webcrypto-subtlecrypto', support: 'unsupported', clauseIds: ['pss.rngControl'], basis: doc("subtle.sign's PSS path exposes no seed/RNG parameter in the W3C API surface") },
  { capabilityId: 'pss.provider.explicit-salt-bytes', operation: 'pss', kind: 'provider-support', usage: 'both', apiSurface: 'webcrypto-subtlecrypto', support: 'unsupported', clauseIds: ['pss.saltBytes'], basis: doc('W3C PSS API has no explicit-salt-bytes parameter') },
  { capabilityId: 'pss.provider.variable-salt-length', operation: 'pss', kind: 'provider-support', usage: 'both', apiSurface: 'webcrypto-subtlecrypto', support: 'supported', clauseIds: ['pss.saltLength'], basis: doc('D-041: WebCrypto/Bouncy Castle runtime-flexible, Crypto++ fixed at hLen') },
  { capabilityId: 'rsa-ser.provider.support', operation: 'rsa-ser', kind: 'provider-support', usage: 'r-cap-claim', apiSurface: 'webcrypto-subtlecrypto', support: 'supported', clauseIds: ['cap'], basis: m1('19', 'RSA-ser x WebCrypto 11/11') },
  { capabilityId: 'ec-ser.provider.support', operation: 'ec-ser', kind: 'provider-support', usage: 'r-cap-claim', apiSurface: 'webcrypto-subtlecrypto', support: 'supported', clauseIds: ['ec-ser.cap'], basis: m1('20', 'EC-ser x Chromium 10/10') },
]);

export const CHROMIUM_MANIFEST_ID = 'provider-cap-manifest-chromium';
export const CHROMIUM_MANIFEST_VERSION = 'v1.0';
