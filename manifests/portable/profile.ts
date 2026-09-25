// M2.4.2 -- static materialization only.
// Source: Paper_4_Experimental_Harness v0.21, §7.4 (11 portable-boundary)
// and §7.5 (3 interface-exposure). 14 declarations total. apiSurface is the
// constant 'sdk-portable' throughout -- never a backend name (§7.3).

import type { PortableCapabilityDeclaration } from '../../harness/schema/capability.js';

export const PORTABLE_DECLARATIONS: readonly PortableCapabilityDeclaration[] = Object.freeze([
  // -- GCM: 3 portable-boundary --
  {
    capabilityId: 'gcm.portable.key-profile', operation: 'gcm', kind: 'portable-boundary', apiSurface: 'sdk-portable',
    admittedDomain: { kind: 'fixed-bytes', length: 32 }, // 256-bit AES key
    clauseIds: ['gcm.key'], exercisedBy: ['GCM-KEY-PROFILE-BOUNDARY-BYPASS'],
  },
  {
    capabilityId: 'gcm.portable.iv-profile', operation: 'gcm', kind: 'portable-boundary', apiSurface: 'sdk-portable',
    admittedDomain: { kind: 'fixed-bytes', length: 12 }, // 96-bit IV
    clauseIds: ['gcm.iv'], exercisedBy: ['GCM-IV-PROFILE-BOUNDARY-BYPASS'],
  },
  {
    capabilityId: 'gcm.portable.tag-length-profile', operation: 'gcm', kind: 'portable-boundary', apiSurface: 'sdk-portable',
    admittedDomain: { kind: 'integer-set', values: [128], unit: 'bits' },
    clauseIds: ['gcm.tagLength'], exercisedBy: ['GCM-TAGLENGTH-PROFILE-BOUNDARY-BYPASS'],
  },
  // -- OAEP: 4 portable-boundary + 1 interface-exposure --
  {
    capabilityId: 'oaep.portable.modulus-profile', operation: 'oaep', kind: 'portable-boundary', apiSurface: 'sdk-portable',
    admittedDomain: { kind: 'integer-set', values: [3072], unit: 'bits' },
    clauseIds: ['oaep.modulus'], exercisedBy: ['OAEP-MODULUS-PROFILE-BYPASS'],
  },
  {
    capabilityId: 'oaep.portable.hash-profile', operation: 'oaep', kind: 'portable-boundary', apiSurface: 'sdk-portable',
    admittedDomain: { kind: 'enum', values: ['SHA-256'] },
    clauseIds: ['oaep.hash'], exercisedBy: ['OAEP-HASH-PROFILE-BYPASS'],
  },
  {
    capabilityId: 'oaep.portable.mgf-coupling', operation: 'oaep', kind: 'portable-boundary', apiSurface: 'sdk-portable',
    admittedDomain: { kind: 'coupled-parameters', constraints: ['H_OAEP = H_MGF1'] },
    clauseIds: ['oaep.mgfCoupling'], exercisedBy: ['OAEP-MGF-COUPLING-BYPASS'],
  },
  {
    capabilityId: 'oaep.portable.label-profile', operation: 'oaep', kind: 'portable-boundary', apiSurface: 'sdk-portable',
    admittedDomain: { kind: 'constant', value: '' },
    clauseIds: ['oaep.label'], exercisedBy: ['OAEP-LABEL-PROFILE-BYPASS'],
  },
  {
    capabilityId: 'oaep.portable.randomness-control', operation: 'oaep', kind: 'interface-exposure', apiSurface: 'sdk-portable',
    state: 'not-exposed',
    clauseIds: ['oaep.randomness', 'oaep.cap.portable'], exercisedBy: ['OAEP-RANDOMNESS-INTERFACE-LEAK'],
  },
  // -- PSS: 4 portable-boundary + 2 interface-exposure --
  {
    capabilityId: 'pss.portable.modulus-profile', operation: 'pss', kind: 'portable-boundary', apiSurface: 'sdk-portable',
    admittedDomain: { kind: 'integer-set', values: [3072], unit: 'bits' },
    clauseIds: ['pss.modulus'], exercisedBy: ['PSS-MODULUS-PROFILE-BYPASS'],
  },
  {
    capabilityId: 'pss.portable.hash-profile', operation: 'pss', kind: 'portable-boundary', apiSurface: 'sdk-portable',
    admittedDomain: { kind: 'enum', values: ['SHA-256'] },
    clauseIds: ['pss.hash'], exercisedBy: ['PSS-HASH-PROFILE-BYPASS'],
  },
  {
    capabilityId: 'pss.portable.mgf-coupling', operation: 'pss', kind: 'portable-boundary', apiSurface: 'sdk-portable',
    admittedDomain: { kind: 'coupled-parameters', constraints: ['H_PSS = H_MGF1'] },
    clauseIds: ['pss.mgfCoupling'], exercisedBy: ['PSS-MGF-COUPLING-BYPASS'],
  },
  {
    capabilityId: 'pss.portable.salt-length-profile', operation: 'pss', kind: 'portable-boundary', apiSurface: 'sdk-portable',
    admittedDomain: { kind: 'integer-set', values: [32], unit: 'bytes' }, // = hLen(SHA-256)
    clauseIds: ['pss.saltLength'], exercisedBy: ['PSS-SALTLENGTH-PROFILE-BYPASS'],
  },
  {
    capabilityId: 'pss.portable.rng-control', operation: 'pss', kind: 'interface-exposure', apiSurface: 'sdk-portable',
    state: 'not-exposed',
    clauseIds: ['pss.rngControl', 'pss.cap.portable'], exercisedBy: ['PSS-RNG-INTERFACE-LEAK'],
  },
  {
    capabilityId: 'pss.portable.salt-bytes-control', operation: 'pss', kind: 'interface-exposure', apiSurface: 'sdk-portable',
    state: 'not-exposed',
    clauseIds: ['pss.saltBytes', 'pss.cap.portable'], exercisedBy: ['PSS-SALT-BYTES-INTERFACE-LEAK'],
  },
]);

export const PORTABLE_PROFILE_ID = 'portable-cap-profile';
export const PORTABLE_PROFILE_VERSION = 'v1.0';
