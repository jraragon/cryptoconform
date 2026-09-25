// M2.4.2 -- static materialization only.
// Source: Paper_4_Experimental_Harness v0.21, §8.4 (six backend-restricted
// requirements) and §9.3 (GCM per-instance microaudit correction, three more).

export type ProviderCapabilityCondition =
  | { readonly kind: 'supported' }
  | { readonly kind: 'domain-includes'; readonly value: unknown }
  | { readonly kind: 'control-available' };

export interface StimulusCapabilityRequirement {
  readonly mutationId: string;
  readonly stimulusInstanceId?: string;
  readonly capabilityId: string;
  readonly requiredCondition: ProviderCapabilityCondition;
}

export const STIMULUS_CAPABILITY_REQUIREMENTS: readonly StimulusCapabilityRequirement[] = Object.freeze([
  // -- Six explicit/derived requirements, §8.4 --
  {
    mutationId: 'OAEP-MGF-COUPLING-BYPASS',
    capabilityId: 'oaep.provider.independent-mgf-hash',
    requiredCondition: { kind: 'control-available' },
  },
  {
    mutationId: 'OAEP-RANDOMNESS-INTERFACE-LEAK',
    capabilityId: 'oaep.provider.external-randomness-control',
    requiredCondition: { kind: 'control-available' },
  },
  {
    mutationId: 'PSS-MGF-COUPLING-BYPASS',
    capabilityId: 'pss.provider.independent-mgf-hash',
    requiredCondition: { kind: 'control-available' },
  },
  {
    mutationId: 'PSS-RNG-INTERFACE-LEAK',
    capabilityId: 'pss.provider.rng-control',
    requiredCondition: { kind: 'control-available' },
  },
  {
    mutationId: 'PSS-SALT-BYTES-INTERFACE-LEAK',
    capabilityId: 'pss.provider.explicit-salt-bytes',
    requiredCondition: { kind: 'control-available' },
  },
  {
    mutationId: 'PSS-SALTLENGTH-PROFILE-BYPASS',
    capabilityId: 'pss.provider.variable-salt-length',
    requiredCondition: { kind: 'control-available' },
  },
  // -- Three per-instance GCM tag-length requirements, §9.3 microaudit --
  {
    mutationId: 'GCM-TAGLENGTH-PROFILE-BOUNDARY-BYPASS',
    stimulusInstanceId: 'tagLength-80',
    capabilityId: 'gcm.provider.tag-length-range',
    requiredCondition: { kind: 'domain-includes', value: 80 },
  },
  {
    mutationId: 'GCM-TAGLENGTH-PROFILE-BOUNDARY-BYPASS',
    stimulusInstanceId: 'tagLength-below-floor-16',
    capabilityId: 'gcm.provider.tag-length-range',
    requiredCondition: { kind: 'domain-includes', value: 16 },
  },
  {
    mutationId: 'GCM-TAGLENGTH-PROFILE-BOUNDARY-BYPASS',
    stimulusInstanceId: 'tagLength-below-floor-0',
    capabilityId: 'gcm.provider.tag-length-range',
    requiredCondition: { kind: 'domain-includes', value: 0 },
  },
]);
