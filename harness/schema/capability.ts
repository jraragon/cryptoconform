// M2.4.2 -- static materialization only. No behavior here.
// Source: Paper_4_Experimental_Harness v0.21, §5.17 (R_cap spec),
// §11 (M2.3.4 provenance/basis), §7 (M2.3.2 portable), §9-10 (M2.3.3 provider).

import type { BackendIdentity } from './backend-identity.js';

export type CapabilityId = string;
export type ClauseId = string;
export type OperationId =
  | 'hkdf' | 'gcm' | 'oaep' | 'pss' | 'rsa-ser' | 'ec-ser';

// Frozen: exactly three kinds, R_cap's own space (§7.2 / §9). Unchanged by
// the manifest's internal 'provider-domain' schema-only refinement (§9.3).
export type CapabilityKind =
  | 'portable-boundary'
  | 'interface-exposure'
  | 'provider-support';

// --- Declaration source (M2.3-first-principle, §9.1) -------------------
export type CapabilityDeclarationSourceRef =
  | {
      readonly kind: 'portable-profile';
      readonly profileId: string;
      readonly profileVersion: string;
      readonly contentHash: string;
    }
  | {
      readonly kind: 'provider-manifest';
      readonly manifestId: string;
      readonly manifestVersion: string;
      readonly contentHash: string;
      readonly backend: BackendIdentity;
    };

// --- Basis (M2.3.4, §11.1) ----------------------------------------------
export type CapabilityDeclarationBasisRef =
  | {
      readonly kind: 'frozen-contract';
      readonly documentId: string;
      readonly version: string;
      readonly sectionRef: string;
      readonly contentHash: string;
    }
  | {
      readonly kind: 'm1-reference-evidence';
      readonly documentId: string;
      readonly version: string;
      readonly sectionRef: string;
      readonly evidenceRef?: string;
      readonly contentHash: string;
    }
  | {
      readonly kind: 'backend-documentation';
      readonly sourceType: 'specification' | 'source-code' | 'api-documentation';
      readonly sourceRef: string;
      readonly versionOrPin?: string;
      readonly sectionOrSymbol?: string;
      readonly contentHash?: string;
    }
  | {
      readonly kind: 'pre-mutation-probe';
      readonly probeId: string;
      readonly executionRef: string;
    };

// --- Portable declarations (M2.3.2, §7) ---------------------------------
export type CapabilityDomainSpec =
  | { readonly kind: 'enum'; readonly values: readonly string[] }
  | { readonly kind: 'integer-set'; readonly values: readonly number[]; readonly unit?: string }
  | { readonly kind: 'fixed-bytes'; readonly length: number }
  | { readonly kind: 'coupled-parameters'; readonly constraints: readonly string[] }
  | { readonly kind: 'constant'; readonly value: unknown };

export type PortableCapabilityDeclaration =
  | {
      readonly capabilityId: CapabilityId;
      readonly operation: OperationId;
      readonly kind: 'portable-boundary';
      readonly apiSurface: 'sdk-portable';
      readonly admittedDomain: CapabilityDomainSpec;
      readonly clauseIds: readonly ClauseId[];
      readonly exercisedBy: readonly string[];
    }
  | {
      readonly capabilityId: CapabilityId;
      readonly operation: OperationId;
      readonly kind: 'interface-exposure';
      readonly apiSurface: 'sdk-portable';
      readonly state: 'exposed' | 'not-exposed';
      readonly clauseIds: readonly ClauseId[];
      readonly exercisedBy: readonly string[];
    };

// --- Provider declarations (M2.3.3, §9-10) ------------------------------
export type ProviderCapabilityUsage = 'r-cap-claim' | 'execution-planning' | 'both';

export type ProviderCapabilityDeclaration =
  | {
      readonly capabilityId: CapabilityId;
      readonly operation: OperationId;
      readonly kind: 'provider-support';
      readonly usage: ProviderCapabilityUsage;
      readonly apiSurface: string;
      readonly support: 'supported' | 'unsupported';
      readonly clauseIds: readonly ClauseId[];
      readonly basis: CapabilityDeclarationBasisRef;
    }
  | {
      readonly capabilityId: CapabilityId;
      readonly operation: OperationId;
      readonly kind: 'provider-domain';
      readonly usage: 'execution-planning' | 'both';
      readonly apiSurface: string;
      readonly supportedDomain: CapabilityDomainSpec;
      readonly clauseIds: readonly ClauseId[];
      readonly basis: CapabilityDeclarationBasisRef;
    };

// Observation-side shadow of CapabilityDeclaration -- structurally
// identical, deliberately renamed so an observation is never mistaken for
// a declared source of truth (§9.2 / R_cap spec).
export type ObservedCapabilityState =
  | { readonly kind: 'portable-boundary'; readonly state: 'allowed' | 'forbidden' }
  | { readonly kind: 'interface-exposure'; readonly state: 'exposed' | 'not-exposed' }
  | { readonly kind: 'provider-support'; readonly state: 'supported' | 'unsupported' };
