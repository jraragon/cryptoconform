// M3.9-B -- the frozen capability manifest, materialised.
//
// TRANSCRIPTION, not research. M2.3.3b-I fixed the closed inventory of 13
// capabilityIds -- each with kind, usage and a necessity column naming the
// mutation class requiring it -- under two guards:
//
//     no evidence => no declaration          no inference by symmetry
//
// and M2.3.3b-II filled every backend cell, closing at 13/13 declarations and
// 39/39 manifest cells. Both are frozen in Experimental Harness v0.26.
//
// Nothing here is discovered. Gathering provider documentation again would
// risk contradicting frozen values, which is exactly what M2.3.3b-I's
// ordering guard exists to prevent: "discovering a backend is more expressive
// than expected must never be allowed to introduce a new capability
// mid-table".
//
// --- Two bases, and why the distinction is load-bearing -------------------
//
//   m1-reference-evidence   an M1 execution already closed and recorded in
//                           Evidence Base v0.13. Legitimate as a declared
//                           basis precisely because it is never reused as the
//                           M4 observation that will test the declaration --
//                           the frozen independence rule is disjointness over
//                           EVIDENCE IDENTITY, not over mechanism.
//   backend-documentation   a published API surface or specification. Must be
//                           pin-compatible: pss.provider.explicit-salt-bytes
//                           holds for Bouncy Castle only because the pinned
//                           jar falls within D-042's scope, not because the
//                           library supports it.

import type { BackendIdentity } from '../schema/backend-identity.js';
import { BOUNCY_CASTLE, CHROMIUM_WEBCRYPTO, CRYPTOPP } from '../schema/backend-identity.js';
import type { CapabilityDomainSpec, CapabilityKind, OperationId } from '../schema/capability.js';

export class ManifestError extends Error {}

export type BasisKind = 'm1-reference-evidence' | 'backend-documentation';
export type DeclarationUsage = 'r-cap-claim' | 'execution-planning' | 'both';

/** One of the 13 frozen declarations. */
export interface FrozenDeclaration {
  readonly capabilityId: string;
  readonly operation: OperationId;
  /** provider-domain is a schema-only refinement; R_cap's own space is CapabilityKind. */
  readonly kind: CapabilityKind | 'provider-domain';
  readonly usage: DeclarationUsage;
  /**
   * The mutation classes whose existence requires this declaration --
   * M2.3.3b-I's own Necessity column, transcribed. Plural because two rows
   * carry more than one, and because 'no inference by symmetry' is exactly
   * what this column enforces.
   */
  readonly necessity: readonly string[];
}

/** One of the 39 frozen cells. */
export interface FrozenCell {
  readonly capabilityId: string;
  readonly backend: BackendIdentity;
  readonly support?: 'supported' | 'unsupported';
  readonly supportedDomain?: CapabilityDomainSpec;
  readonly basisKind: BasisKind;
  readonly basis: string;
}

const C = CHROMIUM_WEBCRYPTO, P = CRYPTOPP, B = BOUNCY_CASTLE;
const M1 = 'm1-reference-evidence' as const;
const DOC = 'backend-documentation' as const;

export const FROZEN_DECLARATIONS: readonly FrozenDeclaration[] = Object.freeze([
  { capabilityId: 'hkdf.provider.support', operation: 'hkdf', kind: 'provider-support', usage: 'r-cap-claim', necessity: ['HKDF-UNSUPPORTED-HASH-DECLARATION', 'HKDF-CAPABILITY-BOUNDARY-MISMATCH'] },
  { capabilityId: 'gcm.provider.support', operation: 'gcm', kind: 'provider-support', usage: 'r-cap-claim', necessity: ['GCM-PROVIDER-CAPABILITY-MISMATCH'] },
  { capabilityId: 'gcm.provider.tag-length-range', operation: 'gcm', kind: 'provider-domain', usage: 'both', necessity: ['GCM-PROVIDER-CAPABILITY-MISMATCH'] },
  { capabilityId: 'oaep.provider.support', operation: 'oaep', kind: 'provider-support', usage: 'r-cap-claim', necessity: ['OAEP-PROVIDER-CAPABILITY-MISREPORT'] },
  { capabilityId: 'oaep.provider.independent-mgf-hash', operation: 'oaep', kind: 'provider-support', usage: 'both', necessity: ['OAEP-MGF-COUPLING-BYPASS'] },
  { capabilityId: 'oaep.provider.external-randomness-control', operation: 'oaep', kind: 'provider-support', usage: 'both', necessity: ['OAEP-RANDOMNESS-INTERFACE-LEAK'] },
  { capabilityId: 'pss.provider.support', operation: 'pss', kind: 'provider-support', usage: 'r-cap-claim', necessity: ['PSS-PROVIDER-CAPABILITY-MISREPORT'] },
  { capabilityId: 'pss.provider.independent-mgf-hash', operation: 'pss', kind: 'provider-support', usage: 'both', necessity: ['PSS-MGF-COUPLING-BYPASS'] },
  { capabilityId: 'pss.provider.rng-control', operation: 'pss', kind: 'provider-support', usage: 'both', necessity: ['PSS-RNG-INTERFACE-LEAK'] },
  { capabilityId: 'pss.provider.explicit-salt-bytes', operation: 'pss', kind: 'provider-support', usage: 'both', necessity: ['PSS-SALT-BYTES-INTERFACE-LEAK'] },
  { capabilityId: 'pss.provider.variable-salt-length', operation: 'pss', kind: 'provider-support', usage: 'both', necessity: ['PSS-SALTLENGTH-PROFILE-BYPASS'] },
  { capabilityId: 'rsa-ser.provider.support', operation: 'rsa-ser', kind: 'provider-support', usage: 'r-cap-claim', necessity: ['RSA-SER-PROVIDER-CAPABILITY-MISREPORT'] },
  { capabilityId: 'ec-ser.provider.support', operation: 'ec-ser', kind: 'provider-support', usage: 'r-cap-claim', necessity: ['EC-CAPABILITY-MANIFEST-MISMATCH'] },
]);

const support = (
  capabilityId: string, backend: BackendIdentity,
  state: 'supported' | 'unsupported', basisKind: BasisKind, basis: string,
): FrozenCell => ({ capabilityId, backend, support: state, basisKind, basis });

export const FROZEN_CELLS: readonly FrozenCell[] = Object.freeze([
  // hkdf.provider.support -- v0.13 §15, all three adapters closed on the
  // identical seven-check matrix, with cross-provider R_byte agreement on
  // RFC 5869 Test Case 1.
  support('hkdf.provider.support', C, 'supported', M1, 'v0.13 §15, HKDF×WebCrypto closed'),
  support('hkdf.provider.support', P, 'supported', M1, 'v0.13 §15, HKDF×Crypto++ closed'),
  support('hkdf.provider.support', B, 'supported', M1, 'v0.13 §15, HKDF×Bouncy Castle closed'),

  support('gcm.provider.support', C, 'supported', M1, 'v0.13 §16, AES-GCM×WebCrypto, 14/14'),
  support('gcm.provider.support', P, 'supported', M1, 'v0.13 §16, AES-GCM×Crypto++, 7/7 check groups'),
  support('gcm.provider.support', B, 'supported', M1, 'v0.13 §16, AES-GCM×Bouncy Castle, 7/7 check groups'),

  // The single provider-domain declaration. Its richness is a tag-length
  // range, and the three backends genuinely differ.
  {
    capabilityId: 'gcm.provider.tag-length-range', backend: C, basisKind: DOC,
    basis: "W3C WebCrypto spec (tagLength discrete set), v0.6's own tag-length matrix",
    supportedDomain: { kind: 'integer-set', values: [32, 64, 96, 104, 112, 120, 128] },
  },
  {
    capabilityId: 'gcm.provider.tag-length-range', backend: P, basisKind: DOC,
    basis: "ThrowIfInvalidTruncatedSize in Crypto++'s cryptlib.cpp; no GCM-specific floor on the generic API path",
    supportedDomain: { kind: 'integer-set', values: [0, 8, 16, 24, 32, 40, 48, 56, 64, 72, 80, 88, 96, 104, 112, 120, 128] },
  },
  {
    capabilityId: 'gcm.provider.tag-length-range', backend: B, basisKind: DOC,
    basis: "bc-java source, v0.6's own tag-length matrix",
    supportedDomain: { kind: 'integer-set', values: [32, 40, 48, 56, 64, 72, 80, 88, 96, 104, 112, 120, 128] },
  },

  support('oaep.provider.support', C, 'supported', M1, 'v0.13 §17, RSA-OAEP×WebCrypto, 14/14'),
  support('oaep.provider.support', P, 'supported', M1, 'v0.13 §17, RSA-OAEP×Crypto++, 9/9 check groups'),
  support('oaep.provider.support', B, 'supported', M1, 'v0.13 §17, RSA-OAEP×Bouncy Castle, 10/10 check groups'),

  support('oaep.provider.independent-mgf-hash', C, 'unsupported', DOC, "W3C WebCrypto's OAEP API exposes a single hash parameter, no independent MGF digest choice"),
  support('oaep.provider.independent-mgf-hash', P, 'unsupported', DOC, "no decoupled-digest constructor documented for Crypto++'s OAEP path"),
  support('oaep.provider.independent-mgf-hash', B, 'supported', DOC, 'v0.6: the only backend whose native API can represent H_OAEP != H_MGF1'),

  support('oaep.provider.external-randomness-control', C, 'unsupported', DOC, "subtle.encrypt's OAEP path exposes no seed/RNG parameter in the W3C API surface"),
  support('oaep.provider.external-randomness-control', P, 'supported', M1, 'v0.13 §17: RNG injection required by Crypto++\'s own API'),
  support('oaep.provider.external-randomness-control', B, 'supported', DOC, 'registry confirms OAEP-RANDOMNESS-INTERFACE-LEAK executable against Bouncy Castle'),

  support('pss.provider.support', C, 'supported', M1, 'v0.13 §18, RSA-PSS×WebCrypto, 11/11'),
  support('pss.provider.support', P, 'supported', M1, 'v0.13 §18, RSA-PSS×Crypto++, 8/8'),
  support('pss.provider.support', B, 'supported', M1, 'v0.13 §18, RSA-PSS×Bouncy Castle, 7/7'),

  support('pss.provider.independent-mgf-hash', C, 'unsupported', DOC, "W3C WebCrypto's PSS API exposes a single hash parameter"),
  support('pss.provider.independent-mgf-hash', P, 'unsupported', DOC, "no decoupled-digest constructor documented for Crypto++'s PSS path"),
  support('pss.provider.independent-mgf-hash', B, 'supported', DOC, 'v0.6: the only backend whose native API can represent H_PSS != H_MGF1'),

  // Checked independently of OAEP's Crypto++ cell, never assumed by symmetry.
  support('pss.provider.rng-control', C, 'unsupported', DOC, "subtle.sign's PSS path exposes no seed/RNG parameter"),
  support('pss.provider.rng-control', P, 'supported', DOC, 'RSASS<PSS,H>::Signer::Sign() structurally requires a RandomNumberGenerator&'),
  support('pss.provider.rng-control', B, 'supported', DOC, 'registry confirms PSS-RNG-INTERFACE-LEAK executable against Bouncy Castle'),

  support('pss.provider.explicit-salt-bytes', C, 'unsupported', DOC, 'W3C PSS API has no explicit-salt-bytes parameter'),
  support('pss.provider.explicit-salt-bytes', P, 'unsupported', DOC, 'registry confirms this class executable only against Bouncy Castle'),
  // Pin-anchored, deliberately: D-042 is scoped to recent BC versions.
  support('pss.provider.explicit-salt-bytes', B, 'supported', DOC, 'D-042, scoped to recent BC versions -- confirmed applicable to our exact pinned jar'),

  support('pss.provider.variable-salt-length', C, 'supported', DOC, 'D-041: WebCrypto/Bouncy Castle runtime-flexible'),
  support('pss.provider.variable-salt-length', P, 'unsupported', DOC, 'D-041: Crypto++ fixed at hLen on the audited surface'),
  support('pss.provider.variable-salt-length', B, 'supported', DOC, 'D-041: WebCrypto/Bouncy Castle runtime-flexible'),

  support('rsa-ser.provider.support', C, 'supported', M1, 'v0.13 §19, RSA-ser×WebCrypto, 11/11'),
  support('rsa-ser.provider.support', P, 'supported', M1, 'v0.13 §19, RSA-ser×Crypto++, 7/7'),
  support('rsa-ser.provider.support', B, 'supported', M1, 'v0.13 §19, RSA-ser×Bouncy Castle, 8/8'),

  support('ec-ser.provider.support', C, 'supported', M1, 'v0.13 §20, EC-ser×Chromium, 10/10'),
  support('ec-ser.provider.support', P, 'supported', M1, 'v0.13 §20, EC-ser×Crypto++, 8/8'),
  support('ec-ser.provider.support', B, 'supported', M1, 'v0.13 §20, EC-ser×Bouncy Castle, 9/9'),
]);

/** Fail-closed: an undeclared (capability, backend) pair has no cell. */
export function cellFor(capabilityId: string, backend: BackendIdentity): FrozenCell {
  const cell = FROZEN_CELLS.find(
    (c) => c.capabilityId === capabilityId && c.backend.sourcePin === backend.sourcePin,
  );
  if (cell === undefined) {
    throw new ManifestError(
      `No frozen manifest cell for '${capabilityId}' on '${backend.family}'. Absence is not a negative ` +
      'declaration, and no cell may be introduced outside the closed inventory.',
    );
  }
  return cell;
}

/** The declarations an operation contributes. */
export function declarationsFor(operation: OperationId): readonly FrozenDeclaration[] {
  return FROZEN_DECLARATIONS.filter((d) => d.operation === operation);
}

/** Only r-cap-claim and both feed R_cap; execution-planning does not. */
export function rCapClaimsFor(operation: OperationId): readonly FrozenDeclaration[] {
  return declarationsFor(operation).filter((d) => d.usage === 'r-cap-claim' || d.usage === 'both');
}
