// M2.4.2 closure audit: re-derive Executable(p,s) purely from the
// materialized provider manifests + requirements, and check the result
// against the ten checksums already frozen in Paper_4_Experimental_Harness
// v0.21 (§8.4, §10.4, §10.5, §9.3). No `if (backend === ...)` anywhere --
// generic over ALL_BACKENDS.
import type { AuditResult } from './cardinality.js';
import { CHROMIUM_WEBCRYPTO, CRYPTOPP, BOUNCY_CASTLE, type BackendIdentity } from '../schema/backend-identity.js';
import type { ProviderCapabilityDeclaration } from '../schema/capability.js';
import { STIMULUS_CAPABILITY_REQUIREMENTS, type ProviderCapabilityCondition } from '../requirements/stimulus-requirements.js';
import { CHROMIUM_DECLARATIONS } from '../../manifests/providers/chromium.js';
import { CRYPTOPP_DECLARATIONS } from '../../manifests/providers/cryptopp.js';
import { BC_DECLARATIONS } from '../../manifests/providers/bc.js';

// The only place backend identity and its declaration set are paired --
// generic lookup, never a per-backend branch in the logic below.
const MANIFESTS: ReadonlyArray<{ backend: BackendIdentity; declarations: readonly ProviderCapabilityDeclaration[] }> = [
  { backend: CHROMIUM_WEBCRYPTO, declarations: CHROMIUM_DECLARATIONS },
  { backend: CRYPTOPP, declarations: CRYPTOPP_DECLARATIONS },
  { backend: BOUNCY_CASTLE, declarations: BC_DECLARATIONS },
];

function satisfies(decl: ProviderCapabilityDeclaration | undefined, condition: ProviderCapabilityCondition): boolean {
  if (!decl) return false;
  switch (condition.kind) {
    case 'supported':
    case 'control-available':
      return decl.kind === 'provider-support' && decl.support === 'supported';
    case 'domain-includes':
      return decl.kind === 'provider-domain' && decl.supportedDomain.kind === 'integer-set'
        && decl.supportedDomain.values.includes(condition.value as number);
    default:
      return false;
  }
}

// Executable(p,s) = AND over kappa in Requirements(s) of Satisfies(A_p^pre, kappa)
function executableBackendsFor(mutationId: string, stimulusInstanceId?: string): string[] {
  const requirements = STIMULUS_CAPABILITY_REQUIREMENTS.filter(
    (r) => r.mutationId === mutationId && (stimulusInstanceId === undefined || r.stimulusInstanceId === stimulusInstanceId),
  );
  return MANIFESTS.filter(({ declarations }) =>
    requirements.every((r) => satisfies(declarations.find((d) => d.capabilityId === r.capabilityId), r.requiredCondition)),
  ).map(({ backend }) => backend.family);
}

export function auditExecutabilityRederivation(): AuditResult[] {
  // Ten checksums frozen across §8.4 (six), §10.4/§10.5 (four OAEP/PSS
  // re-confirmations already folded into the same six), and §9.3 (three
  // GCM per-instance). Listed here as (mutationId, stimulusInstanceId?, expectedFamilies).
  const checks: Array<{ mutationId: string; stimulusInstanceId?: string; expected: string[] }> = [
    { mutationId: 'OAEP-MGF-COUPLING-BYPASS', expected: ['bouncycastle'] },
    { mutationId: 'OAEP-RANDOMNESS-INTERFACE-LEAK', expected: ['cryptopp', 'bouncycastle'] },
    { mutationId: 'PSS-MGF-COUPLING-BYPASS', expected: ['bouncycastle'] },
    { mutationId: 'PSS-RNG-INTERFACE-LEAK', expected: ['cryptopp', 'bouncycastle'] },
    { mutationId: 'PSS-SALT-BYTES-INTERFACE-LEAK', expected: ['bouncycastle'] },
    { mutationId: 'PSS-SALTLENGTH-PROFILE-BYPASS', expected: ['chromium', 'bouncycastle'] },
    { mutationId: 'GCM-TAGLENGTH-PROFILE-BOUNDARY-BYPASS', stimulusInstanceId: 'tagLength-80', expected: ['cryptopp', 'bouncycastle'] },
    { mutationId: 'GCM-TAGLENGTH-PROFILE-BOUNDARY-BYPASS', stimulusInstanceId: 'tagLength-below-floor-16', expected: ['cryptopp'] },
    { mutationId: 'GCM-TAGLENGTH-PROFILE-BOUNDARY-BYPASS', stimulusInstanceId: 'tagLength-below-floor-0', expected: ['cryptopp'] },
  ];

  return checks.map(({ mutationId, stimulusInstanceId, expected }) => {
    const derived = executableBackendsFor(mutationId, stimulusInstanceId).sort();
    const expectedSorted = [...expected].sort();
    const pass = JSON.stringify(derived) === JSON.stringify(expectedSorted);
    return {
      name: `Executable(${mutationId}${stimulusInstanceId ? `, ${stimulusInstanceId}` : ''})`,
      pass,
      detail: `derived=${JSON.stringify(derived)} expected=${JSON.stringify(expectedSorted)}`,
    };
  });
}
