import { test } from 'node:test';
import assert from 'node:assert/strict';

import { decideExecutability } from '../../../harness/capability/executability.js';
import { resolveRequirement, HarnessIntegrityError } from '../../../harness/capability/requirement-resolution.js';
import { STIMULUS_CAPABILITY_REQUIREMENTS } from '../../../harness/requirements/stimulus-requirements.js';
import { CHROMIUM_WEBCRYPTO, CRYPTOPP, BOUNCY_CASTLE, type BackendIdentity } from '../../../harness/schema/backend-identity.js';
import { CHROMIUM_DECLARATIONS } from '../../../manifests/providers/chromium.js';
import { CRYPTOPP_DECLARATIONS } from '../../../manifests/providers/cryptopp.js';
import { BC_DECLARATIONS } from '../../../manifests/providers/bc.js';
import type { ProviderCapabilityDeclaration } from '../../../harness/schema/capability.js';

const MANIFESTS: ReadonlyArray<{ backend: BackendIdentity; declarations: readonly ProviderCapabilityDeclaration[] }> = [
  { backend: CHROMIUM_WEBCRYPTO, declarations: CHROMIUM_DECLARATIONS },
  { backend: CRYPTOPP, declarations: CRYPTOPP_DECLARATIONS },
  { backend: BOUNCY_CASTLE, declarations: BC_DECLARATIONS },
];

// No mutationId/backend hardcoding in the TEST's own derivation logic either
// -- this generically asks each manifest, exactly like the planner does.
function executableFamilies(mutationId: string, stimulusInstanceId?: string): string[] {
  return MANIFESTS.filter(({ backend, declarations }) =>
    decideExecutability(mutationId, stimulusInstanceId ?? 'default', backend, declarations, STIMULUS_CAPABILITY_REQUIREMENTS).status === 'executable',
  ).map(({ backend }) => backend.family).sort();
}

const cases: Array<{ mutationId: string; stimulusInstanceId?: string; expected: string[] }> = [
  { mutationId: 'OAEP-MGF-COUPLING-BYPASS', expected: ['bouncycastle'] },
  { mutationId: 'OAEP-RANDOMNESS-INTERFACE-LEAK', expected: ['bouncycastle', 'cryptopp'] },
  { mutationId: 'PSS-MGF-COUPLING-BYPASS', expected: ['bouncycastle'] },
  { mutationId: 'PSS-RNG-INTERFACE-LEAK', expected: ['bouncycastle', 'cryptopp'] },
  { mutationId: 'PSS-SALT-BYTES-INTERFACE-LEAK', expected: ['bouncycastle'] },
  { mutationId: 'PSS-SALTLENGTH-PROFILE-BYPASS', expected: ['bouncycastle', 'chromium'] },
  { mutationId: 'GCM-TAGLENGTH-PROFILE-BOUNDARY-BYPASS', stimulusInstanceId: 'tagLength-80', expected: ['bouncycastle', 'cryptopp'] },
  { mutationId: 'GCM-TAGLENGTH-PROFILE-BOUNDARY-BYPASS', stimulusInstanceId: 'tagLength-below-floor-16', expected: ['cryptopp'] },
  { mutationId: 'GCM-TAGLENGTH-PROFILE-BOUNDARY-BYPASS', stimulusInstanceId: 'tagLength-below-floor-0', expected: ['cryptopp'] },
];

for (const c of cases) {
  test(`Executable(${c.mutationId}${c.stimulusInstanceId ? `, ${c.stimulusInstanceId}` : ''}) reproduced from manifests+requirements alone`, () => {
    assert.deepEqual(executableFamilies(c.mutationId, c.stimulusInstanceId), [...c.expected].sort());
  });
}

test('a mutation with no requirement at all is trivially executable everywhere', () => {
  for (const { backend, declarations } of MANIFESTS) {
    const decision = decideExecutability('HKDF-INFO-TAMPER', 'default', backend, declarations, STIMULUS_CAPABILITY_REQUIREMENTS);
    assert.equal(decision.status, 'executable');
  }
});

test('capability absence produces not-executed/backend-capability-absent, never an exception and never R_cap=fail', () => {
  const decision = decideExecutability('OAEP-MGF-COUPLING-BYPASS', 'default', CHROMIUM_WEBCRYPTO, CHROMIUM_DECLARATIONS, STIMULUS_CAPABILITY_REQUIREMENTS);
  assert.equal(decision.status, 'not-executed');
  if (decision.status === 'not-executed') {
    assert.equal(decision.reason, 'backend-capability-absent');
    assert.equal(decision.unsatisfiedRequirements.length, 1);
  }
});

test('structural: an unresolvable requirement (no matching declaration) is a harness integrity error, not not-executed', () => {
  assert.throws(() => {
    resolveRequirement(
      { mutationId: 'FAKE-MUTATION', capabilityId: 'does.not.exist', requiredCondition: { kind: 'supported' } },
      CHROMIUM_DECLARATIONS,
    );
  }, HarnessIntegrityError);
});

test('structural: a duplicated capabilityId in the manifest is a harness integrity error', () => {
  const duplicated = [...CHROMIUM_DECLARATIONS, CHROMIUM_DECLARATIONS[0]!];
  assert.throws(() => {
    resolveRequirement(
      { mutationId: 'X', capabilityId: CHROMIUM_DECLARATIONS[0]!.capabilityId, requiredCondition: { kind: 'supported' } },
      duplicated,
    );
  }, HarnessIntegrityError);
});

test('structural: an unsatisfied condition resolves cleanly to not-executed, never throws', () => {
  assert.doesNotThrow(() => {
    decideExecutability('PSS-SALTLENGTH-PROFILE-BYPASS', 'default', CRYPTOPP, CRYPTOPP_DECLARATIONS, STIMULUS_CAPABILITY_REQUIREMENTS);
  });
  const decision = decideExecutability('PSS-SALTLENGTH-PROFILE-BYPASS', 'default', CRYPTOPP, CRYPTOPP_DECLARATIONS, STIMULUS_CAPABILITY_REQUIREMENTS);
  assert.equal(decision.status, 'not-executed');
});
