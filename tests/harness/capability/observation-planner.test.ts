import { test } from 'node:test';
import assert from 'node:assert/strict';
import { planObservations } from '../../../harness/capability/observation-planner.js';
import { APPLICABILITY_MATRIX } from '../../../harness/applicability/matrix.js';
import { CHROMIUM_WEBCRYPTO, CRYPTOPP, BOUNCY_CASTLE } from '../../../harness/schema/backend-identity.js';

const BACKENDS = [CHROMIUM_WEBCRYPTO, CRYPTOPP, BOUNCY_CASTLE];

test('HKDF: R_interop and R_ser are structurally absent, never a fabricated n/a entry', () => {
  const { planned } = planObservations('hkdf', APPLICABILITY_MATRIX.hkdf, BACKENDS);
  const relations = new Set(planned.map((p) => p.relation));
  assert.ok(!relations.has('R_interop'), 'R_interop must be structurally absent for HKDF');
  assert.ok(!relations.has('R_ser'), 'R_ser must be structurally absent for HKDF');
  assert.ok(relations.has('R_byte'));
  assert.ok(relations.has('R_val'));
});

test('GCM (all six applicable): every relation produces at least one planned observation', () => {
  const { planned } = planObservations('gcm', APPLICABILITY_MATRIX.gcm, BACKENDS);
  const relations = new Set(planned.map((p) => p.relation));
  assert.equal(relations.size, 6);
});

test('R_interop plans BOTH directions independently, never collapsed, and excludes self-pairs', () => {
  const { planned } = planObservations('gcm', APPLICABILITY_MATRIX.gcm, BACKENDS);
  const interop = planned.filter((p) => p.relation === 'R_interop');
  // 3 backends, all ordered pairs excluding self: 3*2 = 6.
  assert.equal(interop.length, 6);
  const pairs = interop.map((p) => {
    if (p.scope.kind !== 'backend-pair') throw new Error('expected backend-pair scope');
    return `${p.scope.from.family}->${p.scope.to.family}`;
  });
  assert.ok(pairs.includes('chromium->cryptopp'));
  assert.ok(pairs.includes('cryptopp->chromium'));
  assert.notEqual(pairs.includes('chromium->cryptopp'), false);
  // No self-pair (Phase A's own local round-trip, not a scored R_interop observation).
  assert.ok(!pairs.some((p) => p.split('->')[0] === p.split('->')[1]));
});

test('R_cap plans one manifest-scope observation per backend, and resolves the claim source without evaluating it', () => {
  let resolvedCount = 0;
  const { planned, capabilityClaimResolutions } = planObservations('gcm', APPLICABILITY_MATRIX.gcm, BACKENDS, (backend) => {
    resolvedCount += 1;
    return { kind: 'provider-manifest', manifestId: `provider-cap-manifest-${backend.family}`, manifestVersion: 'v1.0', contentHash: 'x', backend };
  });
  const capObservations = planned.filter((p) => p.relation === 'R_cap');
  assert.equal(capObservations.length, 3);
  assert.equal(resolvedCount, 3);
  assert.equal(capabilityClaimResolutions.size, 3);
  // The resolution is a DeclarationSourceRef, never a declared===observed verdict.
  for (const source of capabilityClaimResolutions.values()) {
    assert.equal(source.kind, 'provider-manifest');
    assert.ok(!('observed' in source));
  }
});
