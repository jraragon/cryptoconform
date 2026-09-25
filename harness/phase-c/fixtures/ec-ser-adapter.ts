// M3.2.4b-2.12 -- EC-ser x adapter-transform fixture resolvers.
//
// 2 classes, 2 pairs, TWO shapes -- and the first adapter group in which a
// fixture reaches the frozen material pool DIRECTLY:
//
//   EcNativeExportIntervention   { material: EcPrivateMaterial,
//                                  adapterReconstructsPubkey: boolean }
//   EcSerErrorMappingIntervention { triggeringCondition, declaredErrorClass }
//
// --- Finding 1: "adapter-transform needs no material" was never a law ---
//
// It held for GCM, OAEP, PSS and RSA-ser, and HKDF only reached material
// indirectly, through a composed request. Here EcNativeExportIntervention
// embeds EcPrivateMaterial itself: the intervention is about whether the
// adapter RECONSTRUCTS the public point from the private scalar rather than
// reading the one it was given, and that question is meaningless without a
// real (d, Q) pair. So the fixture carries genuine key material, and H1
// applies in full rather than vacuously.
//
// --- The bytes/bigint boundary, crossed here for the first time ---
//
// The frozen pool stores NORMALIZED BYTES precisely so that width is
// unambiguous (the structural answer to H4). EcPrivateMaterial, being M1
// contract code, uses bigint. The conversion therefore happens HERE, at the
// boundary, and only in the bytes -> bigint direction, which is total and
// loses nothing: a fixed-width byte string has exactly one integer value.
// The reverse direction is the one that was dangerous, and it is not
// performed.
//
// --- Finding 2: the error-mapping shape recurs for a FIFTH operation ---
//
// Identical structure again, and again needing no material. The baseline
// follows the same stage-order argument settled for RSA-ser, applied to
// EC-ser's own validation order:
//     V_scalar (invalid_key) -> V_curve (invalid_membership) -> V_pair (invalid_key)
// A V_pair failure is only REACHED once V_curve has PASSED, so reporting it
// as invalid_membership asserts the point is off-curve when it demonstrably
// satisfied that very check. That is the misclassification D-061's
// "never normalized" discipline exists to prevent.

import type { EcPrivateMaterial } from '../../../src/contract/ec-ser.js';
import { isValidScalar, isOnCurve, isPair } from '../../../src/contract/p256.js';
import type { EcNativeExportIntervention, EcSerErrorMappingIntervention } from '../../mutations/ec-ser.js';
import type { FrozenMaterialPool } from '../material/pool.js';
import type { EcP256KeyPairMaterial } from '../material/schema.js';
import { PHASE_C_MATERIAL_IDS } from '../material/load.js';
import { MUTATION_REGISTRY } from '../../registry/mutations.js';
import { FixtureResolutionError } from './hkdf-request.js';

// A correct adapter uses the public point it was GIVEN; reconstructing it
// from the private scalar is the native shortcut this class exists to
// detect. The unmutated baseline therefore declares no reconstruction.
export const EC_SER_BASELINE_ADAPTER_RECONSTRUCTS_PUBKEY = false;

// Derived from the frozen contract's own validation order (see the header).
export const EC_SER_BASELINE_TRIGGERING_CONDITION = 'public-point-not-derived-from-private-scalar';
export const EC_SER_BASELINE_DECLARED_ERROR_CLASS = 'invalid_key';

const EC_SER_ADAPTER_ENTRIES = MUTATION_REGISTRY.filter(
  (e) => e.operation === 'ec-ser' && e.mechanism === 'adapter-transform',
);

export const EC_SER_ADAPTER_MUTATION_IDS: readonly string[] =
  EC_SER_ADAPTER_ENTRIES.map((e) => e.mutationId).sort();

export const EC_SER_ADAPTER_STIMULUS_PAIRS: readonly (readonly [string, string])[] =
  EC_SER_ADAPTER_ENTRIES
    .flatMap((e) => e.stimulusInstances.map((s) => [e.mutationId, s.stimulusInstanceId] as const))
    .sort((a, b) => (a[0] === b[0] ? a[1].localeCompare(b[1]) : a[0].localeCompare(b[0])));

// Shape selection derived from each class's own frozen Gamma_0: the
// error-mapping class is the one intervening on the operation's error
// clause; the other intervenes on the export path.
function gamma0Of(mutationId: string): readonly string[] {
  return EC_SER_ADAPTER_ENTRIES.find((e) => e.mutationId === mutationId)?.gamma0 ?? [];
}

export function isEcSerErrorMappingClass(mutationId: string): boolean {
  return gamma0Of(mutationId).some((c) => c.endsWith('.error'));
}

function assertRegistered(mutationId: string, stimulusInstanceId: string): void {
  const known = EC_SER_ADAPTER_STIMULUS_PAIRS.some(([m, s]) => m === mutationId && s === stimulusInstanceId);
  if (!known) {
    throw new FixtureResolutionError(
      `(${mutationId}, ${stimulusInstanceId}) is not a registered ec-ser x adapter-transform stimulus pair.`,
    );
  }
}

function bytesToBigInt(bytes: Uint8Array): bigint {
  return BigInt('0x' + Buffer.from(bytes).toString('hex'));
}

// ---------------------------------------------------------------------
// Resolver A: EcNativeExportIntervention -- carries real key material
// ---------------------------------------------------------------------

export function resolveEcNativeExportFixture(
  mutationId: string,
  stimulusInstanceId: string,
  pool: FrozenMaterialPool,
): EcNativeExportIntervention {
  assertRegistered(mutationId, stimulusInstanceId);
  if (isEcSerErrorMappingClass(mutationId)) {
    throw new FixtureResolutionError(`${mutationId} uses EcSerErrorMappingIntervention, not EcNativeExportIntervention.`);
  }

  const frozen = pool.valueOf<EcP256KeyPairMaterial>(PHASE_C_MATERIAL_IDS.ec, 'ec-p256-keypair');
  const d = bytesToBigInt(frozen.d);
  const q = { x: bytesToBigInt(frozen.x), y: bytesToBigInt(frozen.y) };

  // The pool's own freeze already established these cryptographically, but
  // this class's experiment is ABOUT the (d, Q) relationship, so a fixture
  // silently violating it would make the intervention meaningless. Checked
  // through M1's frozen arithmetic, never re-derived here.
  if (!isValidScalar(d)) throw new FixtureResolutionError('frozen EC scalar fails V_scalar');
  if (!isOnCurve(q)) throw new FixtureResolutionError('frozen EC point fails V_curve');
  if (!isPair(d, q)) throw new FixtureResolutionError('frozen EC material fails V_pair (Q != dG)');

  const material: EcPrivateMaterial = { role: 'private', d, q };
  return { material, adapterReconstructsPubkey: EC_SER_BASELINE_ADAPTER_RECONSTRUCTS_PUBKEY };
}

// ---------------------------------------------------------------------
// Resolver B: EcSerErrorMappingIntervention -- no material, fifth reuse
// ---------------------------------------------------------------------

export function resolveEcSerErrorMappingFixture(
  mutationId: string,
  stimulusInstanceId: string,
  _pool: FrozenMaterialPool,
): EcSerErrorMappingIntervention {
  assertRegistered(mutationId, stimulusInstanceId);
  if (!isEcSerErrorMappingClass(mutationId)) {
    throw new FixtureResolutionError(`${mutationId} does not use EcSerErrorMappingIntervention.`);
  }
  return {
    triggeringCondition: EC_SER_BASELINE_TRIGGERING_CONDITION,
    declaredErrorClass: EC_SER_BASELINE_DECLARED_ERROR_CLASS,
  };
}

export function resolveEcSerAdapterFixture(
  mutationId: string,
  stimulusInstanceId: string,
  pool: FrozenMaterialPool,
): EcNativeExportIntervention | EcSerErrorMappingIntervention {
  return isEcSerErrorMappingClass(mutationId)
    ? resolveEcSerErrorMappingFixture(mutationId, stimulusInstanceId, pool)
    : resolveEcNativeExportFixture(mutationId, stimulusInstanceId, pool);
}
