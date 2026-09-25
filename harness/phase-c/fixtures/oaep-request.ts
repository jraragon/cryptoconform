// M3.2.4b-2.4 -- OAEP x request-transform fixture resolvers.
//
// The first group that is NOT a single shape, and the first that needed a
// protocol decision. Two typed resolvers rather than an artificial union:
//
//   OaepEncryptRequest      (8 classes)
//   OaepKeyRoleBypassState  (1 class, 2 stimuli)
//
// --- Finding 1: this group needs NO frozen key material ---------------
//
// OaepKeyRef is a pure DESCRIPTOR -- { role, modulusBits } -- carrying no
// key bytes at all. The real key is injected later by the adapter wiring,
// exactly as in Phase A/B. So despite being "the asymmetric group", these
// fixtures reference neither the public nor the private RSA material: only
// role metadata. The expectation that asymmetric operations would pull the
// frozen RSA keypair into the fixture was tested and did not hold.
//
// --- Finding 2: the first stimulus-DEPENDENT base fixture -------------
//
// OAEP-KEY-ROLE-BYPASS's own mutate() THROWS when the stimulus does not
// match the state's discriminant:
//     encrypt-with-private  requires  F0.kind === 'encrypt'
//     decrypt-with-public   requires  F0.kind === 'decrypt'
// so here the antecedent of the consolidated rule genuinely holds:
//     stimulusInstanceId in Input  =/=>  it influences F0     (general)
//     but for THIS class            ==>  it does               (particular)
// This retrospectively justifies keeping stimulusInstanceId in the common
// resolver interface even though the three earlier groups never used it.
//
// --- Finding 3: fixture values are not all one kind -------------------
//
//     FixtureValue = FrozenCryptographicMaterial
//                  U ProtocolParameter
//                  U StructuralInertValue
//
// Not every byte in a fixture belongs to the FrozenMaterialPool. The pool
// freezes cryptographic material whose identity must be reproducible; it is
// not a container for every byte-valued field.

import type { OaepEncryptRequest, OaepDecryptRequest } from '../../../src/contract/oaep.js';
import { MODULUS_BITS, OAEP_HASH, K_BYTES, MAX_MESSAGE_LEN_BYTES } from '../../../src/contract/oaep.js';
import type { OaepKeyRoleBypassState } from '../../mutations/oaep.js';
import type { FrozenMaterialPool } from '../material/pool.js';
import { MUTATION_REGISTRY } from '../../registry/mutations.js';
import { FixtureResolutionError } from './hkdf-request.js';

// ---------------------------------------------------------------------
// ProtocolParameter values: deterministic, documented request parameters,
// derived from the frozen portable profile. Byte-valued, but no more
// "cryptographic material" than HKDF_BASELINE_L is: no key, no secret, no
// randomness, nothing whose identity another party must reproduce.
// ---------------------------------------------------------------------

// Well inside MAX_MESSAGE_LEN_BYTES (318, itself derived as D-032), so that
// a boundary mutation genuinely crosses the boundary rather than starting
// on it. Exposed as a factory rather than a shared constant: Object.freeze
// does not work on typed arrays (it throws for array-buffer views), so a
// module-level Uint8Array would be silently mutable by any caller. Each
// call returns a fresh copy.
const OAEP_BASELINE_PLAINTEXT_BYTES: readonly number[] = [0x50, 0x68, 0x61, 0x73, 0x65, 0x43]; // "PhaseC"

export function oaepBaselinePlaintext(): Uint8Array {
  return new Uint8Array(OAEP_BASELINE_PLAINTEXT_BYTES);
}

export const OAEP_BASELINE_PLAINTEXT_LEN = OAEP_BASELINE_PLAINTEXT_BYTES.length;

// ---------------------------------------------------------------------
// StructuralInertValue: required to satisfy OaepDecryptRequest's shape,
// but NOT experimental material.
//
// For OAEP-KEY-ROLE-BYPASS, Gamma_0(c) = { key.role }: the intervened
// property is the ROLE. validateOaepDecryptRequest checks the role FIRST
// (step 2) and deliberately EXCLUDES any ciphertext length check, so the
// decision under test is reached without the ciphertext ever being
// interpreted. Freezing a real A0_OAEP would introduce a causal chain
//     K^RSA -> Encrypt_OAEP -> A0_OAEP -> Fixture
// that this intervention does not need, along with questions about OAEP
// randomness, provenance and cross-provider qualification -- enlarging the
// frozen corpus without adding any detection capability.
//
// This is NOT a placeholder standing in for a valid ciphertext: it is an
// inert structural value, deterministic and never consumed. Its width is
// derived from the modulus (K_BYTES) so the object remains structurally
// coherent. Tests assert that mutate() leaves it byte-identical.
// ---------------------------------------------------------------------
export const OAEP_INERT_CIPHERTEXT_LEN = K_BYTES;

function inertCiphertext(): Uint8Array {
  return new Uint8Array(OAEP_INERT_CIPHERTEXT_LEN);
}

// ---------------------------------------------------------------------
// Group membership, derived from the registry
// ---------------------------------------------------------------------

const OAEP_REQUEST_ENTRIES = MUTATION_REGISTRY.filter(
  (e) => e.operation === 'oaep' && e.mechanism === 'request-transform',
);

export const OAEP_REQUEST_MUTATION_IDS: readonly string[] =
  OAEP_REQUEST_ENTRIES.map((e) => e.mutationId).sort();

export const OAEP_REQUEST_STIMULUS_PAIRS: readonly (readonly [string, string])[] =
  OAEP_REQUEST_ENTRIES
    .flatMap((e) => e.stimulusInstances.map((s) => [e.mutationId, s.stimulusInstanceId] as const))
    .sort((a, b) => (a[0] === b[0] ? a[1].localeCompare(b[1]) : a[0].localeCompare(b[0])));

// The one class in this group whose fixture is OaepKeyRoleBypassState is
// identified by its own multi-stimulus signature rather than by a
// hard-coded id: it is the only member carrying more than one stimulus.
const KEY_ROLE_BYPASS_ID: string | undefined =
  OAEP_REQUEST_ENTRIES.find((e) => e.stimulusInstances.length > 1)?.mutationId;

export function isOaepKeyRoleBypass(mutationId: string): boolean {
  return mutationId === KEY_ROLE_BYPASS_ID;
}

function assertRegistered(mutationId: string, stimulusInstanceId: string): void {
  const known = OAEP_REQUEST_STIMULUS_PAIRS.some(([m, s]) => m === mutationId && s === stimulusInstanceId);
  if (!known) {
    throw new FixtureResolutionError(
      `(${mutationId}, ${stimulusInstanceId}) is not a registered oaep x request-transform stimulus pair.`,
    );
  }
}

// ---------------------------------------------------------------------
// Resolver A: OaepEncryptRequest (the 8 single-shape classes)
// ---------------------------------------------------------------------

export function resolveOaepEncryptRequestFixture(
  mutationId: string,
  stimulusInstanceId: string,
  _pool: FrozenMaterialPool, // no frozen material is needed: OaepKeyRef is a descriptor
): OaepEncryptRequest {
  assertRegistered(mutationId, stimulusInstanceId);
  if (isOaepKeyRoleBypass(mutationId)) {
    throw new FixtureResolutionError(
      `${mutationId} uses OaepKeyRoleBypassState, not OaepEncryptRequest -- use the key-role resolver.`,
    );
  }
  return {
    key: { role: 'public', modulusBits: MODULUS_BITS }, // Accept_C: encrypt requires a PUBLIC key
    plaintext: oaepBaselinePlaintext(),
    label: undefined,
    hash: OAEP_HASH,
    mgfHash: OAEP_HASH, // coupled, per the frozen portable profile
  };
}

// ---------------------------------------------------------------------
// Resolver B: OaepKeyRoleBypassState -- stimulus-DEPENDENT
// ---------------------------------------------------------------------

export function resolveOaepKeyRoleBypassFixture(
  mutationId: string,
  stimulusInstanceId: string,
  _pool: FrozenMaterialPool,
): OaepKeyRoleBypassState {
  assertRegistered(mutationId, stimulusInstanceId);
  if (!isOaepKeyRoleBypass(mutationId)) {
    throw new FixtureResolutionError(`${mutationId} does not use OaepKeyRoleBypassState.`);
  }

  // The base fixture's discriminant is chosen by the stimulus, because
  // mutate() itself requires the two to agree. Each branch starts from the
  // CONTRACTUALLY CORRECT role, so that the mutation genuinely bypasses a
  // role requirement rather than starting from an already-invalid state.
  if (stimulusInstanceId === 'encrypt-with-private') {
    const request: OaepEncryptRequest = {
      key: { role: 'public', modulusBits: MODULUS_BITS },
      plaintext: oaepBaselinePlaintext(),
      label: undefined, hash: OAEP_HASH, mgfHash: OAEP_HASH,
    };
    return { kind: 'encrypt', request };
  }
  if (stimulusInstanceId === 'decrypt-with-public') {
    const request: OaepDecryptRequest = {
      key: { role: 'private', modulusBits: MODULUS_BITS },
      ciphertext: inertCiphertext(), // structural inert value; never interpreted before the role check
      label: undefined, hash: OAEP_HASH, mgfHash: OAEP_HASH,
    };
    return { kind: 'decrypt', request };
  }

  throw new FixtureResolutionError(
    `${mutationId}: no base fixture defined for stimulusInstanceId '${stimulusInstanceId}'.`,
  );
}

// Convenience dispatcher over the whole group, so callers need not know
// which of the two shapes a given class uses.
export function resolveOaepRequestFixture(
  mutationId: string,
  stimulusInstanceId: string,
  pool: FrozenMaterialPool,
): OaepEncryptRequest | OaepKeyRoleBypassState {
  return isOaepKeyRoleBypass(mutationId)
    ? resolveOaepKeyRoleBypassFixture(mutationId, stimulusInstanceId, pool)
    : resolveOaepEncryptRequestFixture(mutationId, stimulusInstanceId, pool);
}

export const OAEP_MAX_MESSAGE_LEN_BYTES = MAX_MESSAGE_LEN_BYTES;
