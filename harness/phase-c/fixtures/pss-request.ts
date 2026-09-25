// M3.2.4b-2.6 -- PSS x request-transform fixture resolvers.
//
// THREE shapes, the most so far, and the first group in which the frozen
// signature artifact is genuinely required:
//
//   PssSignRequest         (7 classes)  no signature; message is a ProtocolParameter
//   PssVerifyRequest       (1 class)    REQUIRES the frozen valid signature
//   PssKeyRoleBypassState  (1 class)    composes a PssSignRequest
//
// 9 classes, 9 pairs -- no multi-stimulus class here.
//
// --- Finding 1: the frozen signature IS needed, unlike OAEP's ciphertext ---
//
// The contrast is precise, and rests on Gamma_0 rather than on the field's
// type. For OAEP-KEY-ROLE-BYPASS, Gamma_0 = { key.role } and Accept_C
// checks the role BEFORE interpreting the ciphertext, so that ciphertext
// was a StructuralInertValue. For PSS-VERIFY-MESSAGE-NORMALIZATION,
// Gamma_0 = { pss.message, pss.verification }: the verification OUTCOME is
// the observed consequence. The experiment is
//     baseline: signature valid over message  -> verification succeeds
//     mutated:  message replaced              -> verification must fail
// and if the baseline signature were inert the baseline would already fail,
// testing nothing. So the signature is FrozenCryptographicMaterial here,
// and the baseline message must be exactly the one that signature covers.
//
// --- Finding 2: PSS's key-role class is NOT OAEP's ---
//
// PSS-KEY-ROLE-BYPASS carries a single stimulus ('default') and its
// mutate() accepts ONLY state.kind === 'sign', presenting a public key
// where signing requires a private one. OAEP's counterpart had two stimuli
// selecting two different discriminants. Same name, different structure:
// carrying the OAEP shape across would have produced a fixture mutate()
// rejects outright.

import type { PssSignRequest, PssVerifyRequest } from '../../../src/contract/pss.js';
import { MODULUS_BITS, PSS_HASH, SALT_LEN_BYTES } from '../../../src/contract/pss.js';
import type { PssKeyRoleBypassState } from '../../mutations/pss.js';
import type { FrozenMaterialPool } from '../material/pool.js';
import type { PssValidSignatureArtifact } from '../material/schema.js';
import { PHASE_C_MATERIAL_IDS } from '../material/load.js';
import { MUTATION_REGISTRY } from '../../registry/mutations.js';
import { FixtureResolutionError } from './hkdf-request.js';

// ProtocolParameter: the message a SIGN request carries. Deterministic and
// documented; no key, no secret, no randomness. Distinct from the VERIFY
// message, which is not free to choose (see below).
const PSS_BASELINE_SIGN_MESSAGE_BYTES: readonly number[] = [0x50, 0x53, 0x53, 0x2d, 0x50, 0x68, 0x61, 0x73, 0x65, 0x43]; // "PSS-PhaseC"

export function pssBaselineSignMessage(): Uint8Array {
  return new Uint8Array(PSS_BASELINE_SIGN_MESSAGE_BYTES);
}

const PSS_REQUEST_ENTRIES = MUTATION_REGISTRY.filter(
  (e) => e.operation === 'pss' && e.mechanism === 'request-transform',
);

export const PSS_REQUEST_MUTATION_IDS: readonly string[] =
  PSS_REQUEST_ENTRIES.map((e) => e.mutationId).sort();

export const PSS_REQUEST_STIMULUS_PAIRS: readonly (readonly [string, string])[] =
  PSS_REQUEST_ENTRIES
    .flatMap((e) => e.stimulusInstances.map((s) => [e.mutationId, s.stimulusInstanceId] as const))
    .sort((a, b) => (a[0] === b[0] ? a[1].localeCompare(b[1]) : a[0].localeCompare(b[0])));

// Shape selection is derived from each class's own frozen Gamma_0, never
// from hard-coded ids:
//   - the key-role class intervenes on pss.key;
//   - the verify class is the one whose observed consequence is
//     pss.verification;
//   - everything else is a plain sign request.
function gamma0Of(mutationId: string): readonly string[] {
  return PSS_REQUEST_ENTRIES.find((e) => e.mutationId === mutationId)?.gamma0 ?? [];
}

export function isPssKeyRoleBypass(mutationId: string): boolean {
  return gamma0Of(mutationId).some((c) => c.endsWith('.key'));
}

export function isPssVerifyRequestClass(mutationId: string): boolean {
  return gamma0Of(mutationId).some((c) => c.endsWith('.verification'));
}

function assertRegistered(mutationId: string, stimulusInstanceId: string): void {
  const known = PSS_REQUEST_STIMULUS_PAIRS.some(([m, s]) => m === mutationId && s === stimulusInstanceId);
  if (!known) {
    throw new FixtureResolutionError(
      `(${mutationId}, ${stimulusInstanceId}) is not a registered pss x request-transform stimulus pair.`,
    );
  }
}

// ---------------------------------------------------------------------
// Resolver A: PssSignRequest (7 classes)
// ---------------------------------------------------------------------

export function resolvePssSignRequestFixture(
  mutationId: string,
  stimulusInstanceId: string,
  _pool: FrozenMaterialPool, // PssKeyRef is a descriptor; no key bytes are needed
): PssSignRequest {
  assertRegistered(mutationId, stimulusInstanceId);
  if (isPssKeyRoleBypass(mutationId) || isPssVerifyRequestClass(mutationId)) {
    throw new FixtureResolutionError(`${mutationId} does not use a plain PssSignRequest.`);
  }
  return buildSignRequest();
}

function buildSignRequest(): PssSignRequest {
  return {
    key: { role: 'private', modulusBits: MODULUS_BITS }, // Accept_C: signing requires a PRIVATE key
    message: pssBaselineSignMessage(),
    hash: PSS_HASH,
    mgfHash: PSS_HASH,       // coupled, per the frozen portable profile
    saltLengthBytes: SALT_LEN_BYTES, // sLen = hLen (D-041)
  };
}

// ---------------------------------------------------------------------
// Resolver B: PssVerifyRequest -- the one class that needs real material
// ---------------------------------------------------------------------

export function resolvePssVerifyRequestFixture(
  mutationId: string,
  stimulusInstanceId: string,
  pool: FrozenMaterialPool,
): PssVerifyRequest {
  assertRegistered(mutationId, stimulusInstanceId);
  if (!isPssVerifyRequestClass(mutationId)) {
    throw new FixtureResolutionError(`${mutationId} does not use PssVerifyRequest.`);
  }

  // The frozen, cross-provider-qualified signature, together with the exact
  // message it covers. Taking the message from anywhere else would leave the
  // baseline already failing verification, and the mutation would then be
  // measuring nothing.
  const artifact = pool.valueOf<PssValidSignatureArtifact>(
    PHASE_C_MATERIAL_IDS.pssSignature, 'pss-valid-signature',
  );

  return {
    key: { role: 'public', modulusBits: MODULUS_BITS }, // Accept_C: verification requires a PUBLIC key
    message: new Uint8Array(artifact.message),
    signature: new Uint8Array(artifact.signature),
    hash: PSS_HASH,
    mgfHash: PSS_HASH,
    saltLengthBytes: SALT_LEN_BYTES,
  };
}

// ---------------------------------------------------------------------
// Resolver C: PssKeyRoleBypassState -- composes a sign request.
//
// Its mutate() accepts ONLY kind === 'sign', so the discriminant is fixed
// here rather than selected by the stimulus (this class has just one).
// ---------------------------------------------------------------------

export function resolvePssKeyRoleBypassFixture(
  mutationId: string,
  stimulusInstanceId: string,
  _pool: FrozenMaterialPool,
): PssKeyRoleBypassState {
  assertRegistered(mutationId, stimulusInstanceId);
  if (!isPssKeyRoleBypass(mutationId)) {
    throw new FixtureResolutionError(`${mutationId} does not use PssKeyRoleBypassState.`);
  }
  // Composition, per the rule settled after OAEP: delegate when the type
  // structurally contains the same canonical object.
  return { kind: 'sign', request: buildSignRequest() };
}

export function resolvePssRequestFixture(
  mutationId: string,
  stimulusInstanceId: string,
  pool: FrozenMaterialPool,
): PssSignRequest | PssVerifyRequest | PssKeyRoleBypassState {
  if (isPssKeyRoleBypass(mutationId)) return resolvePssKeyRoleBypassFixture(mutationId, stimulusInstanceId, pool);
  if (isPssVerifyRequestClass(mutationId)) return resolvePssVerifyRequestFixture(mutationId, stimulusInstanceId, pool);
  return resolvePssSignRequestFixture(mutationId, stimulusInstanceId, pool);
}
