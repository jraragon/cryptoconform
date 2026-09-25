// M3.7.3 -- consumer-input assembly for R_interop.
//
// The transfer hands backend B the artifact backend A produced. But B does
// not consume bare bytes: it consumes a request, and that request has fields
// beyond the artifact. This module builds it, and does so EXPLICITLY and
// AUDITABLY rather than as five improvised blocks inside makeResolve.
//
// --- The rule every field obeys -------------------------------------------
//
//     every consumer-input field has demonstrable frozen provenance
//
// Exactly three provenances are admissible, and the assembly records which
// one each field used:
//
//   'transferred-artifact'  the bytes the producer emitted -- the only field
//                           the transfer itself supplies.
//   'producer-fixture'      copied verbatim from the mutated producer input.
//                           Parameters that must be identical on both sides
//                           or the round trip is not a round trip.
//   'contract-role'         fixed by the frozen contract's own round-trip
//                           obligation, which states what the consumer role
//                           is: Dec_q(Enc_p(m)) needs a PRIVATE key where
//                           Enc_p needed a public one, Verify_q needs a
//                           public key where Sign_p needed a private one,
//                           Import_q needs the role its container declares.
//
// There is deliberately NO 'default' and NO 'derived' provenance. A field
// that cannot cite one of the three is not assembled: the builder refuses,
// because inventing a parameter here would be inventing an experiment.
//
// --- What this module does not do -----------------------------------------
//
// It does not decide direction, roles, backends or material -- all four are
// already determined by the M3.7.2 binding. It does not interpret the
// artifact: parsing it is the consumer's contractual job, and duplicating
// that here would put scientific semantics in the plumbing.

import type { OperationId } from '../schema/capability.js';

export class ConsumerInputError extends Error {}

export type FieldProvenance =
  | 'transferred-artifact'
  | 'producer-fixture'
  | 'contract-role'
  // M3.7.3 -- the SAME nominal frozen material the producer executed from.
  // An artifact-side fixture carries the artifact and not the producer's own
  // inputs, so the consumer's key or role must come from there. Identified as
  // its own category rather than disguised as fixture: the two have different
  // provenance and must stay distinguishable in the record.
  | 'bound-material';

export interface AssembledConsumerInput {
  readonly operation: OperationId;
  /** The value handed to the consumer adapter. */
  readonly input: unknown;
  /** Field-by-field provenance, so the assembly is auditable after the fact. */
  readonly provenance: Readonly<Record<string, FieldProvenance>>;
}

/* eslint-disable @typescript-eslint/no-explicit-any */

function requireField<T>(source: any, field: string, operation: string): T {
  const v = source?.[field];
  if (v === undefined) {
    throw new ConsumerInputError(
      `${operation}: the producer fixture has no '${field}', so the consumer input cannot be assembled from ` +
      'frozen material. Refusing rather than supplying a default.',
    );
  }
  return v as T;
}

/**
 * Builds the consumer input for one transfer.
 *
 * `producerFixture` is the MUTATED producer input -- the same object the
 * producer executed on, so any parameter copied from it is by construction the
 * one the artifact was produced under.
 */
export function assembleConsumerInput(params: {
  readonly operation: OperationId;
  readonly producerFixture: unknown;
  readonly artifactHex: string;
  /** The material already bound for this obligation. Never searched for. */
  readonly boundMaterial?: unknown;
  /** Exact material expected after serialization import, when already resolved. */
  readonly expectedMaterial?: unknown;
}): AssembledConsumerInput {
  const { operation, artifactHex } = params;
  // An adapter-transform fixture wraps the real request: { kind, request } or
  // { externalRandomnessProvided, request }. Traversing that structure is not
  // policy -- the value is the frozen fixture's own, and keeps its provenance.
  const raw = params.producerFixture as any;
  const f = (raw && typeof raw === 'object' && raw.request !== undefined) ? raw.request : raw;
  const m = params.boundMaterial as any;
  // Reads a field the consumer needs from the fixture, falling back to the
  // ALREADY-BOUND material -- not to a default, and not to a search. The
  // caller is told which of the two supplied it.
  const fromFixtureOrMaterial = (field: string, materialField: string, what: string) => {
    if (f?.[field] !== undefined) return { value: f[field], provenance: 'producer-fixture' as FieldProvenance };
    if (m?.[materialField] !== undefined) return { value: m[materialField], provenance: 'bound-material' as FieldProvenance };
    throw new ConsumerInputError(
      `${what}: neither the producer fixture nor the bound material supplies '${field}'. Refusing rather than ` +
      'supplying a default.',
    );
  };
  if (artifactHex.length === 0) {
    throw new ConsumerInputError(`${operation}: an empty artifact cannot be consumed.`);
  }
  const bytes = Buffer.from(artifactHex, 'hex');

  switch (operation) {
    // AES-GCM: Dec_q(Enc_p(m)) = m. The consumer receives the SDK AEAD
    // artifact plus the same AAD the producer authenticated -- a different
    // AAD would not be the same round trip.
    case 'gcm':
      return {
        operation,
        input: {
          // The SAME key that encrypted: a different one would not be a round
          // trip. Required, never defaulted -- a producer fixture without a
          // key cannot begin a GCM transfer, and that is refused here rather
          // than discovered as a decryption failure.
          key: fromFixtureOrMaterial('key', 'key', 'gcm').value,
          artifact: bytes,
          aad: fromFixtureOrMaterial('aad', 'aad', 'gcm').value,
        },
        provenance: {
          key: fromFixtureOrMaterial('key', 'key', 'gcm').provenance,
          artifact: 'transferred-artifact',
          aad: fromFixtureOrMaterial('aad', 'aad', 'gcm').provenance,
        },
      };

    // RSA-OAEP: the decrypt request mirrors the encrypt request in every
    // output-affecting parameter, and its key role is PRIVATE because
    // Accept_C's own oaep.key clause requires it for decryption.
    case 'oaep':
      return {
        operation,
        input: {
          key: { role: 'private', modulusBits: requireField<any>(f, 'key', 'oaep').modulusBits },
          ciphertext: bytes,
          label: f?.label,
          hash: requireField<string>(f, 'hash', 'oaep'),
          mgfHash: requireField<string>(f, 'mgfHash', 'oaep'),
        },
        provenance: {
          'key.role': 'contract-role',
          'key.modulusBits': 'producer-fixture',
          ciphertext: 'transferred-artifact',
          label: 'producer-fixture',
          hash: 'producer-fixture',
          mgfHash: 'producer-fixture',
        },
      };

    // RSA-PSS: Verify_q(m, Sign_p(m)) = true. The message must be the one
    // signed; the salt length and hashes must be the ones signed under; the
    // key role is PUBLIC because pss.key requires it for verification.
    case 'pss':
      return {
        operation,
        input: {
          key: { role: 'public', modulusBits: requireField<any>(f, 'key', 'pss').modulusBits },
          message: requireField<unknown>(f, 'message', 'pss'),
          signature: bytes,
          hash: requireField<string>(f, 'hash', 'pss'),
          mgfHash: requireField<string>(f, 'mgfHash', 'pss'),
          saltLengthBytes: requireField<number>(f, 'saltLengthBytes', 'pss'),
        },
        provenance: {
          'key.role': 'contract-role',
          'key.modulusBits': 'producer-fixture',
          message: 'producer-fixture',
          signature: 'transferred-artifact',
          hash: 'producer-fixture',
          mgfHash: 'producer-fixture',
          saltLengthBytes: 'producer-fixture',
        },
      };

    // Key serialization: Import_q(Export_p(K)) === K. The importer takes the
    // exported bytes and the role the container declares -- the same role the
    // producer exported, since a container does not change role in transit.
    case 'rsa-ser':
    case 'ec-ser':
      return {
        operation,
        input: {
          artifactHex,
          requestedRole: fromFixtureOrMaterial('role', 'role', operation).value as string,
          ...(params.expectedMaterial === undefined
            ? {}
            : { expectedMaterial: params.expectedMaterial }),
        },
        provenance: {
          artifactHex: 'transferred-artifact',
          requestedRole: fromFixtureOrMaterial('role', 'role', operation).provenance,
        },
      };

    // HKDF has no producer/consumer split at all, so it has no R_interop
    // obligation and must never reach this function.
    default:
      throw new ConsumerInputError(
        `Operation '${operation}' has no interoperability consumer input; it has no producer/consumer split.`,
      );
  }
}

/* eslint-enable @typescript-eslint/no-explicit-any */

/** The five families that carry R_interop obligations. */
export const INTEROP_FAMILIES: readonly OperationId[] =
  Object.freeze(['gcm', 'oaep', 'pss', 'rsa-ser', 'ec-ser']);
