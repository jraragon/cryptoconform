// M3.2.4a-5 -- Frozen Material Pool: schema and field normalization.
//
// This is the FieldNormalization layer, deliberately separate from
// M3-H2's generic canonicalEncode():
//     Validate/Normalize  ->  canonicalEncode  ->  SHA256
// canonicalEncode cannot know that a P-256 scalar is exactly 32 bytes or
// that an RSA-3072 modulus is exactly 384 -- it only sees bigint/Uint8Array.
// Semantic width is enforced HERE, before a value ever reaches the encoder.
//
// Frozen material stores NORMALIZED BYTES, never bigint. Bytes eliminate
// width ambiguity by construction: a 32-byte scalar with a leading zero is
// a distinct, well-defined value, whereas 2n carries no width at all. This
// is the structural answer to H4 (BigInt.toString(16) not zero-padding),
// applied to the frozen corpus rather than patched at each call site.

export type MaterialType =
  | 'rsa-3072-keypair'
  | 'ec-p256-keypair'
  | 'aes-base-material'
  | 'hkdf-base-material'
  | 'gcm-valid-artifact'
  | 'pss-valid-signature';

export class MaterialSchemaViolationError extends Error {}

// --- Material value shapes -------------------------------------------------

// P-256: every field is exactly 32 bytes. No bigint anywhere.
export interface EcP256KeyPairMaterial {
  readonly curve: 'P-256';
  readonly x: Uint8Array;
  readonly y: Uint8Array;
  readonly d: Uint8Array;
}

// RSA-3072, big-endian normalized components. Widths are fixed by the
// modulus size except for the public exponent, which is genuinely
// variable-width (65537 is 3 bytes) and only constrained to be odd.
export interface Rsa3072KeyPairMaterial {
  readonly modulusBits: 3072;
  readonly n: Uint8Array;
  readonly e: Uint8Array;
  readonly d: Uint8Array;
  readonly p: Uint8Array;
  readonly q: Uint8Array;
  readonly dp: Uint8Array;
  readonly dq: Uint8Array;
  readonly qi: Uint8Array;
}

export interface AesBaseMaterial {
  readonly key: Uint8Array;
  readonly iv: Uint8Array;
  readonly plaintext: Uint8Array;
  readonly aad?: Uint8Array;
}

export interface HkdfBaseMaterial {
  readonly ikm: Uint8Array;
  readonly salt: Uint8Array;
  readonly info: Uint8Array;
}

// The two artifacts that cannot be produced by a pure encoder and must be
// generated once during M3, then frozen as exact bytes. sourceMaterialId
// makes the dependency explicit; it does not replace provenance.
export interface GcmValidArtifact {
  readonly ciphertext: Uint8Array;
  readonly sourceMaterialId: string;
}

export interface PssValidSignatureArtifact {
  readonly signature: Uint8Array;
  readonly sourceMaterialId: string;
  readonly message: Uint8Array;
}

export type MaterialValue =
  | EcP256KeyPairMaterial
  | Rsa3072KeyPairMaterial
  | AesBaseMaterial
  | HkdfBaseMaterial
  | GcmValidArtifact
  | PssValidSignatureArtifact;

// --- Provenance ------------------------------------------------------------

// M3.2.4b-2.13 -- artifact QUALIFICATION.
//
// Discovered while binding GCM x artifact-transform: 'gcm-valid-artifact'
// as a materialType said nothing about WHICH artifact domain a value
// belongs to. gcm-valid-artifact-01 was frozen holding the raw output of
// webcrypto.subtle.encrypt -- C||tag -- which is cryptographically valid
// and decrypts correctly, yet is NOT an artifact of the SDK contract under
// experiment:
//     Decrypt_WebCrypto(A) = PT   =/=>   Valid_SDK(A) = true
// The SDK's own domain is version||IV||C||tag, and parseAeadArtifact
// rejects the former outright. Naming alone could not prevent that, so the
// distinction is now explicit and machine-checkable.
export type ArtifactQualification =
  | 'sdk-aead-artifact'  // parses under the frozen SDK contract, round-trips exactly
  | 'webcrypto-output';  // raw provider output; valid for its own producer, NOT an SDK artifact

export interface MaterialProvenance {
  readonly origin: 'generated-during-m3' | 'derived-by-frozen-encoder';
  readonly generator?: string;
  readonly generatorVersion?: string;
  readonly sourceMaterialIds?: readonly string[];
  readonly createdAt?: string;
}

// --- Stored record ---------------------------------------------------------

// canonicalEncoding and sha256 are RECORDED here, never TRUSTED on load:
// verifyMaterialRecord recomputes both from `value` and refuses on mismatch
// (see canonical-identity.ts). Storing them makes the frozen artifact
// self-describing and diffable; recomputing them makes it verifiable.
export interface FrozenMaterialRecord<T extends MaterialValue = MaterialValue> {
  readonly materialId: string;
  readonly materialType: MaterialType;
  readonly schemaVersion: '1.0';
  readonly value: T;
  readonly canonicalEncoding: string;
  readonly sha256: string;
  readonly provenance: MaterialProvenance;
  // M3.2.4b-2.13 -- both fields live on the RECORD, never inside `value`.
  // canonicalEncoding and sha256 are computed over `value` alone, so
  // annotating an already-frozen record leaves its identity byte-identical:
  //     (materialType, sha256) stable across M3/M4
  // is preserved even while its eligibility is corrected.
  readonly qualification?: ArtifactQualification;
  // Non-empty => this record is SUPERSEDED: retained as historical evidence,
  // never selectable as active Phase C material. Its bytes, hash and
  // original provenance remain untouched.
  readonly supersededBy?: readonly string[];
}

// A derived artifact is NOT stored as a primary record: it is regenerated by
// a frozen pure encoder from a stored material, and only its expected hash
// is pinned. StoredMaterial != DerivedArtifact.
// A derived artifact is NOT stored as a primary record: it is regenerated by
// a frozen pure encoder from a stored material, and only its expected hash
// is pinned. StoredMaterial != DerivedArtifact.
//
// M3.2.4b-2.15-D: `derivation` must name the REAL frozen M1 encoder, not an
// approximately equivalent label. RSA-ser's private container is produced by
// encodePrivateKeyInfo, so 'encode-private-key-info' was ADDED rather than
// reusing 'encode-pkcs8' -- which EC-ser already uses legitimately for its
// own encodePkcs8. Two different encoders must not share one identifier.
//     encode-spki              -> encodeSpki            (EC-ser, RSA-ser)
//     encode-pkcs8             -> encodePkcs8           (EC-ser)
//     encode-private-key-info  -> encodePrivateKeyInfo  (RSA-ser)
export interface DerivedArtifactDescriptor {
  readonly artifactId: string;
  readonly sourceMaterialId: string;
  readonly derivation: 'encode-spki' | 'encode-pkcs8' | 'encode-private-key-info';
  readonly expectedSha256: string;
}

// --- Field normalization / validation --------------------------------------

const EC_P256_FIELD_BYTES = 32;
const RSA_3072_MODULUS_BYTES = 384; // 3072 / 8
const RSA_3072_PRIME_BYTES = 192;   // each of p, q, and the CRT components

function requireBytes(v: unknown, field: string): Uint8Array {
  if (!(v instanceof Uint8Array)) {
    throw new MaterialSchemaViolationError(`${field} must be a Uint8Array of normalized bytes, never a bigint or number.`);
  }
  return v;
}

function requireExactWidth(v: Uint8Array, expected: number, field: string): void {
  if (v.length !== expected) {
    throw new MaterialSchemaViolationError(
      `${field} must be exactly ${expected} bytes (normalized, big-endian, zero-padded on the left); got ${v.length}. ` +
      'Fixed-width normalization is enforced here, never left to the generic canonical encoder.',
    );
  }
}

export function validateMaterial(materialType: MaterialType, value: MaterialValue): void {
  switch (materialType) {
    case 'ec-p256-keypair': {
      const m = value as EcP256KeyPairMaterial;
      if (m.curve !== 'P-256') throw new MaterialSchemaViolationError("ec-p256-keypair requires curve === 'P-256'.");
      for (const f of ['x', 'y', 'd'] as const) {
        requireExactWidth(requireBytes(m[f], f), EC_P256_FIELD_BYTES, f);
      }
      return;
    }
    case 'rsa-3072-keypair': {
      const m = value as Rsa3072KeyPairMaterial;
      if (m.modulusBits !== 3072) throw new MaterialSchemaViolationError('rsa-3072-keypair requires modulusBits === 3072.');
      requireExactWidth(requireBytes(m.n, 'n'), RSA_3072_MODULUS_BYTES, 'n');
      requireExactWidth(requireBytes(m.d, 'd'), RSA_3072_MODULUS_BYTES, 'd');
      for (const f of ['p', 'q', 'dp', 'dq', 'qi'] as const) {
        requireExactWidth(requireBytes(m[f], f), RSA_3072_PRIME_BYTES, f);
      }
      // e is genuinely variable-width; constrain only what is semantically required.
      const e = requireBytes(m.e, 'e');
      if (e.length === 0 || e.length > 8) throw new MaterialSchemaViolationError('e must be 1..8 bytes.');
      if ((e[e.length - 1]! & 1) === 0) throw new MaterialSchemaViolationError('e must be odd.');
      return;
    }
    case 'aes-base-material': {
      const m = value as AesBaseMaterial;
      requireExactWidth(requireBytes(m.key, 'key'), 32, 'key');   // AES-256, the frozen portable profile
      requireExactWidth(requireBytes(m.iv, 'iv'), 12, 'iv');      // GCM's own 96-bit IV
      requireBytes(m.plaintext, 'plaintext');
      if (m.aad !== undefined) requireBytes(m.aad, 'aad');
      return;
    }
    case 'hkdf-base-material': {
      const m = value as HkdfBaseMaterial;
      for (const f of ['ikm', 'salt', 'info'] as const) requireBytes(m[f], f);
      return;
    }
    case 'gcm-valid-artifact': {
      const m = value as GcmValidArtifact;
      const ct = requireBytes(m.ciphertext, 'ciphertext');
      if (ct.length === 0) throw new MaterialSchemaViolationError('ciphertext must be non-empty.');
      if (typeof m.sourceMaterialId !== 'string' || m.sourceMaterialId.length === 0) {
        throw new MaterialSchemaViolationError('gcm-valid-artifact requires a non-empty sourceMaterialId.');
      }
      return;
    }
    case 'pss-valid-signature': {
      const m = value as PssValidSignatureArtifact;
      // An RSA-3072 PSS signature is exactly one modulus wide.
      requireExactWidth(requireBytes(m.signature, 'signature'), RSA_3072_MODULUS_BYTES, 'signature');
      requireBytes(m.message, 'message');
      if (typeof m.sourceMaterialId !== 'string' || m.sourceMaterialId.length === 0) {
        throw new MaterialSchemaViolationError('pss-valid-signature requires a non-empty sourceMaterialId.');
      }
      return;
    }
    default: {
      const never: never = materialType;
      throw new MaterialSchemaViolationError(`Unknown materialType '${String(never)}'.`);
    }
  }
}
