import { checkClause } from './check-clause.js';

/**
 * AES-256-GCM portable contract. Source: v0.6, sec:aesgcm ($C_{pre}^{GCM}$).
 *
 * gcm.key: portable profile fixes a 256-bit AES key.
 * gcm.iv: portable profile fixes an externally supplied 96-bit (12-byte) IV.
 * gcm.tagLength: portable profile fixes the tag to 128 bits (16 bytes) --
 *   NOTE: this is the single most adapter-critical bound in this operation.
 *   Crypto++'s generic API path enforces NO lower bound on tag length at all
 *   (only t<=16 bytes; v0.6, sec:aesgcm-backends) -- unlike gcm.key/gcm.iv,
 *   where every backend's native floor is at least as strict as ours, a
 *   request with t=0 would pass through Crypto++ with no real authentication
 *   whatsoever if this adapter-level check were ever skipped or bypassed.
 * gcm.artifact: portable representation is version(1) || IV(12) || C || T(16).
 *   AAD is explicitly NOT part of the artifact -- external contractual input.
 */

export const KEY_LEN_BYTES = 32; // 256 bits
export const IV_LEN_BYTES = 12; // 96 bits
export const TAG_LEN_BYTES = 16; // 128 bits
export const TAG_LEN_BITS = TAG_LEN_BYTES * 8; // 128
export const ARTIFACT_VERSION = 1; // single version byte, v0.6's "explicit format evolution" placeholder
export const MIN_ARTIFACT_LEN_BYTES = 1 + IV_LEN_BYTES + TAG_LEN_BYTES; // 29, empty-plaintext floor

export interface GcmEncryptRequest {
  readonly key: Uint8Array;
  readonly plaintext: Uint8Array;
  readonly aad: Uint8Array | undefined; // undefined = absent; contractually AAD_absent === AAD_empty (v0.6, unlike hkdf.salt)
  readonly iv: Uint8Array;
  readonly tagLengthBits: number; // requested tag length, in BITS (adapter-facing contract unit; Crypto++'s native API is bytes -- unit conversion is the adapter's job, not this layer's)
}

export interface GcmDecryptRequest {
  readonly key: Uint8Array;
  readonly artifact: Uint8Array; // version || IV12 || C || T16
  readonly aad: Uint8Array | undefined;
}

export interface AeadArtifactParts {
  readonly version: number;
  readonly iv: Uint8Array;
  readonly ciphertext: Uint8Array;
  readonly tag: Uint8Array;
}

/**
 * Accept_C(request) for GCM encrypt -- v0.6's classification steps (1) and (3)
 * (capability/portable boundary, then remaining contractual parameters).
 * Step (2), artifact structural validation, does not apply to encrypt (there
 * is no artifact yet). Step (4), authentication_failure, is never raised
 * here -- it can only occur inside an actual decrypt call.
 */
export function validateGcmEncryptRequest(req: GcmEncryptRequest): void {
  // Step 1: capability/portable boundary -- BEFORE any backend is invoked.
  checkClause(
    'gcm.key',
    req.key instanceof Uint8Array && req.key.length === KEY_LEN_BYTES,
    'invalid_parameter',
    `key length ${req.key instanceof Uint8Array ? req.key.length : 'n/a'} bytes, portable profile requires exactly ${KEY_LEN_BYTES} (256 bits)`,
  );
  checkClause(
    'gcm.iv',
    req.iv instanceof Uint8Array && req.iv.length === IV_LEN_BYTES,
    'invalid_parameter',
    `IV length ${req.iv instanceof Uint8Array ? req.iv.length : 'n/a'} bytes, portable profile requires exactly ${IV_LEN_BYTES} (96 bits)`,
  );
  checkClause(
    'gcm.tagLength',
    req.tagLengthBits === TAG_LEN_BITS,
    'invalid_parameter',
    `tagLength=${req.tagLengthBits} bits outside portable profile; must be exactly ${TAG_LEN_BITS} bits (v0.6 sec:aesgcm, SP 800-38D-aligned)`,
  );
  // Step 3: remaining contractual parameters.
  checkClause('gcm.plaintext', req.plaintext instanceof Uint8Array, 'invalid_parameter', 'plaintext must be a byte sequence');
  checkClause(
    'gcm.aad',
    req.aad === undefined || req.aad instanceof Uint8Array,
    'invalid_parameter',
    'aad must be absent or a byte sequence',
  );
}

/**
 * Accept_C(request) for GCM decrypt, step (1) only: key check. Split from
 * step (3) (aad) so the adapter can interleave parseAeadArtifact's step (2)
 * (malformed_artifact) BETWEEN them, in the exact frozen order: key -> artifact
 * structure -> aad -> the decrypt/authentication call itself.
 */
export function validateGcmDecryptKey(req: Pick<GcmDecryptRequest, 'key'>): void {
  checkClause(
    'gcm.key',
    req.key instanceof Uint8Array && req.key.length === KEY_LEN_BYTES,
    'invalid_parameter',
    `key length ${req.key instanceof Uint8Array ? req.key.length : 'n/a'} bytes, portable profile requires exactly ${KEY_LEN_BYTES} (256 bits)`,
  );
}

/** Accept_C(request) for GCM decrypt, step (3) only: aad type check. See validateGcmDecryptKey's comment for why this is split out. */
export function validateGcmDecryptAad(req: Pick<GcmDecryptRequest, 'aad'>): void {
  checkClause(
    'gcm.aad',
    req.aad === undefined || req.aad instanceof Uint8Array,
    'invalid_parameter',
    'aad must be absent or a byte sequence',
  );
}

/**
 * Convenience wrapper for tests/quick checks ONLY -- runs steps (1) and (3)
 * back to back with NO step (2) artifact-structure check interleaved between
 * them. A real adapter must NOT call this; it must call validateGcmDecryptKey,
 * then parseAeadArtifact, then validateGcmDecryptAad, in that exact sequence,
 * to respect v0.6's frozen classification order.
 */
export function validateGcmDecryptRequest(req: GcmDecryptRequest): void {
  validateGcmDecryptKey(req);
  validateGcmDecryptAad(req);
}

/**
 * Encodes the portable AEADArtifact: version(1) || IV(12) || C || T(16).
 * Pure encoder -- the caller (adapter) is responsible for having already
 * validated iv.length===IV_LEN_BYTES and tag.length===TAG_LEN_BYTES via
 * validateGcmEncryptRequest before this is called; this function does not
 * re-validate, it only lays out bytes per the frozen v0.6 format.
 */
export function buildAeadArtifact(iv: Uint8Array, ciphertext: Uint8Array, tag: Uint8Array): Uint8Array {
  const out = new Uint8Array(1 + iv.length + ciphertext.length + tag.length);
  out[0] = ARTIFACT_VERSION;
  out.set(iv, 1);
  out.set(ciphertext, 1 + iv.length);
  out.set(tag, 1 + iv.length + ciphertext.length);
  return out;
}

/**
 * Parses and structurally validates a portable AEADArtifact -- v0.6's
 * classification step (2): "the adapter structurally validates the
 * AEADArtifact. If it cannot contain a well-formed IV/ciphertext/tag split,
 * this is malformed_artifact." Byte 0 is the version; the next 12 bytes are
 * the IV; the last 16 bytes are the tag; everything in between is ciphertext
 * (v0.6, sec:aesgcm, verbatim).
 */
export function parseAeadArtifact(artifact: Uint8Array): AeadArtifactParts {
  checkClause(
    'gcm.artifact',
    artifact instanceof Uint8Array && artifact.length >= MIN_ARTIFACT_LEN_BYTES,
    'malformed_artifact',
    `artifact length ${artifact instanceof Uint8Array ? artifact.length : 'n/a'} below minimum ${MIN_ARTIFACT_LEN_BYTES} bytes (version(1) + IV(12) + tag(16), empty ciphertext)`,
  );
  // noUncheckedIndexedAccess makes artifact[0] type as `number | undefined`;
  // the length check just above already guarantees index 0 exists (>=29>0).
  // The ?? -1 fallback is unreachable in practice; it exists only to satisfy
  // strict indexing without a non-null assertion, and -1 !== ARTIFACT_VERSION
  // so it fails safely (as malformed_artifact below) if it were ever hit.
  const version = artifact[0] ?? -1;
  checkClause(
    'gcm.artifact',
    version === ARTIFACT_VERSION,
    'malformed_artifact',
    `unsupported artifact version ${version}, expected ${ARTIFACT_VERSION}`,
  );
  const iv = artifact.slice(1, 1 + IV_LEN_BYTES);
  const tag = artifact.slice(artifact.length - TAG_LEN_BYTES);
  const ciphertext = artifact.slice(1 + IV_LEN_BYTES, artifact.length - TAG_LEN_BYTES);
  return { version, iv, ciphertext, tag };
}
