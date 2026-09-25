// M3.2.4a-5 -- Frozen Material Pool: canonical identity.
//
//     MaterialIdentity = (materialId, materialType, H)
//     C = canonicalEncode(value)          -- M3-H2's validated primitive
//     H = SHA256(C)
//
// The pipeline is fixed and non-negotiable:
//     Validate/Normalize -> canonicalEncode -> SHA256
// schema.ts owns the first step (semantic field widths); M3-H2's
// canonicalEncode owns the second (type-safe, injective, fail-closed);
// this module owns the third and binds them together.
//
// canonicalEncoding and sha256 stored inside a FrozenMaterialRecord are
// RECORDED, never TRUSTED: verifyMaterialRecord recomputes both from the
// record's own `value` and refuses on any mismatch. A frozen artifact that
// merely asserts its own hash proves nothing.

import { createHash } from 'node:crypto';

import { canonicalEncode } from '../../canonical/canonical-encode.js';
import type { FrozenMaterialRecord, MaterialType, MaterialValue } from './schema.js';
import { validateMaterial } from './schema.js';

export class MaterialIdentityViolationError extends Error {}

export interface MaterialIdentity {
  readonly materialId: string;
  readonly materialType: MaterialType;
  readonly sha256: string;
}

export function sha256Hex(input: string): string {
  return createHash('sha256').update(input, 'utf8').digest('hex');
}

// Computes the canonical encoding and hash of a material value, validating
// its schema first. This is the ONLY sanctioned way to mint a material
// identity -- there is deliberately no path that hashes an unvalidated value.
export function computeMaterialIdentity(
  materialType: MaterialType,
  value: MaterialValue,
): { readonly canonicalEncoding: string; readonly sha256: string } {
  validateMaterial(materialType, value);
  const canonicalEncoding = canonicalEncode(value);
  return { canonicalEncoding, sha256: sha256Hex(canonicalEncoding) };
}

// Fail-closed verification of a stored record:
//   Load(material) => ValidateSchema AND SHA256(canonicalEncode(value)) === storedHash
// Any failure stops the instrument; nothing is repaired or recomputed in place.
export function verifyMaterialRecord(record: FrozenMaterialRecord): void {
  if (record.schemaVersion !== '1.0') {
    throw new MaterialIdentityViolationError(
      `Material '${record.materialId}' declares schemaVersion '${record.schemaVersion}'; only '1.0' is recognised.`,
    );
  }

  // Recompute from `value` alone -- the stored encoding/hash are never inputs.
  const recomputed = computeMaterialIdentity(record.materialType, record.value);

  if (recomputed.canonicalEncoding !== record.canonicalEncoding) {
    throw new MaterialIdentityViolationError(
      `Material '${record.materialId}': stored canonicalEncoding does not match the encoding recomputed from its own value. ` +
      'The record has been altered, or was produced by a different encoder version.',
    );
  }
  if (recomputed.sha256 !== record.sha256) {
    throw new MaterialIdentityViolationError(
      `Material '${record.materialId}': stored sha256 (${record.sha256}) does not match the hash recomputed from its own value ` +
      `(${recomputed.sha256}). Refusing to load corrupted frozen material.`,
    );
  }
}

export function materialIdentityOf(record: FrozenMaterialRecord): MaterialIdentity {
  return { materialId: record.materialId, materialType: record.materialType, sha256: record.sha256 };
}
