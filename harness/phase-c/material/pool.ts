// M3.2.4a-5 -- Frozen Material Pool: the pool itself.
//
// Global invariants enforced here:
//   I_pool1  materialId is unique across the pool
//   I_pool2  (materialType, sha256) is stable for the whole of M3/M4 --
//            verified on every load, never silently refreshed
//   I_pool3  NoRuntimeGenerationInM4: M4 may only LOAD frozen material and
//            DERIVE artifacts through frozen pure encoders. It may never
//            generate a new key, signature or base ciphertext.
//
// I_pool3 is structural, not advisory: the pool exposes no generation entry
// point at all. Material is generated exactly once, during M3, by a separate
// build-time script, and enters the pool only as an already-frozen record.

import type { DerivedArtifactDescriptor, FrozenMaterialRecord, MaterialType, MaterialValue } from './schema.js';
import { verifyMaterialRecord, sha256Hex, type MaterialIdentity, materialIdentityOf } from './canonical-identity.js';
import { canonicalEncode } from '../../canonical/canonical-encode.js';

export class MaterialPoolError extends Error {}

export class FrozenMaterialPool {
  private readonly records = new Map<string, FrozenMaterialRecord>();
  private readonly derived = new Map<string, DerivedArtifactDescriptor>();

  // Every record is verified fail-closed at insertion: schema, canonical
  // encoding, and hash must all agree with the record's own value.
  constructor(
    records: readonly FrozenMaterialRecord[],
    derivedArtifacts: readonly DerivedArtifactDescriptor[] = [],
  ) {
    for (const record of records) {
      if (this.records.has(record.materialId)) {
        throw new MaterialPoolError(
          `Duplicate materialId '${record.materialId}'. Material identity must be unique across the pool (I_pool1).`,
        );
      }
      verifyMaterialRecord(record); // throws on any schema/encoding/hash mismatch
      this.records.set(record.materialId, record);
    }

    for (const descriptor of derivedArtifacts) {
      if (this.derived.has(descriptor.artifactId)) {
        throw new MaterialPoolError(`Duplicate artifactId '${descriptor.artifactId}'.`);
      }
      if (!this.records.has(descriptor.sourceMaterialId)) {
        throw new MaterialPoolError(
          `Derived artifact '${descriptor.artifactId}' references sourceMaterialId ` +
          `'${descriptor.sourceMaterialId}', which is not in the pool. No orphan derivations.`,
        );
      }
      this.derived.set(descriptor.artifactId, descriptor);
    }

    // Artifacts that name a source material must reference one that exists.
    for (const record of this.records.values()) {
      const source = (record.value as { sourceMaterialId?: unknown }).sourceMaterialId;
      if (typeof source === 'string' && !this.records.has(source)) {
        throw new MaterialPoolError(
          `Material '${record.materialId}' declares sourceMaterialId '${source}', which is not in the pool.`,
        );
      }
    }
  }

  get(materialId: string): FrozenMaterialRecord {
    const record = this.records.get(materialId);
    if (!record) {
      throw new MaterialPoolError(
        `No frozen material with id '${materialId}'. M4 may only consume material frozen during M3 (I_pool3) -- ` +
        'there is no generation path.',
      );
    }
    // M3.2.4b-2.13 -- a superseded record stays in the corpus as historical
    // evidence but is NOT selectable as active experimental material. This
    // is fail-closed by default: reaching it requires the explicit
    // historical accessor below, so no resolver can pick one up by accident.
    if (record.supersededBy !== undefined && record.supersededBy.length > 0) {
      throw new MaterialPoolError(
        `Material '${materialId}' is SUPERSEDED by ${record.supersededBy.join(', ')} and is not eligible as ` +
        'active Phase C material. It is retained for traceability only; use getHistorical() to inspect it.',
      );
    }
    return record;
  }

  // Reads a record regardless of supersession. For audit and traceability
  // only -- never a path to experimental material.
  getHistorical(materialId: string): FrozenMaterialRecord {
    const record = this.records.get(materialId);
    if (!record) throw new MaterialPoolError(`No frozen material with id '${materialId}'.`);
    return record;
  }

  isSuperseded(materialId: string): boolean {
    const record = this.records.get(materialId);
    return record !== undefined && record.supersededBy !== undefined && record.supersededBy.length > 0;
  }

  valueOf<T extends MaterialValue>(materialId: string, expectedType: MaterialType): T {
    const record = this.get(materialId);
    if (record.materialType !== expectedType) {
      throw new MaterialPoolError(
        `Material '${materialId}' is of type '${record.materialType}', not the requested '${expectedType}'.`,
      );
    }
    return record.value as T;
  }

  identities(): readonly MaterialIdentity[] {
    return [...this.records.values()].map(materialIdentityOf);
  }

  materialIds(): readonly string[] {
    return [...this.records.keys()].sort();
  }

  // Derivation is the ONLY sanctioned way to obtain an artifact that is not
  // itself stored: a frozen pure encoder is applied to stored material and
  // the result is checked against the pinned hash. A mismatch means either
  // the material or the encoder changed -- both are freeze violations, so it
  // fails closed rather than accepting the new value.
  deriveArtifact(artifactId: string, encoder: (value: MaterialValue) => Uint8Array): Uint8Array {
    const descriptor = this.derived.get(artifactId);
    if (!descriptor) {
      throw new MaterialPoolError(`No derived-artifact descriptor with id '${artifactId}'.`);
    }
    const source = this.get(descriptor.sourceMaterialId);
    const bytes = encoder(source.value);
    const actual = sha256Hex(canonicalEncode(bytes));
    if (actual !== descriptor.expectedSha256) {
      throw new MaterialPoolError(
        `Derived artifact '${artifactId}' hashes to ${actual}, but the frozen descriptor pins ${descriptor.expectedSha256}. ` +
        'Either the source material or the frozen encoder has changed -- refusing.',
      );
    }
    return bytes;
  }

  derivedArtifactIds(): readonly string[] {
    return [...this.derived.keys()].sort();
  }
}
