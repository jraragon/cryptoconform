// M3.2.4a-6 -- loader for the frozen material corpus.
//
// Bytes are stored in JSON as { "__bytes__": "<hex>" } and reconstructed
// into Uint8Array here BEFORE anything is verified, so that the recomputed
// canonical encoding is over the same value shape the generator encoded.
//
// This module is the only sanctioned entry point to the real corpus, and it
// is read-only: it can load and verify, never generate (I_pool3). Every
// record passes through FrozenMaterialPool's own fail-closed construction,
// which re-derives canonicalEncode+SHA256 from each value and refuses on
// any mismatch -- the stored hash is never taken on trust.

import { readFileSync, existsSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import type { FrozenMaterialRecord, DerivedArtifactDescriptor } from './schema.js';
import { FrozenMaterialPool } from './pool.js';

// The corpus is a .json file, and tsc does not copy non-TS assets into
// dist/. Running from source (tsx) resolves it co-located; running from
// compiled output does not, and would fail with ENOENT -- caught only
// because a script was run from dist/, since the whole test suite runs
// under tsx. Rather than depend on which entry point happens to be used,
// resolve the co-located path first and fall back to the source tree.
const HERE = path.dirname(fileURLToPath(import.meta.url));
const CO_LOCATED = path.join(HERE, 'frozen-material.json');
const FROM_DIST = path.join(HERE, '../../../../harness/phase-c/material/frozen-material.json');

const FROZEN_MATERIAL_PATH = existsSync(CO_LOCATED) ? CO_LOCATED : FROM_DIST;

function reviveBytes(v: unknown): unknown {
  if (v !== null && typeof v === 'object' && !Array.isArray(v)) {
    const rec = v as Record<string, unknown>;
    if (typeof rec['__bytes__'] === 'string') {
      return new Uint8Array(Buffer.from(rec['__bytes__'], 'hex'));
    }
    const out: Record<string, unknown> = {};
    for (const k of Object.keys(rec)) out[k] = reviveBytes(rec[k]);
    return out;
  }
  if (Array.isArray(v)) return v.map(reviveBytes);
  return v;
}

export function loadFrozenMaterialRecords(filePath: string = FROZEN_MATERIAL_PATH): readonly FrozenMaterialRecord[] {
  const parsed = JSON.parse(readFileSync(filePath, 'utf8')) as { schemaVersion: string; records: unknown[] };
  if (parsed.schemaVersion !== '1.0') {
    throw new Error(`frozen-material.json declares schemaVersion '${parsed.schemaVersion}'; only '1.0' is recognised.`);
  }
  return parsed.records.map((r) => {
    const rec = r as Record<string, unknown>;
    return { ...rec, value: reviveBytes(rec['value']) } as unknown as FrozenMaterialRecord;
  });
}

// M3.2.4b-2.14-D -- derived-artifact descriptors, now genuinely carried by
// the corpus. The mechanism was defined and unit-tested in M3.2.4a-5 but had
// never been materialized: the corpus held no descriptors and this loader did
// not read any, so FrozenMaterialPool's own deriveArtifact() was unreachable
// from real material. A descriptor stores a RECIPE plus an expected hash --
// never the derived bytes:
//     StoredMaterial            = bytes + hash
//     DerivedArtifactDescriptor = recipe + expectedHash
export function loadDerivedArtifactDescriptors(filePath: string = FROZEN_MATERIAL_PATH): readonly DerivedArtifactDescriptor[] {
  const parsed = JSON.parse(readFileSync(filePath, 'utf8')) as { derivedArtifacts?: unknown[] };
  return (parsed.derivedArtifacts ?? []) as readonly DerivedArtifactDescriptor[];
}

// Loads and fully verifies the frozen corpus. Any schema violation,
// encoding mismatch, hash mismatch, duplicate id or orphan reference stops
// the instrument here.
export function loadFrozenMaterialPool(filePath: string = FROZEN_MATERIAL_PATH): FrozenMaterialPool {
  return new FrozenMaterialPool(loadFrozenMaterialRecords(filePath), loadDerivedArtifactDescriptors(filePath));
}

// The canonical material identifiers, pinned as literals so a missing or
// renamed record is a loud failure rather than a silent absence.
// pssSignature2 was added in M3.2.4b-2.8 as an authorized corpus extension:
// PSS-VERIFICATION-FALSE-REJECT needs two independently valid signatures
// over the same message. It was appended, never rewriting the first.
export const PHASE_C_MATERIAL_IDS = Object.freeze({
  rsa: 'rsa-3072-primary-01',
  ec: 'ec-p256-primary-01',
  aes: 'aes-phasec-primary-01',
  hkdf: 'hkdf-phasec-primary-01',
  gcmArtifact: 'gcm-valid-artifact-01',
  pssSignature: 'pss-valid-signature-01',
  pssSignature2: 'pss-valid-signature-02',
  // M3.2.4b-2.13: the two SDK-format GCM artifacts. gcmArtifact above is
  // SUPERSEDED (raw webcrypto-output, not an SDK artifact) and is retained
  // only as historical evidence -- the pool refuses to serve it as active
  // material. These two are what GCM x artifact-transform consumes.
  gcmSdkArtifactGeneral: 'gcm-sdk-artifact-general-01',
  gcmSdkArtifactCtLen: 'gcm-sdk-artifact-ctlen-01',
} as const);

// M3.2.4b-2.14-D -- derived artifacts. Their BYTES are never stored: only
// the recipe (source material + encoder) and the expected hash. They are
// materialized on demand through FrozenMaterialPool.deriveArtifact(), which
// re-runs the frozen M1 encoder and refuses any result that does not hash to
// the pinned value.
export const PHASE_C_DERIVED_ARTIFACT_IDS = Object.freeze({
  ecSpki: 'ec-p256-spki-derived-01',
  ecPkcs8: 'ec-p256-pkcs8-derived-01',
  // M3.2.4b-2.15-D. Both RSA containers are qualified here; WHICH class
  // consumes which is decided in -R, keeping
  //     D = availability + identity + qualification
  //     R = experimental binding
  rsaSpki: 'rsa-3072-spki-derived-01',
  rsaPrivateKeyInfo: 'rsa-3072-private-key-info-derived-01',
} as const);
