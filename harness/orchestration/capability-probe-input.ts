// Nominal operational input for R_cap provider-support runtime probes.
//
// The probe asks one question only:
//
//     "Can this pinned backend execute this frozen operation nominally?"
//
// It therefore MUST NOT reuse the experimental mutation fixture. A request-,
// adapter-, artifact- or capability-transform fixture represents the state
// intervened on by that class, not the neutral operational input required by
// an independent provider-support probe.
//
// All values below come from already-frozen material/profile constants.
// No mutation id, stimulus id, backend result, search or fallback participates.

import type { OperationId } from '../schema/capability.js';
import type { FrozenMaterialPool } from '../phase-c/material/pool.js';
import type {
  AesBaseMaterial,
  HkdfBaseMaterial,
} from '../phase-c/material/schema.js';
import { PHASE_C_MATERIAL_IDS } from '../phase-c/material/load.js';
import type { BoundMaterial } from '../phase-c/execution-binding.js';

import { HKDF_BASELINE_L } from '../phase-c/fixtures/hkdf-request.js';
import { GCM_BASELINE_TAG_LENGTH_BITS } from '../phase-c/fixtures/gcm-request.js';
import { oaepBaselinePlaintext } from '../phase-c/fixtures/oaep-request.js';
import { pssBaselineSignMessage } from '../phase-c/fixtures/pss-request.js';

import {
  MODULUS_BITS as OAEP_MODULUS_BITS,
  OAEP_HASH,
  type OaepEncryptRequest,
} from '../../src/contract/oaep.js';
import {
  MODULUS_BITS as PSS_MODULUS_BITS,
  PSS_HASH,
  SALT_LEN_BYTES,
  type PssSignRequest,
} from '../../src/contract/pss.js';
import type { HkdfRequest } from '../../src/contract/hkdf.js';
import type { GcmEncryptRequest } from '../../src/contract/gcm.js';

import { serializationFixture } from './serialization-adapter.js';

export class CapabilityProbeInputError extends Error {}

function requireMaterial(
  operation: OperationId,
  material: BoundMaterial | undefined,
  expectedType: string,
): BoundMaterial {
  if (material === undefined) {
    throw new CapabilityProbeInputError(
      `${operation}: nominal provider-support probe requires bound material '${expectedType}', but none was supplied.`,
    );
  }
  if (material.materialType !== expectedType) {
    throw new CapabilityProbeInputError(
      `${operation}: nominal provider-support probe expected '${expectedType}', got '${material.materialType}'.`,
    );
  }
  return material;
}

export function capabilityProbeInput(params: {
  readonly operation: OperationId;
  readonly pool: FrozenMaterialPool;
  readonly material?: BoundMaterial;
}): unknown {
  const { operation, pool } = params;

  switch (operation) {
    case 'hkdf': {
      const m = pool.valueOf<HkdfBaseMaterial>(
        PHASE_C_MATERIAL_IDS.hkdf,
        'hkdf-base-material',
      );

      const request: HkdfRequest = {
        ikm: new Uint8Array(m.ikm),
        salt: new Uint8Array(m.salt),
        info: new Uint8Array(m.info),
        length: HKDF_BASELINE_L,
      };
      return request;
    }

    case 'gcm': {
      const bound = requireMaterial(
        operation,
        params.material,
        'aes-base-material',
      );
      const m = bound.value as AesBaseMaterial;

      const request: GcmEncryptRequest = {
        key: new Uint8Array(m.key),
        plaintext: new Uint8Array(m.plaintext),
        aad: m.aad === undefined ? undefined : new Uint8Array(m.aad),
        iv: new Uint8Array(m.iv),
        tagLengthBits: GCM_BASELINE_TAG_LENGTH_BITS,
      };
      return request;
    }

    case 'oaep': {
      const request: OaepEncryptRequest = {
        key: { role: 'public', modulusBits: OAEP_MODULUS_BITS },
        plaintext: oaepBaselinePlaintext(),
        label: undefined,
        hash: OAEP_HASH,
        mgfHash: OAEP_HASH,
      };
      return request;
    }

    case 'pss': {
      const request: PssSignRequest = {
        key: { role: 'private', modulusBits: PSS_MODULUS_BITS },
        message: pssBaselineSignMessage(),
        hash: PSS_HASH,
        mgfHash: PSS_HASH,
        saltLengthBytes: SALT_LEN_BYTES,
      };
      return request;
    }

    case 'rsa-ser': {
      const material = requireMaterial(
        operation,
        params.material,
        'rsa-3072-keypair',
      );
      return serializationFixture({
        operation: 'rsa-ser',
        material,
        artifactRole: 'private',
      });
    }

    case 'ec-ser': {
      const material = requireMaterial(
        operation,
        params.material,
        'ec-p256-keypair',
      );
      return serializationFixture({
        operation: 'ec-ser',
        material,
        artifactRole: 'private',
      });
    }

    default: {
      const unreachable: never = operation;
      throw new CapabilityProbeInputError(
        `No nominal provider-support input is defined for '${String(unreachable)}'.`,
      );
    }
  }
}
