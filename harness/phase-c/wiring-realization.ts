// M3.7.3 -- wiring realization.
//
// M3.7.2 decided WHICH wiring each obligation uses; this converts the
// descriptor it chose into the arguments that wiring actually takes. It is a
// REPRESENTATION CONVERSION and nothing else:
//
//     frozen material  ->  factory input
//
// resolveDispatch() and the M3.7.2 binding remain the authority. Nothing here
// selects a wiring, a backend, a role or a key. The frozen corpus stores
// components as normalised BYTES; the factories take the same components as
// HEX. Renaming a field and rendering bytes as hex is plumbing.
//
// --- The line this module must not cross ----------------------------------
//
// A conversion of representation is plumbing. FABRICATING a cryptographic
// component the freeze does not provide is not, and would be inventing
// experimental material. So every component is read by name from the frozen
// record and a missing one is REFUSED -- there is no derivation, no
// recomputation from other components, no default and no generation. If a
// factory needs something the corpus does not hold, this throws and the
// milestone stops.

import type { OaepKeyHex } from '../orchestration/oaep-chromium-wiring.js';
import type { RsaKeyHexMaterial } from '../orchestration/rsa-ser-chromium-wiring.js';
import type { EcKeyHexMaterial } from '../orchestration/ec-ser-chromium-wiring.js';
import type { GcmDecryptRequest } from '../../src/contract/gcm.js';
import type { PssVerifyRequest } from '../../src/contract/pss.js';
import { MODULUS_BITS, PSS_HASH, SALT_LEN_BYTES } from '../../src/contract/pss.js';
import type { AesBaseMaterial } from './material/schema.js';
import type { BoundMaterial } from './execution-binding.js';

export class RealizationError extends Error {}

/* eslint-disable @typescript-eslint/no-explicit-any */

/**
 * Reads one component of a frozen record BY NAME and renders it as hex.
 *
 * The corpus stores components as `{ __bytes__: <hex> }` -- normalised, fixed
 * width, with the width carried by construction (the M2.5 H4 lesson). This
 * reads that representation and nothing else: no bigint path, no padding
 * decision, no recomputation.
 */
function componentHex(record: any, field: string, what: string): string {
  const v = record?.[field];
  // The pool deserialises `{ __bytes__: <hex> }` into a Uint8Array, so the
  // component arrives as bytes whose width the corpus already normalised.
  // Rendering those exact bytes as hex adds nothing and removes nothing.
  const hex = v instanceof Uint8Array ? Buffer.from(v).toString('hex')
    : typeof v === 'string' ? v
      : typeof v?.__bytes__ === 'string' ? v.__bytes__ : undefined;
  if (typeof hex !== 'string' || hex.length === 0) {
    throw new RealizationError(
      `${what}: the frozen record has no component '${field}'. Refusing to fabricate it -- a representation ` +
      'conversion is plumbing, but inventing a cryptographic component the freeze does not provide is not.',
    );
  }
  return hex;
}

/**
 * Completes a GCM decrypt-side fixture using only already-bound frozen
 * material. Artifact-transform fixtures carry the state they intervene on
 * ({artifact, aad} or {artifact}); the AES key is deliberately not part of
 * that mutation state.
 *
 * If the fixture itself carries `aad`, that value is authoritative because it
 * may have been changed by the frozen mutation (AAD-TAMPER). A bare artifact
 * fixture instead receives the nominal AAD from the bound AES material.
 */
export function realizeGcmDecryptRequest(
  material: BoundMaterial,
  fixture: unknown,
): GcmDecryptRequest {
  if (material.materialType !== 'aes-base-material') {
    throw new RealizationError(
      `Expected an aes-base-material, got '${material.materialType}'.`,
    );
  }

  const aes = material.value as AesBaseMaterial;
  const candidate = fixture as {
    readonly artifact?: unknown;
    readonly aad?: unknown;
  };

  if (!(candidate.artifact instanceof Uint8Array)) {
    throw new RealizationError(
      'GCM decrypt-side realization requires the artifact supplied by the frozen fixture.',
    );
  }

  const carriesAad = Object.prototype.hasOwnProperty.call(candidate, 'aad');
  const aad = carriesAad ? candidate.aad : aes.aad;

  if (aad !== undefined && !(aad instanceof Uint8Array)) {
    throw new RealizationError(
      'GCM decrypt-side realization received a non-byte AAD.',
    );
  }

  return {
    key: new Uint8Array(aes.key),
    artifact: new Uint8Array(candidate.artifact),
    aad: aad === undefined ? undefined : new Uint8Array(aad),
  };
}


/**
 * Completes a PSS artifact-side verification fixture using the frozen
 * portable-profile descriptors. The mutation supplies the message/signature
 * artifact; key role, modulus descriptor, hash coupling and salt length are
 * fixed by the already-frozen PSS contract.
 *
 * No key bytes are created here: actual RSA material remains bound separately
 * to the adapter factory.
 */
export function realizePssVerifyRequest(
  material: BoundMaterial,
  fixture: unknown,
): PssVerifyRequest {
  if (material.materialType !== 'rsa-3072-keypair') {
    throw new RealizationError(
      `Expected an rsa-3072-keypair, got '${material.materialType}'.`,
    );
  }

  const candidate = fixture as {
    readonly message?: unknown;
    readonly signature?: unknown;
  };

  if (!(candidate.message instanceof Uint8Array)) {
    throw new RealizationError(
      'PSS artifact-side verification requires the message supplied by the frozen fixture.',
    );
  }

  if (!(candidate.signature instanceof Uint8Array)) {
    throw new RealizationError(
      'PSS artifact-side verification requires the signature supplied by the frozen fixture.',
    );
  }

  return {
    key: { role: 'public', modulusBits: MODULUS_BITS },
    message: new Uint8Array(candidate.message),
    signature: new Uint8Array(candidate.signature),
    hash: PSS_HASH,
    mgfHash: PSS_HASH,
    saltLengthBytes: SALT_LEN_BYTES,
  };
}

/** RSA components, for the OAEP and PSS adapter factories. */
export function realizeRsaKeyHex(material: BoundMaterial): OaepKeyHex {
  if (material.materialType !== 'rsa-3072-keypair') {
    throw new RealizationError(`Expected an rsa-3072-keypair, got '${material.materialType}'.`);
  }
  const r = material.value as any;
  const what = `RSA key ${material.materialId}`;
  return {
    modulusHex: componentHex(r, 'n', what),
    publicExponentHex: componentHex(r, 'e', what),
    privateExponentHex: componentHex(r, 'd', what),
    pHex: componentHex(r, 'p', what),
    qHex: componentHex(r, 'q', what),
    dpHex: componentHex(r, 'dp', what),
    dqHex: componentHex(r, 'dq', what),
    qiHex: componentHex(r, 'qi', what),
  };
}

export function realizeMutatedRsaSerMaterial(
  fixture: unknown,
): RsaKeyHexMaterial {
  if (fixture === null || typeof fixture !== 'object') {
    throw new RealizationError(
      'RSA-ser material-side export fixture is not an object.',
    );
  }

  const f = fixture as Record<string, unknown>;

  if (f.role !== 'public' && f.role !== 'private') {
    throw new RealizationError(
      'RSA-ser material-side export fixture has no public/private role.',
    );
  }

  const bigintHex = (field: string): string => {
    const value = f[field];
    if (typeof value !== 'bigint') {
      throw new RealizationError(
        `RSA-ser material-side export fixture has no bigint '${field}'.`,
      );
    }
    const hex = value.toString(16);
    return hex.length % 2 === 0 ? hex : `0${hex}`;
  };

  if (f.role === 'public') {
    return {
      role: 'public',
      nHex: bigintHex('n'),
      eHex: bigintHex('e'),
    };
  }

  return {
    role: 'private',
    nHex: bigintHex('n'),
    eHex: bigintHex('e'),
    dHex: bigintHex('d'),
    pHex: bigintHex('p'),
    qHex: bigintHex('q'),
    dpHex: bigintHex('dP'),
    dqHex: bigintHex('dQ'),
    qiHex: bigintHex('qInv'),
  };
}

/** RSA components in the serialization wirings' own shape. Same source. */
export function realizeRsaSerMaterial(
  material: BoundMaterial, role: 'public' | 'private',
): RsaKeyHexMaterial {
  const k = realizeRsaKeyHex(material);
  return role === 'public'
    ? { role, nHex: k.modulusHex, eHex: k.publicExponentHex }
    : {
        role, nHex: k.modulusHex, eHex: k.publicExponentHex,
        dHex: k.privateExponentHex!, pHex: k.pHex!, qHex: k.qHex!,
        dpHex: k.dpHex!, dqHex: k.dqHex!, qiHex: k.qiHex!,
      };
}

/** EC P-256 components, for the EC serialization wirings. */
export function realizeEcSerMaterial(
  material: BoundMaterial, role: 'public' | 'private',
): EcKeyHexMaterial {
  if (material.materialType !== 'ec-p256-keypair') {
    throw new RealizationError(`Expected an ec-p256-keypair, got '${material.materialType}'.`);
  }
  const r = material.value as any;
  const what = `EC key ${material.materialId}`;
  const base = { role, xHex: componentHex(r, 'x', what), yHex: componentHex(r, 'y', what) };
  return role === 'public' ? base : { ...base, dHex: componentHex(r, 'd', what) };
}


/** Mutated EC-ser material -> the representation consumed by export wirings. */
export function realizeMutatedEcSerMaterial(
  fixture: unknown,
): EcKeyHexMaterial {
  if (fixture === null || typeof fixture !== 'object') {
    throw new RealizationError('Mutated EC serialization material is not an object.');
  }

  const f = fixture as {
    readonly role?: unknown;
    readonly d?: unknown;
    readonly q?: { readonly x?: unknown; readonly y?: unknown };
  };

  if (
    (f.role !== 'public' && f.role !== 'private')
    || f.q === undefined
    || typeof f.q.x !== 'bigint'
    || typeof f.q.y !== 'bigint'
  ) {
    throw new RealizationError(
      'Mutated EC serialization material lacks role/q.x/q.y.',
    );
  }

  const xHex = f.q.x.toString(16).padStart(64, '0');
  const yHex = f.q.y.toString(16).padStart(64, '0');

  if (f.role === 'public') {
    return { role: 'public', xHex, yHex };
  }

  if (typeof f.d !== 'bigint') {
    throw new RealizationError(
      'Mutated private EC serialization material lacks d.',
    );
  }

  return {
    role: 'private',
    xHex,
    yHex,
    dHex: f.d.toString(16).padStart(64, '0'),
  };
}

/* eslint-enable @typescript-eslint/no-explicit-any */
