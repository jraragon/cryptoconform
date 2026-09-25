// M3.2.4b-2.14-R -- EC-ser x artifact-transform fixture resolvers.
//
// The most heterogeneous group of the whole binding: 11 classes, 11 pairs,
// FOUR shapes.
//
//   { artifact }                              7 classes
//   EcPrivateMaterial                         2 classes
//   EcPublicMaterial                          1 class
//   { artifact, requestedRole }               1 class
//
// --- Derived artifacts, never encoded here ---
//
// The 8 serialized classes consume SPKI or PKCS8 obtained through
// deriveArtifact(), never by calling encodeSpki/encodePkcs8 directly:
//     Resolver selects; Descriptor identifies; Encoder derives; Hash authenticates.
// A byte of drift in the frozen M1 encoder, or a wrong encoder, is refused
// by the pinned hash rather than silently producing a different fixture.
//
// --- Which artifact each class needs, DERIVED not named ---
//
// Two independent mechanisms, because neither alone suffices:
//
//   (1) PROBE. Five classes parse the artifact and throw on the wrong
//       structure (SPKI has 2 SEQUENCE children, PKCS8 has 3), so asking
//       the implementation is decisive:
//           CURVE-SUBSTITUTION, PUBLIC-POINT-ENCODING  -> SPKI
//           PRIVATE-{PARAMS-ABSENT, PARAMS-MISMATCH, PUBKEY-ABSENT} -> PKCS8
//
//   (2) Gamma_0 CLAUSE. The two DER-MALFORMED classes xor a byte without
//       parsing, so they accept either artifact and the probe cannot
//       separate them. Their own clauses can: 'ec-ser.public.asn1' versus
//       'ec-ser.private.asn1'.
//
// Gamma_0 alone would have failed too: EC-PRIVATE-PARAMS-ABSENT declares
// only { ec-ser.validation.semantic, ec-ser.export } and names no role at
// all, while EC-CURVE-SUBSTITUTION carries the deliberately ambiguous
// 'ec-ser.public.asn1-or-private.asn1'. Hence both mechanisms, each used
// where it is decisive.
//
// --- Two causal preconditions, checked rather than assumed ---
//
// EC-PUBLIC-OFF-CURVE mutates q.y -> q.y+1 and its own source comment says
// this is off-curve "for almost any point -- verified in the test, never
// assumed". EC-PRIVATE-PAIR-MISMATCH substitutes 3G for the material's own
// dG. Both are only meaningful for THIS frozen key:
//     isOnCurve(x, y+1) = false
//     d != 3  and  isPair(d, 3G) = false
// A different key could violate either, leaving a "mutation" that mutates
// nothing. Same reasoning as V_pair in the EC-ser adapter group.

import type { EcPublicMaterial, EcPrivateMaterial } from '../../../src/contract/ec-ser.js';
import { encodeSpki, encodePkcs8 } from '../../../src/contract/ec-ser.js';
import { isOnCurve, isPair, isValidScalar, scalarMultiplyG } from '../../../src/contract/p256.js';
import type { FrozenMaterialPool } from '../material/pool.js';
import type { EcP256KeyPairMaterial, MaterialValue } from '../material/schema.js';
import { PHASE_C_MATERIAL_IDS, PHASE_C_DERIVED_ARTIFACT_IDS } from '../material/load.js';
import { MUTATION_REGISTRY } from '../../registry/mutations.js';
import { FixtureResolutionError } from './hkdf-request.js';
import { getMutationImplementation } from '../mutation-index.js';

export interface EcArtifactStimulus {
  readonly artifact: Uint8Array;
}
export interface EcRoleContainerStimulus {
  readonly artifact: Uint8Array;
  readonly requestedRole: 'public' | 'private';
}

const EC_ARTIFACT_ENTRIES = MUTATION_REGISTRY.filter(
  (e) => e.operation === 'ec-ser' && e.mechanism === 'artifact-transform',
);

export const EC_ARTIFACT_MUTATION_IDS: readonly string[] =
  EC_ARTIFACT_ENTRIES.map((e) => e.mutationId).sort();

export const EC_ARTIFACT_STIMULUS_PAIRS: readonly (readonly [string, string])[] =
  EC_ARTIFACT_ENTRIES
    .flatMap((e) => e.stimulusInstances.map((s) => [e.mutationId, s.stimulusInstanceId] as const))
    .sort((a, b) => (a[0] === b[0] ? a[1].localeCompare(b[1]) : a[0].localeCompare(b[0])));

function gamma0Of(mutationId: string): readonly string[] {
  return EC_ARTIFACT_ENTRIES.find((e) => e.mutationId === mutationId)?.gamma0 ?? [];
}

// --- Shape classification, all from the registry / implementations --------

export function isEcRoleContainerClass(mutationId: string): boolean {
  return getMutationImplementation(mutationId).directInterventionTargets.some(
    (t) => String(t) === 'requestedRole',
  );
}

// A material class intervenes on the key's own components rather than on
// serialized bytes.
export function isEcMaterialClass(mutationId: string): boolean {
  const targets = getMutationImplementation(mutationId).directInterventionTargets.map(String);
  return targets.every((t) => t === 'd' || t === 'q');
}

// Of the material classes, the public one intervenes only on q AND declares
// the curve-membership clause; the private ones touch d or pair consistency.
export function isEcPublicMaterialClass(mutationId: string): boolean {
  return isEcMaterialClass(mutationId)
    && gamma0Of(mutationId).some((c) => c.endsWith('.curveMembership'));
}

// --- Bytes -> bigint, the safe direction only ----------------------------

function bytesToBigInt(bytes: Uint8Array): bigint {
  return BigInt('0x' + Buffer.from(bytes).toString('hex'));
}

function frozenPublicMaterial(pool: FrozenMaterialPool): EcPublicMaterial {
  const ec = pool.valueOf<EcP256KeyPairMaterial>(PHASE_C_MATERIAL_IDS.ec, 'ec-p256-keypair');
  return { role: 'public', q: { x: bytesToBigInt(ec.x), y: bytesToBigInt(ec.y) } };
}
function frozenPrivateMaterial(pool: FrozenMaterialPool): EcPrivateMaterial {
  const ec = pool.valueOf<EcP256KeyPairMaterial>(PHASE_C_MATERIAL_IDS.ec, 'ec-p256-keypair');
  return { role: 'private', d: bytesToBigInt(ec.d), q: { x: bytesToBigInt(ec.x), y: bytesToBigInt(ec.y) } };
}

// --- Derived artifacts, obtained only through the descriptor --------------

const spkiEncoder = (v: MaterialValue): Uint8Array => {
  const ec = v as EcP256KeyPairMaterial;
  return encodeSpki({ role: 'public', q: { x: bytesToBigInt(ec.x), y: bytesToBigInt(ec.y) } });
};
const pkcs8Encoder = (v: MaterialValue): Uint8Array => {
  const ec = v as EcP256KeyPairMaterial;
  return encodePkcs8({
    role: 'private', d: bytesToBigInt(ec.d),
    q: { x: bytesToBigInt(ec.x), y: bytesToBigInt(ec.y) },
  });
};

function derivedSpki(pool: FrozenMaterialPool): Uint8Array {
  return pool.deriveArtifact(PHASE_C_DERIVED_ARTIFACT_IDS.ecSpki, spkiEncoder);
}
function derivedPkcs8(pool: FrozenMaterialPool): Uint8Array {
  return pool.deriveArtifact(PHASE_C_DERIVED_ARTIFACT_IDS.ecPkcs8, pkcs8Encoder);
}

// Which serialized artifact a class needs: probe first, fall back to the
// class's own Gamma_0 clause for the two that parse nothing.
const ARTIFACT_CHOICE = new Map<string, 'spki' | 'pkcs8'>();

function classifyArtifactNeed(pool: FrozenMaterialPool): void {
  if (ARTIFACT_CHOICE.size > 0) return;
  const spki = derivedSpki(pool);
  const pkcs8 = derivedPkcs8(pool);

  for (const entry of EC_ARTIFACT_ENTRIES) {
    const id = entry.mutationId;
    if (isEcMaterialClass(id) || isEcRoleContainerClass(id)) continue;
    const impl = getMutationImplementation(id);
    const spkiOk = ((): boolean => { try { impl.mutate({ artifact: spki }, 'default'); return true; } catch { return false; } })();
    const pkcs8Ok = ((): boolean => { try { impl.mutate({ artifact: pkcs8 }, 'default'); return true; } catch { return false; } })();

    if (spkiOk && !pkcs8Ok) { ARTIFACT_CHOICE.set(id, 'spki'); continue; }
    if (pkcs8Ok && !spkiOk) { ARTIFACT_CHOICE.set(id, 'pkcs8'); continue; }
    if (!spkiOk && !pkcs8Ok) {
      throw new FixtureResolutionError(`${id} accepts neither derived artifact; its precondition is unmet.`);
    }
    // Accepts both (parses nothing): its own clause decides.
    const clauses = gamma0Of(id);
    if (clauses.includes('ec-ser.private.asn1')) { ARTIFACT_CHOICE.set(id, 'pkcs8'); continue; }
    if (clauses.includes('ec-ser.public.asn1')) { ARTIFACT_CHOICE.set(id, 'spki'); continue; }
    throw new FixtureResolutionError(
      `${id} accepts both derived artifacts and declares no role-specific ASN.1 clause; cannot choose.`,
    );
  }
}

function assertRegistered(mutationId: string, stimulusInstanceId: string): void {
  const known = EC_ARTIFACT_STIMULUS_PAIRS.some(([m, s]) => m === mutationId && s === stimulusInstanceId);
  if (!known) {
    throw new FixtureResolutionError(
      `(${mutationId}, ${stimulusInstanceId}) is not a registered ec-ser x artifact-transform stimulus pair.`,
    );
  }
}

// ---------------------------------------------------------------------
// R1: { artifact } -- 7 classes
// ---------------------------------------------------------------------

export function resolveEcArtifactStimulusFixture(
  mutationId: string,
  stimulusInstanceId: string,
  pool: FrozenMaterialPool,
): EcArtifactStimulus {
  assertRegistered(mutationId, stimulusInstanceId);
  if (isEcMaterialClass(mutationId) || isEcRoleContainerClass(mutationId)) {
    throw new FixtureResolutionError(`${mutationId} does not use a bare artifact stimulus.`);
  }
  classifyArtifactNeed(pool);
  const choice = ARTIFACT_CHOICE.get(mutationId);
  if (choice === undefined) throw new FixtureResolutionError(`${mutationId} has no classified artifact need.`);
  return { artifact: choice === 'spki' ? derivedSpki(pool) : derivedPkcs8(pool) };
}

// ---------------------------------------------------------------------
// R2: EcPrivateMaterial -- 2 classes
// ---------------------------------------------------------------------

export function resolveEcPrivateMaterialFixture(
  mutationId: string,
  stimulusInstanceId: string,
  pool: FrozenMaterialPool,
): EcPrivateMaterial {
  assertRegistered(mutationId, stimulusInstanceId);
  if (!isEcMaterialClass(mutationId) || isEcPublicMaterialClass(mutationId)) {
    throw new FixtureResolutionError(`${mutationId} does not use EcPrivateMaterial.`);
  }
  const material = frozenPrivateMaterial(pool);

  // Baseline validity: the pair must be genuine before either intervention.
  if (!isValidScalar(material.d)) throw new FixtureResolutionError('frozen scalar fails V_scalar');
  if (material.q === 'infinity' || !isOnCurve(material.q)) throw new FixtureResolutionError('frozen point fails V_curve');
  if (!isPair(material.d, material.q)) throw new FixtureResolutionError('frozen material fails V_pair');

  // Causal precondition for the pair-mismatch intervention: it substitutes
  // 3G for dG, which only isolates V_pair from V_curve when 3G != dG.
  const g3 = scalarMultiplyG(3n);
  if (material.d === 3n || isPair(material.d, g3)) {
    throw new FixtureResolutionError(
      'the frozen scalar makes 3G the CORRECT public point, so a pair-mismatch mutation would produce a valid pair.',
    );
  }
  return material;
}

// ---------------------------------------------------------------------
// R3: EcPublicMaterial -- 1 class
// ---------------------------------------------------------------------

export function resolveEcPublicMaterialFixture(
  mutationId: string,
  stimulusInstanceId: string,
  pool: FrozenMaterialPool,
): EcPublicMaterial {
  assertRegistered(mutationId, stimulusInstanceId);
  if (!isEcPublicMaterialClass(mutationId)) {
    throw new FixtureResolutionError(`${mutationId} does not use EcPublicMaterial.`);
  }
  const material = frozenPublicMaterial(pool);
  if (material.q === 'infinity' || !isOnCurve(material.q)) {
    throw new FixtureResolutionError('frozen point fails V_curve');
  }

  // Causal precondition: the intervention is q.y -> q.y+1, which must
  // genuinely leave the curve for THIS point.
  if (isOnCurve({ x: material.q.x, y: material.q.y + 1n })) {
    throw new FixtureResolutionError(
      'for this frozen point, (x, y+1) is ALSO on the curve, so the off-curve mutation would not leave the curve.',
    );
  }
  return material;
}

// ---------------------------------------------------------------------
// R4: { artifact, requestedRole } -- 1 class
// ---------------------------------------------------------------------

export function resolveEcRoleContainerFixture(
  mutationId: string,
  stimulusInstanceId: string,
  pool: FrozenMaterialPool,
): EcRoleContainerStimulus {
  assertRegistered(mutationId, stimulusInstanceId);
  if (!isEcRoleContainerClass(mutationId)) {
    throw new FixtureResolutionError(`${mutationId} does not use a role-container stimulus.`);
  }
  // Baseline: artifact and requested role AGREE, so the mutation -- which
  // flips only the role -- creates a genuine container/role mismatch rather
  // than starting from one.
  return { artifact: derivedSpki(pool), requestedRole: 'public' };
}

export function resolveEcArtifactFixture(
  mutationId: string,
  stimulusInstanceId: string,
  pool: FrozenMaterialPool,
): EcArtifactStimulus | EcPrivateMaterial | EcPublicMaterial | EcRoleContainerStimulus {
  if (isEcRoleContainerClass(mutationId)) return resolveEcRoleContainerFixture(mutationId, stimulusInstanceId, pool);
  if (isEcPublicMaterialClass(mutationId)) return resolveEcPublicMaterialFixture(mutationId, stimulusInstanceId, pool);
  if (isEcMaterialClass(mutationId)) return resolveEcPrivateMaterialFixture(mutationId, stimulusInstanceId, pool);
  return resolveEcArtifactStimulusFixture(mutationId, stimulusInstanceId, pool);
}

/**
 * M3.7.3 -- the producer role for an artifact-side EC-ser obligation.
 *
 * PROPAGATES the decision the frozen resolver already made; it does not make a
 * fourth one. classifyArtifactNeed picks SPKI or PKCS8 by behavioural
 * discrimination and, where that is inconclusive, by the class's own
 * ec-ser.public.asn1 / ec-ser.private.asn1 clause. The Harness fixes what each
 * container means -- SPKI is the public material, PKCS8/RFC5915 the private --
 * so the role follows from the identity, with no DER inspected.
 *
 * EC-ROLE-CONTAINER-MISMATCH gets the BASE artifact's role, never the mutated
 * requestedRole: its baseline is an artifact whose role matches its request,
 * and the mutation then changes the request. Producing the mutated role would
 * collapse cause and detector into one.
 */
export function ecArtifactProducerRole(
  mutationId: string, stimulusInstanceId: string, pool: FrozenMaterialPool,
): 'public' | 'private' {
  // Derived from the IDENTITY of the artifact the frozen resolver actually
  // selected, by comparing against the two derived-artifact descriptors --
  // never hardcoded per class, and never by inspecting DER. For a
  // role-container class this yields the BASE artifact's role, which is what
  // the producer must emit: the mutation then flips the requested role, and
  // producing the mutated role would collapse cause and detector into one.
  const fixture = resolveEcArtifactFixture(mutationId, stimulusInstanceId, pool) as { artifact?: Uint8Array };
  const artifact = fixture.artifact;
  if (artifact === undefined) {
    throw new FixtureResolutionError(`${mutationId} has no artifact stimulus; its producer role is undetermined.`);
  }
  const hex = Buffer.from(artifact).toString('hex');
  if (hex === Buffer.from(derivedSpki(pool)).toString('hex')) return 'public';
  if (hex === Buffer.from(derivedPkcs8(pool)).toString('hex')) return 'private';
  throw new FixtureResolutionError(
    `${mutationId}: its artifact matches neither frozen derived descriptor, so no producer role is determined.`,
  );
}


/**
 * M3-reopen-v5 -- serialization role for either EC-ser direction.
 *
 * Artifact-side keeps the already-frozen artifact identity decision.
 * Material-side propagates the explicit role carried by the mutated EC
 * material. No role is inferred from the relation or backend.
 */
export function ecSerializationRole(
  mutationId: string, stimulusInstanceId: string, pool: FrozenMaterialPool,
): 'public' | 'private' {
  const base = resolveEcArtifactFixture(mutationId, stimulusInstanceId, pool);
  const mutated = (getMutationImplementation(mutationId) as {
    mutate: (fixture: unknown, stimulusInstanceId: string) => unknown;
  }).mutate(base, stimulusInstanceId);

  if (mutated !== null && typeof mutated === 'object') {
    const candidate = mutated as {
      readonly artifact?: unknown;
      readonly role?: unknown;
    };

    if (candidate.artifact instanceof Uint8Array) {
      return ecArtifactProducerRole(mutationId, stimulusInstanceId, pool);
    }

    if (candidate.role === 'public' || candidate.role === 'private') {
      return candidate.role;
    }
  }

  throw new FixtureResolutionError(
    `${mutationId}::${stimulusInstanceId} exposes neither an artifact-side `
    + `nor a material-side EC serialization role.`,
  );
}
