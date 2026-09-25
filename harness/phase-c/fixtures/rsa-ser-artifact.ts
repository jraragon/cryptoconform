// M3.2.4b-2.15-R -- RSA-ser x artifact-transform fixture resolvers.
//
// The final binding group: 15 classes, 19 pairs, FOUR shapes.
//
//   RsaPublicMaterial            6 classes
//   { artifact }                 5 classes
//   RsaPrivateMaterial           3 classes
//   { artifact, requestedRole }  1 class
//
// Note the distribution is INVERTED relative to EC-ser, where artifacts
// dominated (8 of 11). Here material classes dominate (9 of 15).
//
// --- Shape classification, derived from intervention targets ---
//
// A class intervening on 'artifact' or 'requestedRole' is serialized. A
// material class whose targets fall entirely within { n, e } can only be
// operating on a PUBLIC key, since those are the sole components
// RsaPublicMaterial has; anything touching d, p, q, dP, dQ or qInv is
// private. No classification rests on a mutationId.
//
// --- Artifact selection: the third level of decision ---
//
// EC-ser needed two mechanisms; RSA-ser needs three, because the second
// fails here:
//
//   1. BEHAVIOUR. Two classes intervene on the AlgorithmIdentifier at a
//      position only SPKI has there, and throw on PrivateKeyInfo. Decisive.
//
//   2. Gamma_0. Useless here: RSA-ser's clauses are ROLE-AGNOSTIC
//      (der-syntax, container, exact-consumption, role-container,
//      algorithm-id, algorithm-params). None names a role, unlike EC-ser's
//      own 'ec-ser.public.asn1' / 'ec-ser.private.asn1'.
//
//   3. EXPLICIT PROTOCOL DECISION. The remaining four are genuinely
//      role-agnostic, so their artifact is not derivable at all. They are
//      assigned PrivateKeyInfo, which yields
//          Coverage(SPKI) > 0  AND  Coverage(PrivateKeyInfo) > 0
//      -- a container the frozen contract supports would otherwise never
//      participate in Phase C despite having been qualified. The greater
//      structural richness of PrivateKeyInfo is a secondary consideration
//      only; no claim is made that it makes these interventions more
//      sensitive, since that has not been measured.
//
// Artifacts come exclusively from the qualified descriptors, never from a
// direct encoder call:
//     Resolver selects; Descriptor identifies; Encoder derives; Hash authenticates.

import type { RsaPublicMaterial, RsaPrivateMaterial } from '../../../src/contract/rsa-ser.js';
import { encodeSpki, encodePrivateKeyInfo } from '../../../src/contract/rsa-ser.js';
import type { FrozenMaterialPool } from '../material/pool.js';
import type { Rsa3072KeyPairMaterial, MaterialValue } from '../material/schema.js';
import { PHASE_C_MATERIAL_IDS, PHASE_C_DERIVED_ARTIFACT_IDS } from '../material/load.js';
import { MUTATION_REGISTRY } from '../../registry/mutations.js';
import { FixtureResolutionError } from './hkdf-request.js';
import { getMutationImplementation } from '../mutation-index.js';

export interface RsaArtifactStimulus {
  readonly artifact: Uint8Array;
}
export interface RsaRoleContainerStimulus {
  readonly artifact: Uint8Array;
  readonly requestedRole: 'public' | 'private';
}

const RSA_ARTIFACT_ENTRIES = MUTATION_REGISTRY.filter(
  (e) => e.operation === 'rsa-ser' && e.mechanism === 'artifact-transform',
);

export const RSA_ARTIFACT_MUTATION_IDS: readonly string[] =
  RSA_ARTIFACT_ENTRIES.map((e) => e.mutationId).sort();

export const RSA_ARTIFACT_STIMULUS_PAIRS: readonly (readonly [string, string])[] =
  RSA_ARTIFACT_ENTRIES
    .flatMap((e) => e.stimulusInstances.map((s) => [e.mutationId, s.stimulusInstanceId] as const))
    .sort((a, b) => (a[0] === b[0] ? a[1].localeCompare(b[1]) : a[0].localeCompare(b[0])));

function targetsOf(mutationId: string): readonly string[] {
  return getMutationImplementation(mutationId).directInterventionTargets.map(String);
}

export function isRsaRoleContainerClass(mutationId: string): boolean {
  return targetsOf(mutationId).includes('requestedRole');
}
export function isRsaBareArtifactClass(mutationId: string): boolean {
  const t = targetsOf(mutationId);
  return t.includes('artifact') && !t.includes('requestedRole');
}
// Public material carries only { n, e }; a class confined to those two can
// only be operating on a public key.
export function isRsaPublicMaterialClass(mutationId: string): boolean {
  const t = targetsOf(mutationId);
  if (t.includes('artifact') || t.includes('requestedRole')) return false;
  return t.every((x) => x === 'n' || x === 'e');
}
export function isRsaPrivateMaterialClass(mutationId: string): boolean {
  const t = targetsOf(mutationId);
  if (t.includes('artifact') || t.includes('requestedRole')) return false;
  return !isRsaPublicMaterialClass(mutationId);
}

const big = (b: Uint8Array): bigint => BigInt('0x' + Buffer.from(b).toString('hex'));

function frozenPublic(pool: FrozenMaterialPool): RsaPublicMaterial {
  const r = pool.valueOf<Rsa3072KeyPairMaterial>(PHASE_C_MATERIAL_IDS.rsa, 'rsa-3072-keypair');
  return { role: 'public', n: big(r.n), e: big(r.e) };
}
function frozenPrivate(pool: FrozenMaterialPool): RsaPrivateMaterial {
  const r = pool.valueOf<Rsa3072KeyPairMaterial>(PHASE_C_MATERIAL_IDS.rsa, 'rsa-3072-keypair');
  return {
    role: 'private', n: big(r.n), e: big(r.e), d: big(r.d),
    p: big(r.p), q: big(r.q), dP: big(r.dp), dQ: big(r.dq), qInv: big(r.qi),
  };
}

const spkiEncoder = (v: MaterialValue): Uint8Array => {
  const r = v as Rsa3072KeyPairMaterial;
  return encodeSpki({ role: 'public', n: big(r.n), e: big(r.e) });
};
const pkiEncoder = (v: MaterialValue): Uint8Array => {
  const r = v as Rsa3072KeyPairMaterial;
  return encodePrivateKeyInfo({
    role: 'private', n: big(r.n), e: big(r.e), d: big(r.d),
    p: big(r.p), q: big(r.q), dP: big(r.dp), dQ: big(r.dq), qInv: big(r.qi),
  });
};

function derivedSpki(pool: FrozenMaterialPool): Uint8Array {
  return pool.deriveArtifact(PHASE_C_DERIVED_ARTIFACT_IDS.rsaSpki, spkiEncoder);
}
function derivedPrivateKeyInfo(pool: FrozenMaterialPool): Uint8Array {
  return pool.deriveArtifact(PHASE_C_DERIVED_ARTIFACT_IDS.rsaPrivateKeyInfo, pkiEncoder);
}

// Classes that REQUIRE SPKI, established by probing rather than by name:
// they reject PrivateKeyInfo outright.
const REQUIRES_SPKI = new Set<string>();
let classified = false;

function classifyArtifactNeed(pool: FrozenMaterialPool): void {
  if (classified) return;
  const pki = derivedPrivateKeyInfo(pool);
  for (const entry of RSA_ARTIFACT_ENTRIES) {
    const id = entry.mutationId;
    if (!isRsaBareArtifactClass(id) && !isRsaRoleContainerClass(id)) continue;
    const probe = isRsaRoleContainerClass(id)
      ? { artifact: pki, requestedRole: 'private' as const }
      : { artifact: pki };
    try {
      getMutationImplementation(id).mutate(probe, 'default');
    } catch {
      REQUIRES_SPKI.add(id); // rejects the private container: SPKI is mandatory
    }
  }
  classified = true;
}

function assertRegistered(mutationId: string, stimulusInstanceId: string): void {
  const known = RSA_ARTIFACT_STIMULUS_PAIRS.some(([m, s]) => m === mutationId && s === stimulusInstanceId);
  if (!known) {
    throw new FixtureResolutionError(
      `(${mutationId}, ${stimulusInstanceId}) is not a registered rsa-ser x artifact-transform stimulus pair.`,
    );
  }
}

// ---------------------------------------------------------------------
// R1: { artifact } -- 5 classes
// ---------------------------------------------------------------------

export function resolveRsaArtifactStimulusFixture(
  mutationId: string,
  stimulusInstanceId: string,
  pool: FrozenMaterialPool,
): RsaArtifactStimulus {
  assertRegistered(mutationId, stimulusInstanceId);
  if (!isRsaBareArtifactClass(mutationId)) {
    throw new FixtureResolutionError(`${mutationId} does not use a bare artifact stimulus.`);
  }
  classifyArtifactNeed(pool);
  return { artifact: REQUIRES_SPKI.has(mutationId) ? derivedSpki(pool) : derivedPrivateKeyInfo(pool) };
}

// ---------------------------------------------------------------------
// R2: RsaPublicMaterial -- 6 classes
// ---------------------------------------------------------------------

export function resolveRsaPublicMaterialFixture(
  mutationId: string,
  stimulusInstanceId: string,
  pool: FrozenMaterialPool,
): RsaPublicMaterial {
  assertRegistered(mutationId, stimulusInstanceId);
  if (!isRsaPublicMaterialClass(mutationId)) {
    throw new FixtureResolutionError(`${mutationId} does not use RsaPublicMaterial.`);
  }
  return frozenPublic(pool);
}

// ---------------------------------------------------------------------
// R3: RsaPrivateMaterial -- 3 classes
// ---------------------------------------------------------------------

export function resolveRsaPrivateMaterialFixture(
  mutationId: string,
  stimulusInstanceId: string,
  pool: FrozenMaterialPool,
): RsaPrivateMaterial {
  assertRegistered(mutationId, stimulusInstanceId);
  if (!isRsaPrivateMaterialClass(mutationId)) {
    throw new FixtureResolutionError(`${mutationId} does not use RsaPrivateMaterial.`);
  }
  const m = frozenPrivate(pool);

  // Baseline validity: the relations these classes exist to break must hold
  // BEFORE the intervention, or breaking one would measure nothing. Pure
  // modular arithmetic over frozen values; nothing is generated.
  if (m.p * m.q !== m.n) throw new FixtureResolutionError('frozen material fails n = pq');
  const gcd = (a: bigint, b: bigint): bigint => (b === 0n ? a : gcd(b, a % b));
  const lambda = ((m.p - 1n) * (m.q - 1n)) / gcd(m.p - 1n, m.q - 1n);
  if ((m.e * m.d) % lambda !== 1n) throw new FixtureResolutionError('frozen material fails ed = 1 mod lambda(n)');
  if (m.dP !== m.d % (m.p - 1n)) throw new FixtureResolutionError('frozen material fails dP = d mod (p-1)');
  if (m.dQ !== m.d % (m.q - 1n)) throw new FixtureResolutionError('frozen material fails dQ = d mod (q-1)');
  if ((m.qInv * m.q) % m.p !== 1n) throw new FixtureResolutionError('frozen material fails qInv*q = 1 mod p');
  if (m.p === m.q) throw new FixtureResolutionError('frozen material has p = q, so the domain bypass would be a no-op');

  return m;
}

// ---------------------------------------------------------------------
// R4: { artifact, requestedRole } -- 1 class
// ---------------------------------------------------------------------

export function resolveRsaRoleContainerFixture(
  mutationId: string,
  stimulusInstanceId: string,
  pool: FrozenMaterialPool,
): RsaRoleContainerStimulus {
  assertRegistered(mutationId, stimulusInstanceId);
  if (!isRsaRoleContainerClass(mutationId)) {
    throw new FixtureResolutionError(`${mutationId} does not use a role-container stimulus.`);
  }
  classifyArtifactNeed(pool);
  // Baseline: artifact and requested role AGREE, so the mutation -- which
  // flips only the role -- creates a genuine mismatch rather than starting
  // from one.
  return REQUIRES_SPKI.has(mutationId)
    ? { artifact: derivedSpki(pool), requestedRole: 'public' }
    : { artifact: derivedPrivateKeyInfo(pool), requestedRole: 'private' };
}

export function resolveRsaArtifactFixture(
  mutationId: string,
  stimulusInstanceId: string,
  pool: FrozenMaterialPool,
): RsaArtifactStimulus | RsaPublicMaterial | RsaPrivateMaterial | RsaRoleContainerStimulus {
  if (isRsaRoleContainerClass(mutationId)) return resolveRsaRoleContainerFixture(mutationId, stimulusInstanceId, pool);
  if (isRsaBareArtifactClass(mutationId)) return resolveRsaArtifactStimulusFixture(mutationId, stimulusInstanceId, pool);
  if (isRsaPublicMaterialClass(mutationId)) return resolveRsaPublicMaterialFixture(mutationId, stimulusInstanceId, pool);
  return resolveRsaPrivateMaterialFixture(mutationId, stimulusInstanceId, pool);
}

/**
 * Pre-experimental RSA serialization role for either frozen direction.
 *
 * Material-side stimuli exercise export and carry their own public/private
 * role after mutation. Artifact-side stimuli exercise import and retain the
 * producer role selected by the frozen artifact resolver.
 *
 * This function only propagates information already present in the frozen
 * fixture/mutation. It does not infer a role from a mutationId or inspect DER.
 */
export function rsaSerializationRole(
  mutationId: string,
  stimulusInstanceId: string,
  pool: FrozenMaterialPool,
): 'public' | 'private' {
  const base = resolveRsaArtifactFixture(
    mutationId,
    stimulusInstanceId,
    pool,
  );

  const mutated = (getMutationImplementation(mutationId) as {
    mutate: (fixture: unknown, stimulusInstanceId: string) => unknown;
  }).mutate(base, stimulusInstanceId);

  if (mutated !== null && typeof mutated === 'object') {
    const candidate = mutated as {
      readonly artifact?: unknown;
      readonly role?: unknown;
    };

    if (candidate.artifact instanceof Uint8Array) {
      return rsaArtifactProducerRole(
        mutationId,
        stimulusInstanceId,
        pool,
      );
    }

    if (candidate.role === 'public' || candidate.role === 'private') {
      return candidate.role;
    }
  }

  throw new FixtureResolutionError(
    `${mutationId}::${stimulusInstanceId} exposes neither an artifact-side `
    + `nor a material-side RSA serialization role.`,
  );
}

/**
 * M3.7.3 -- the producer role for an artifact-side RSA-ser obligation.
 *
 * Symmetric to ecArtifactProducerRole, and for the same reason: it PROPAGATES
 * the decision the frozen resolver already made, by comparing the artifact it
 * selected against the two derived-artifact descriptors. Not a default of
 * 'private', not a class name, and no DER inspected.
 *
 *     A_0 == rsa-3072-spki-derived-01              -> public
 *     A_0 == rsa-3072-private-key-info-derived-01  -> private
 *
 * A role-container class gets the BASE artifact's role: its mutation flips the
 * requested role afterwards, and producing the flipped one would collapse
 * cause and detector into one.
 */
export function rsaArtifactProducerRole(
  mutationId: string, stimulusInstanceId: string, pool: FrozenMaterialPool,
): 'public' | 'private' {
  const fixture = resolveRsaArtifactFixture(mutationId, stimulusInstanceId, pool) as { artifact?: Uint8Array };
  const artifact = fixture.artifact;
  if (artifact === undefined) {
    throw new FixtureResolutionError(`${mutationId} has no artifact stimulus; its producer role is undetermined.`);
  }
  const hex = Buffer.from(artifact).toString('hex');
  if (hex === Buffer.from(derivedSpki(pool)).toString('hex')) return 'public';
  if (hex === Buffer.from(derivedPrivateKeyInfo(pool)).toString('hex')) return 'private';
  throw new FixtureResolutionError(
    `${mutationId}: its artifact matches neither frozen derived descriptor, so no producer role is determined.`,
  );
}
