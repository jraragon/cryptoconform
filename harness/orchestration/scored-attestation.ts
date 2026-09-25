// M3.7.5 / D15 -- positive scored attestation.
//
// Until now the separation ran one way only:
//
//     dry-run  =>  explicit mark          scored  =>  absence of a mark
//
// The absence of a property is not an attestation. A file with no runKind is
// indistinguishable from a file that lost one, from a hand-written one, and
// from a dry-run bundle whose wrapper was stripped. D15 closes that.
//
// ---------------------------------------------------------------------
// Where it lives, and why not anywhere else
// ---------------------------------------------------------------------
//
// In the persisted ENVELOPE, as the single authoritative source, with the
// EvidenceBundle unchanged.
//
//   Not a CLI flag: it would vanish before reaching the dataset, and the
//   dataset is what has to prove things later.
//   Not inside the bundle: the bundle is the scientific record and gains no
//   scientific field here; and duplicating the identity in two places creates
//   two writable answers to one question, which is the D13 mistake.
//   Not a sidecar file: a separate file can be swapped or lost while the
//   bundle looks intact.
//
// The envelope carries the attestation and the bundle together, and the
// attestation's digest covers the serialized bundle, so the two cannot be
// separated or recombined without detection.
//
// ---------------------------------------------------------------------
// The chain it makes traversable
// ---------------------------------------------------------------------
//
//     M4 dataset -> run attestation -> execution-policy identity
//                                   -> frozen M3 identity
//
// Every link is an identity a reader can check against the artifact it names,
// not a description.
//
// This module DECIDES NOTHING about what is scored or how it executes -- D14
// settled that. It only represents and verifies the identity D14 already
// presupposes, which is why it imports no evidence, aggregation or planning
// module.

import { createHash } from 'node:crypto';
import {
  assertRunIdentityComplete, SCORED_EXECUTION_POLICY_VERSION,
  type BlockCommit, type ScoredRunIdentity,
} from './scored-execution-policy.js';

export class ScoredAttestationError extends Error {}

/** The positive mark. Its presence is the claim; its digest is the proof. */
export interface ScoredAttestation {
  readonly kind: 'scored';
  readonly runId: string;
  readonly policyVersion: string;
  readonly instrumentCommit: string;
  readonly environmentDigest: string;
  readonly plannedObligations: number;
  readonly requiredObligations: number;
  /** SHA-256 of the serialized content this attestation vouches for. */
  readonly contentDigest: string;
  /** SHA-256 over every field above. Recomputed on verification. */
  readonly attestationDigest: string;
}

export interface ScoredEnvelope {
  readonly attestation: ScoredAttestation;
  readonly content: unknown;
}

function sha256(s: string): string {
  return createHash('sha256').update(s, 'utf8').digest('hex');
}

/**
 * The digest is computed over the fields in a FIXED order, so it cannot drift
 * with object key order, and it includes contentDigest -- so altering either
 * the identity or the content breaks it.
 */
function computeAttestationDigest(a: Omit<ScoredAttestation, 'attestationDigest'>): string {
  return sha256([
    a.kind, a.runId, a.policyVersion, a.instrumentCommit, a.environmentDigest,
    String(a.plannedObligations), String(a.requiredObligations), a.contentDigest,
  ].join('\u0000'));
}

/**
 * Creates the attestation. Deliberate by construction: it demands a complete
 * run identity and the serialized content, so nothing can be attested by
 * accident or in passing.
 */
export function attestScoredRun(params: {
  readonly identity: ScoredRunIdentity;
  readonly serializedContent: string;
}): ScoredAttestation {
  assertRunIdentityComplete(params.identity);
  if (params.identity.policyVersion !== SCORED_EXECUTION_POLICY_VERSION) {
    throw new ScoredAttestationError(
      `Run identity cites policy '${params.identity.policyVersion}', not the frozen ` +
      `'${SCORED_EXECUTION_POLICY_VERSION}'. A scored run executes the frozen policy or it is not a scored run.`,
    );
  }
  const base = {
    kind: 'scored' as const,
    runId: params.identity.runId,
    policyVersion: params.identity.policyVersion,
    instrumentCommit: params.identity.instrumentCommit,
    environmentDigest: params.identity.environmentDigest,
    plannedObligations: params.identity.plannedObligations,
    requiredObligations: params.identity.requiredObligations,
    contentDigest: sha256(params.serializedContent),
  };
  return { ...base, attestationDigest: computeAttestationDigest(base) };
}

/**
 * Fail-closed on every axis that could let something be mistaken for scored:
 * a missing attestation, a wrong kind, a foreign policy version, a tampered
 * identity, or content that is not the content attested.
 */
export function verifyScoredAttestation(
  attestation: unknown, serializedContent: string,
): asserts attestation is ScoredAttestation {
  if (attestation === null || typeof attestation !== 'object') {
    throw new ScoredAttestationError(
      'No attestation. Absence is not a claim: an artifact without one has not been shown to be scored.',
    );
  }
  const a = attestation as Partial<ScoredAttestation>;
  if (a.kind !== 'scored') {
    throw new ScoredAttestationError(`Attestation kind is '${String(a.kind)}', not 'scored'.`);
  }
  for (const field of ['runId', 'policyVersion', 'instrumentCommit', 'environmentDigest', 'contentDigest', 'attestationDigest'] as const) {
    if (typeof a[field] !== 'string' || a[field] === '') {
      throw new ScoredAttestationError(`Attestation is missing '${field}'.`);
    }
  }
  if (a.policyVersion !== SCORED_EXECUTION_POLICY_VERSION) {
    throw new ScoredAttestationError(
      `Attestation cites policy '${a.policyVersion}', not '${SCORED_EXECUTION_POLICY_VERSION}'.`,
    );
  }
  const recomputed = computeAttestationDigest(a as Omit<ScoredAttestation, 'attestationDigest'>);
  if (recomputed !== a.attestationDigest) {
    throw new ScoredAttestationError(
      'The attestation does not match its own fields; it has been altered since it was issued.',
    );
  }
  if (sha256(serializedContent) !== a.contentDigest) {
    throw new ScoredAttestationError(
      'The attestation does not correspond to this content. An attestation cannot be moved onto a different dataset.',
    );
  }
}

/**
 * The gate that makes promotion impossible.
 *
 * A dry-run artifact declares runKind 'dry-run' INSIDE its serialized form
 * (M3.5), so it is refused here whatever it is renamed to or moved into. And
 * it can never acquire an attestation by relabelling: the attestation binds a
 * content digest, so vouching for dry-run content would require issuing a new
 * attestation for it -- which is a deliberate act, not a rename, and one that
 * this function still refuses.
 */
export function assertIsScoredArtifact(envelope: unknown, serializedContent: string): void {
  const e = envelope as { runKind?: unknown; attestation?: unknown };
  if (e?.runKind === 'dry-run') {
    throw new ScoredAttestationError(
      'This is a DRY RUN artifact and cannot be presented as scored. M3.1: no result from instrument validation may ' +
      'be reused as scored M4 data.',
    );
  }
  verifyScoredAttestation(e?.attestation, serializedContent);
}

/**
 * Block commits must all belong to the attested run and its policy. Prevents
 * assembling a dataset from blocks of two different runs, which D14 already
 * refuses for consistency and which here is bound to the attestation as well.
 */
export function assertCommitsMatchAttestation(
  attestation: ScoredAttestation, commits: readonly BlockCommit[],
): void {
  for (const c of commits) {
    if (c.runId !== attestation.runId) {
      throw new ScoredAttestationError(
        `Block '${c.blockId}' belongs to run '${c.runId}', not to the attested run '${attestation.runId}'.`,
      );
    }
    if (c.policyVersion !== attestation.policyVersion) {
      throw new ScoredAttestationError(
        `Block '${c.blockId}' was produced under policy '${c.policyVersion}', not '${attestation.policyVersion}'.`,
      );
    }
  }
}

/** The traversable chain, returned as the identities a reader can check. */
export function attestationChain(a: ScoredAttestation): {
  readonly dataset: string;
  readonly run: string;
  readonly policy: string;
  readonly instrument: string;
  readonly environment: string;
} {
  return {
    dataset: a.contentDigest,
    run: a.runId,
    policy: a.policyVersion,
    instrument: a.instrumentCommit,
    environment: a.environmentDigest,
  };
}

export { SCORED_EXECUTION_POLICY_VERSION };
