// M3-H9.3a-3.2.5b -- InteropEligibility: types.
//
// InteropEligibility(c,s) answers a question that is NEITHER applicability
// NOR executability:
//
//     Applicability(o,R)        does this relation belong to the protocol?
//     InteropEligibility(c,s)   is there an operational producer->consumer
//                               flow to evaluate for this stimulus?
//     Executability(c,s,sigma)  can THESE backends materialise this scope?
//
// M3-H9.3a-3.2.3 established the ordering
//     Applicability -> InteropEligibility -> ScopeExecutability -> Execution
// by demonstrating that collapsing the middle two into
// PlannedExecutability is not a stylistic choice: a non-eligible pair
// routed through structurally-not-executable reaches H7's own
// |Required(i,R)| = 0 branch, and 24 of 71 classes would then lose their
// ENTIRE MutationResult -- including relations that have nothing to do with
// interoperability -- because one relation they never had an obligation to
// observe was reported as unsupported.
//
// Hence, and enforced by the absence of any conversion in this module:
//     InteropEligibility  is NOT  PlannedExecutability
//     non-eligible        is NOT  structurally-not-executable(reason)
//     NonExecutionReason  is NOT  reused here

import type { GroundTruthProvenance } from '../ground-truth/schema.js';
import type { OperationId } from '../../schema/capability.js';

// ---------------------------------------------------------------------
// Provenance
//
// A SPECIALIZATION of the H9.2a union, never a parallel taxonomy. The
// M3-H9.3a-3.2.5a audit established that H9.3b partitions exhaustively as
//     contract-derived  |_|  m3-normative-decision
// with no third, structurally-derived population anywhere. So
// GroundTruthProvenance is not widened: it is narrowed at the one use site
// that can only ever be contractual.
// ---------------------------------------------------------------------

export type ContractDerivedProvenance = Extract<GroundTruthProvenance, { kind: 'contract-derived' }>;

// ---------------------------------------------------------------------
// The domain
//
// Provenance is attached to exactly ONE variant, by construction rather
// than by test. The rule the M3-H9.3a-3.2.5a audit settled is:
//
//     Provenance required  <=>  the assertion claims an EXTERNAL
//                               normative basis
//
// 'producer-contractually-blocked' claims one: a frozen v0.6 clause
// rejects the mutated producer input, so no artifact is ever produced.
// That claim must cite the clause or be unconstructible.
//
// 'no-operational-input' claims none. The fixture is a capability
// declaration {capabilityId, kind, support} or an error-mapping
// intervention {triggeringCondition, declaredErrorClass}; neither can
// begin a producer-to-consumer flow. Those classes DO carry Gamma_0
// clauses (gcm.cap.provider, gcm.error, ...), but those clauses name what
// the intervention perturbs, on a different relation -- they say nothing
// about interop flow. Citing them would forge a contractual basis. Its
// refutability comes from the other chain instead:
//     RegistryEntry -> H_entry -> FixtureMechanism -> structural probe
//
// 'eligible' likewise claims nothing: it is the state in which no clause
// blocks the flow, and an absence has no clause to cite.
//
// Therefore illegal BY CONSTRUCTION, not by assertion:
//   - eligible carrying contractual provenance
//   - no-operational-input carrying a (necessarily invented) ClauseId
//   - producer-contractually-blocked without provenance
// ---------------------------------------------------------------------

export type InteropEligibility =
  | { readonly kind: 'eligible' }
  | { readonly kind: 'non-eligible'; readonly reason: 'no-operational-input' }
  | {
      readonly kind: 'non-eligible';
      readonly reason: 'producer-contractually-blocked';
      readonly provenance: ContractDerivedProvenance;
    };

export type NonEligibilityReason = Extract<InteropEligibility, { kind: 'non-eligible' }>['reason'];

// ---------------------------------------------------------------------
// Granularity: class default + stimulus override
//
// Settled by evidence in M3-H9.3a-3.2.1, not inherited from H9.2a's own
// 74/79 statistic. Of the 71 classes with R_interop applicable, only four
// carry more than one stimulus, and probing all fourteen of their pairs
// against the contract gave 70 uniform classes and exactly ONE mixed:
// OAEP-KEY-ROLE-BYPASS, whose two stimuli fail on opposite sides of
// Dec_q(Enc_p(m)) while sharing one ClauseId and one error class.
//
//     Eligibility(c,s) = Override(c,s) if present, else Default(c)
//
// An override is therefore a positive statement that this stimulus
// differs; a redundant one is refused (I_ovr), so its mere existence
// carries information.
//
// stimulusOverrides is a plain Record, never a Map: the entry has to
// canonicalize and survive a JSON round trip unchanged (I_json).
// ---------------------------------------------------------------------

export interface ClassEligibilityEntry {
  readonly mutationId: string;
  readonly operation: OperationId;
  readonly classDefault: InteropEligibility;
  readonly stimulusOverrides?: Readonly<Record<string, InteropEligibility>>;
}

export type InteropEligibilityRegistry = readonly ClassEligibilityEntry[];

// ---------------------------------------------------------------------
// The resolved entry -- the object H_entry is computed over.
//
// It carries the identity of the pair AND the full eligibility value
// INCLUDING its provenance, because two decisions with the same outcome
// but different normative justification are not the same scientific
// object. A bare 'eligible'/'non-eligible' hash could not tell them apart.
//
// `source` records which of the two granularity levels answered, so a
// dataset reader can see that an override was applied without having to
// re-resolve against a registry it may no longer have.
// ---------------------------------------------------------------------

export interface ResolvedEligibilityEntry {
  readonly mutationId: string;
  readonly stimulusInstanceId: string;
  readonly eligibility: InteropEligibility;
  readonly source: 'class-default' | 'stimulus-override';
}

export class InteropEligibilityRegistryError extends Error {}
