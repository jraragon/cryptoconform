// M3-H9.2a -- Phase C normative ground-truth SCHEMA.
//
// Types and structure only. Nothing is populated here: the 79 classes are
// filled in H9.3, and doing so requires scientific decisions this file
// deliberately does not pre-empt.
//
// --- Why this layer exists ---
//
// Phase C has classes, stimuli, Gamma_0, applicability, expectedSpectrum,
// fixtures, executability and typed evaluators -- but four evaluators judge
// evidence against a NORMATIVE EXPECTATION the plan never carried:
//
//     ExpectedDetection(c, R)  !=  NormativeOutcome(c, s, R)
//
// The first says whether detection is expected; the second says what the
// contractually correct result IS. They are different magnitudes and
// neither derives from the other.
//
// --- Two kinds of gap, deliberately kept apart ---
//
// The H9.1 audit found the four premises are NOT alike in provenance, and
// the schema encodes that difference rather than flattening it:
//
//   IMPLIED-BUT-NOT-MATERIALIZED -- the frozen design names a source.
//     expectedErrorClass: "expectedErrorClass comes from the frozen
//       contract" (Comparable_err, condition 6).
//     expectedOutcome: "per-operation instantiations, drawn directly from
//       the frozen contracts".
//     For these, materialisation must CITE that source. A bare table
//     mutationId -> 'invalid_key' would lose exactly what makes them
//     legitimate.
//
//   UNSPECIFIED -- the frozen design fixes the DOMAIN but delegates the
//     value, and the plan never decided it.
//     checksRequired: "when both are required BY THE PLAN".
//     expectedValidation: requires "an unambiguous expected contractual
//       decision EXISTS", and explicitly forbids any default
//       (Reject =/=> fail, Accept =/=> pass).
//     For these, materialisation is a NEW normative decision of M3 and must
//     be recorded as such, with its rationale -- never disguised as a
//     derivation from something that does not determine it.
//
// The provenance union below makes that distinction unforgeable: a
// contract-derived premise cannot be recorded without a ClauseId, and a
// newly decided one cannot be recorded without a rationale.

import type { SdkErrorClass } from '../../../src/contract/errors.js';
import type { ClauseId } from '../../../src/contract/clause-ids.js';
import type { OperationId } from '../../schema/capability.js';

// ---------------------------------------------------------------------
// Provenance
// ---------------------------------------------------------------------

export type GroundTruthProvenance =
  // The frozen contract determines this value; the clause is named so the
  // assignment can be checked against it rather than trusted.
  | {
      readonly kind: 'contract-derived';
      readonly clauseIds: readonly ClauseId[];
      readonly note?: string;
    }
  // The frozen design fixes the admissible domain but not the value. This
  // is an M3 decision, recorded as one.
  | {
      readonly kind: 'm3-normative-decision';
      readonly rationale: string;
      readonly decidedIn: string; // e.g. 'M3-H9.3'
    };

// ---------------------------------------------------------------------
// R_ser -- checksRequired
//
// The frozen design enumerates exactly THREE bases
// (SerializationObservationBasis), while the executable type used two
// independent booleans and therefore admitted a fourth, meaningless state:
// {rep: false, material: false}. An R_ser observation that requires no
// check is not an observation. The union below makes the empty basis
// UNCONSTRUCTIBLE rather than merely invalid -- the same principle applied
// in b-3.5 to the absent resolve callback.
// ---------------------------------------------------------------------

export type SerializationObservationBasis =
  | 'representation-conformance'
  | 'material-preservation'
  | 'both';

// ---------------------------------------------------------------------
// R_val -- expectedValidation
//
// The vocabulary is frozen AND operation-conditioned: EC-ser's three-way
// Accept/Accept(N)/Reject, PSS's boolean verify, GCM/OAEP/RSA-ser's binary
// accept/reject, HKDF's parameter-boundary validation. verified(false) is
// NOT "PSS's reject": for a genuinely invalid signature it is the correct,
// conformant decision.
// ---------------------------------------------------------------------

export type ValidationDecisionGT =
  | { readonly kind: 'accept' }
  | { readonly kind: 'accept-normalized'; readonly normalizedForm?: string }
  | { readonly kind: 'reject' }
  | { readonly kind: 'verified'; readonly value: boolean };

// Which decisions an operation may legitimately express. Populated in H9.3
// from the frozen per-operation vocabulary; declared here so a ground-truth
// entry outside its operation's vocabulary can be refused.
export type AllowedValidationDecisions = ReadonlyMap<OperationId, ReadonlySet<ValidationDecisionGT['kind']>>;

// ---------------------------------------------------------------------
// R_err -- expectedErrorClass, or its explicit absence
//
// Absence is a first-class case, not a missing field. Comparable_err's
// condition 4 guards precisely against the verified(false) trap: a
// contractually correct outcome need not be an error at all. And
// NoReject =/=> R_err = fail -- an expected rejection that fails to
// materialise yields insufficient-evidence for R_err while R_val records
// the divergence independently.
//
// Modelled as a union so "no error expected" must be STATED, never inferred
// from an undefined field.
// ---------------------------------------------------------------------

export type ErrorExpectation =
  | { readonly kind: 'error-expected'; readonly errorClass: SdkErrorClass }
  | { readonly kind: 'no-error-expected'; readonly reason: string };

// ---------------------------------------------------------------------
// R_interop -- expectedOutcome
//
// The kind follows from the operation's own frozen instantiation
// (Dec_q(Enc_p(m)) = m; Verify_q(m, Sign_p(m)) = true;
// Import_q(Export_p(K)) === K), but a mutation may replace that normal
// outcome with rejection -- which is why the 'reject' variant exists at
// all. So the kind is operation-derived while the VALUE is per (c, s).
//
// ConsumerReject =/=> R_interop = fail: for tamper-style stimuli rejection
// IS the contractually correct outcome.
// ---------------------------------------------------------------------

export type InteropExpectedOutcomeGT =
  | { readonly kind: 'recover-bytes'; readonly expected: Uint8Array }
  | { readonly kind: 'verify'; readonly expected: boolean }
  | { readonly kind: 'import-material'; readonly expectedMaterialId: string }
  | { readonly kind: 'authenticated-decrypt'; readonly expected: Uint8Array }
  | { readonly kind: 'reject'; readonly expectedErrorClass?: SdkErrorClass };

// ---------------------------------------------------------------------
// The ground-truth record
//
// Each premise is OPTIONAL at the type level because its presence is
// governed by applicability, which is a property of the operation, not of
// this record. H9.3 enforces the four coverage invariants:
//     Applicable(c, R_val)    => expectedValidation present
//     Applicable(c, R_ser)    => checksRequired present (never empty, by type)
//     Applicable(c, R_err)    => errorExpectation present (possibly 'no-error')
//     Applicable(c, R_interop)=> expectedOutcome present
// Making them required here instead would force meaningless values onto
// classes whose operation does not have the relation -- reintroducing the
// n/a-versus-not-applicable confusion H7 was opened to prevent.
// ---------------------------------------------------------------------

export interface RelationGroundTruth {
  readonly checksRequired?: {
    readonly basis: SerializationObservationBasis;
    readonly provenance: GroundTruthProvenance;
  };
  readonly expectedValidation?: {
    readonly decision: ValidationDecisionGT;
    readonly provenance: GroundTruthProvenance;
  };
  readonly errorExpectation?: {
    readonly expectation: ErrorExpectation;
    readonly provenance: GroundTruthProvenance;
  };
  readonly expectedOutcome?: {
    readonly outcome: InteropExpectedOutcomeGT;
    readonly provenance: GroundTruthProvenance;
  };
}

// ---------------------------------------------------------------------
// Granularity: class default, stimulus override
//
// 74 of 79 classes carry a single stimulus, so a flat (class, stimulus)
// table would be 90 rows of which 74 are trivially redundant. Worse, it
// would hide the handful of cases where the ground truth genuinely differs
// between stimuli of one class -- exactly the distinction M3-H6 had to
// recover for executability.
//
//     GT(c, s) = Override(c, s)  if present, else  Default(c)
//
// An override is therefore a positive statement that this stimulus differs,
// visible by its mere existence. Keys are never derived from a mutationId's
// spelling.
// ---------------------------------------------------------------------

export interface ClassGroundTruth {
  readonly mutationId: string;
  readonly operation: OperationId;
  readonly classDefault: RelationGroundTruth;
  // Only for stimuli whose ground truth genuinely differs from the default.
  readonly stimulusOverrides?: ReadonlyMap<string, RelationGroundTruth>;
}

export type GroundTruthTable = ReadonlyMap<string, ClassGroundTruth>;

export function resolveGroundTruth(
  table: GroundTruthTable,
  mutationId: string,
  stimulusInstanceId: string,
): RelationGroundTruth | undefined {
  const entry = table.get(mutationId);
  if (entry === undefined) return undefined;
  const override = entry.stimulusOverrides?.get(stimulusInstanceId);
  return override ?? entry.classDefault;
}

// The ground truth is part of the PLAN, established before any execution:
//     ExecutionPlan = StructuralPlan + NormativeGroundTruth + Executability
// never
//     ObservedEvidence -> ExpectedOutcome
// Evidence cannot decide what the experiment expected. This module
// therefore imports nothing from the execution or evidence layers, and a
// test asserts as much.
