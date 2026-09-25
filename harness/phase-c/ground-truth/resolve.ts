// Bloque C1 -- ground-truth resolution and structural guards.
//
// Consumes the pre-registered table. Derives nothing: no mutate(), no
// contractual validator, no fixture. The independent probe lives in the
// tests and refutes this, never seeds it.

import { MUTATION_REGISTRY } from '../../registry/mutations.js';
import { APPLICABILITY_MATRIX } from '../../applicability/matrix.js';
import { resolveInteropEligibility } from '../interop-eligibility/resolve.js';
import { GROUND_TRUTH_TABLE } from './table.js';
import { GROUND_TRUTH_RULES, type GroundTruthRow } from './types.js';
import type { GroundTruthProvenance } from './schema.js';
import type { OperationId } from '../../schema/capability.js';

export class GroundTruthError extends Error {}

export interface ResolvedGroundTruth {
  readonly mutationId: string;
  readonly stimulusInstanceId: string;
  readonly operation: OperationId;
  readonly row: GroundTruthRow;
}

const key = (m: string, s: string) => `${m}::${s}`;

/** Fail-closed: an unknown pair is refused, never defaulted to anything. */
export function resolveGroundTruth(mutationId: string, stimulusInstanceId: string): ResolvedGroundTruth {
  const entry = MUTATION_REGISTRY.find((e) => e.mutationId === mutationId);
  if (entry === undefined) throw new GroundTruthError(`Unknown class '${mutationId}'.`);
  if (!entry.stimulusInstances.some((s) => s.stimulusInstanceId === stimulusInstanceId)) {
    throw new GroundTruthError(`'${mutationId}' declares no stimulus '${stimulusInstanceId}'.`);
  }
  const row = GROUND_TRUTH_TABLE.get(key(mutationId, stimulusInstanceId));
  if (row === undefined) {
    throw new GroundTruthError(
      `No ground truth for ${mutationId}::${stimulusInstanceId}. Refusing to supply a default: an unstated ` +
      'normative premise is not an empty one.',
    );
  }
  return { mutationId, stimulusInstanceId, operation: entry.operation, row };
}

/**
 * Provenance is DERIVED from the row's own shape rather than stored twice.
 * Citing clauses means contract-derived; citing a rule means the rule's own
 * recorded rationale. Nothing can be both, and nothing can be neither.
 */
export function provenanceOf(
  premise: { readonly clauseIds?: readonly string[]; readonly ruleId?: keyof typeof GROUND_TRUTH_RULES },
): GroundTruthProvenance {
  if (premise.clauseIds !== undefined && premise.ruleId !== undefined) {
    throw new GroundTruthError('A premise cannot be both contract-derived and an M3 decision.');
  }
  if (premise.clauseIds !== undefined) {
    if (premise.clauseIds.length === 0) {
      throw new GroundTruthError('A contract-derived premise without a clause is unconstructible.');
    }
    return { kind: 'contract-derived', clauseIds: premise.clauseIds as never };
  }
  if (premise.ruleId !== undefined) {
    const rule = GROUND_TRUTH_RULES[premise.ruleId];
    if (rule === undefined) throw new GroundTruthError(`Unknown rule '${String(premise.ruleId)}'.`);
    return { kind: 'm3-normative-decision', rationale: rule.rationale, decidedIn: rule.decidedIn };
  }
  throw new GroundTruthError('A premise must cite either a clause or a rule.');
}

export interface GroundTruthAudit {
  readonly pairs: number;
  readonly expectedValidation: { present: number; absent: number; contractDerived: number; m3Decision: number };
  readonly errorExpectation: { present: number; contractDerived: number; m3Decision: number };
  readonly checksRequired: { present: number; both: number; representationOnly: number };
  readonly expectedOutcome: { present: number; absentNonEligible: number; contractDerived: number; m3Decision: number };
}

/**
 * Exhaustive resolution over all 90 pairs with the three structural
 * invariants:
 *
 *   I-GT1  every pair resolves exactly one row
 *   I-GT2  a premise its relation requires is PRESENT
 *   I-GT3  a premise its relation does not admit is ABSENT
 *
 * "Requires" is not the same as "applicable". R_val is applicable to all six
 * operations, but a capability declaration and an error-mapping intervention
 * carry no operational input for a validator to decide on, so the premise is
 * legitimately absent there. Forcing a value to make the table total would
 * be exactly the fabrication this work exists to prevent.
 */
export function auditGroundTruth(): GroundTruthAudit {
  let pairs = 0;
  const val = { present: 0, absent: 0, contractDerived: 0, m3Decision: 0 };
  const err = { present: 0, contractDerived: 0, m3Decision: 0 };
  const ser = { present: 0, both: 0, representationOnly: 0 };
  const out = { present: 0, absentNonEligible: 0, contractDerived: 0, m3Decision: 0 };

  const seen = new Set<string>();
  for (const e of MUTATION_REGISTRY) {
    const ap = APPLICABILITY_MATRIX[e.operation];
    for (const si of e.stimulusInstances) {
      pairs += 1;
      const k = key(e.mutationId, si.stimulusInstanceId);
      if (seen.has(k)) throw new GroundTruthError(`Duplicate ground-truth row for ${k}.`);
      seen.add(k);
      const { row } = resolveGroundTruth(e.mutationId, si.stimulusInstanceId);

      if (row.expectedValidation !== undefined) {
        if (!ap.R_val) throw new GroundTruthError(`${k}: expectedValidation where R_val is not applicable.`);
        val.present += 1;
        provenanceOf(row.expectedValidation).kind === 'contract-derived' ? val.contractDerived++ : val.m3Decision++;
      } else if (ap.R_val) val.absent += 1;

      if (row.errorExpectation !== undefined) {
        if (!ap.R_err) throw new GroundTruthError(`${k}: errorExpectation where R_err is not applicable.`);
        err.present += 1;
        const p = row.errorExpectation.kind === 'error-expected'
          ? provenanceOf({ clauseIds: row.errorExpectation.clauseIds })
          : provenanceOf({ ruleId: row.errorExpectation.ruleId });
        p.kind === 'contract-derived' ? err.contractDerived++ : err.m3Decision++;
      } else if (ap.R_err) throw new GroundTruthError(`${k}: R_err is applicable but no expectation is stated.`);

      if (row.checksRequired !== undefined) {
        if (!ap.R_ser) throw new GroundTruthError(`${k}: checksRequired where R_ser is not applicable.`);
        ser.present += 1;
        row.checksRequired.basis === 'both' ? ser.both++ : ser.representationOnly++;
        provenanceOf({ ruleId: row.checksRequired.ruleId });
      } else if (ap.R_ser) throw new GroundTruthError(`${k}: R_ser is applicable but no basis is stated.`);

      const eligible = ap.R_interop
        && resolveInteropEligibility(e.mutationId, si.stimulusInstanceId).eligibility.kind === 'eligible';
      if (row.expectedOutcome !== undefined) {
        if (!eligible) {
          throw new GroundTruthError(
            `${k}: expectedOutcome where the pair is not interop-eligible. A non-eligible pair has no ` +
            'producer-to-consumer flow, and inventing a reject for it would fabricate the very result H11 refused.',
          );
        }
        out.present += 1;
        const p = row.expectedOutcome.kind === 'reject'
          ? provenanceOf({ clauseIds: row.expectedOutcome.clauseIds })
          : provenanceOf({ ruleId: row.expectedOutcome.ruleId });
        p.kind === 'contract-derived' ? out.contractDerived++ : out.m3Decision++;
      } else if (eligible) {
        throw new GroundTruthError(`${k}: interop-eligible but no expectedOutcome.`);
      } else if (ap.R_interop) out.absentNonEligible += 1;
    }
  }

  if (GROUND_TRUTH_TABLE.size !== pairs) {
    throw new GroundTruthError(`The table has ${GROUND_TRUTH_TABLE.size} rows for ${pairs} pairs -- orphan rows exist.`);
  }
  return { pairs, expectedValidation: val, errorExpectation: err, checksRequired: ser, expectedOutcome: out };
}
