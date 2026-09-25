// Bloque C3 -- relation evaluator wiring.
//
// The last link. Every applicable relation now has a REAL projector and a
// REAL evaluator, reachable by relation rather than by mutationId, so a
// PlanEntry's resolve() has something to call other than a placeholder.
//
// The dispatch is on RELATION, never on mutationId or backend: which
// evaluator judges an observation is a property of the relation alone, and
// M2.4.4's own standing restriction ("no mutationId branching anywhere") is
// preserved by giving this module no way to see one.

import type { RelationId } from '../schema/registry-types.js';
import type { ObservationState } from '../evidence/execution-status.js';
import { evaluateByte } from '../evaluators/r-byte.js';
import { evaluateInterop } from '../evaluators/r-interop.js';
import { evaluateSer } from '../evaluators/r-ser.js';
import { evaluateVal } from '../evaluators/r-val.js';
import { evaluateErr } from '../evaluators/r-err.js';
import { evaluateCap } from '../evaluators/r-cap.js';
import {
  projectByte, projectCap, projectErr, projectInterop, projectSer, projectVal, ProjectionError,
} from './evaluator-projection.js';

export class WiringError extends Error {}

/**
 * One wired relation: the projector that builds its evaluator's exact input,
 * and the evaluator itself. Held as a pair so neither can be used without the
 * other -- calling an evaluator with a hand-built input is how a convenient
 * premise gets in.
 */
export interface WiredRelation<TProjectionParams, TEvaluatorInput> {
  readonly relation: RelationId;
  readonly project: (params: TProjectionParams) => TEvaluatorInput;
  readonly evaluate: (input: TEvaluatorInput) => ObservationState;
}

/* eslint-disable @typescript-eslint/no-explicit-any */
const WIRED: Readonly<Record<RelationId, WiredRelation<any, any>>> = Object.freeze({
  R_byte: { relation: 'R_byte', project: projectByte, evaluate: evaluateByte },
  R_interop: { relation: 'R_interop', project: projectInterop, evaluate: evaluateInterop },
  R_ser: { relation: 'R_ser', project: projectSer, evaluate: evaluateSer },
  R_val: { relation: 'R_val', project: projectVal, evaluate: evaluateVal },
  R_err: { relation: 'R_err', project: projectErr, evaluate: evaluateErr },
  R_cap: { relation: 'R_cap', project: projectCap, evaluate: evaluateCap },
});
/* eslint-enable @typescript-eslint/no-explicit-any */

/** Fail-closed: an unknown relation is refused, never silently skipped. */
export function wiredRelation(relation: RelationId): WiredRelation<unknown, unknown> {
  const w = WIRED[relation];
  if (w === undefined) throw new WiringError(`No projector/evaluator wired for relation '${relation}'.`);
  return w;
}

export const WIRED_RELATIONS: readonly RelationId[] =
  Object.freeze(Object.keys(WIRED) as RelationId[]);

/**
 * Runs the full last stretch for one relation:
 *
 *     projection params -> EvaluatorInput_R -> ObservationState
 *
 * A ProjectionError is NOT converted into an observation state. A projector
 * that refuses -- same-backend R_byte, a self-serving R_cap declaration, a
 * transfer whose two sides are one execution -- is reporting a malformed
 * experiment, and turning that into 'insufficient-evidence' would file a
 * harness defect as a scientific result. It propagates.
 */
export function evaluateRelation(relation: RelationId, projectionParams: unknown): ObservationState {
  const w = wiredRelation(relation);
  const input = w.project(projectionParams);
  return w.evaluate(input);
}

export { ProjectionError };
