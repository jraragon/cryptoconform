// M2.4.6 -- generic mutation implementation framework.
// Source: Paper_4_Experimental_Harness v0.21, §2 (registry), applied here.
// A MutationImplementation materializes Gamma_0(c) as a concrete transform.
// It never consults manifests/, never evaluates a relation, never produces
// a MutationResult, never reinterprets a cryptographic error.
//
// M2.4.6a correction: Gamma_0(c) is the set of clauses an intervention MAY
// perturb, not the literal set of fields a mutate() call must write. Some
// Gamma_0 members (e.g. hkdf.output) are causally-downstream consequences
// of the intervention, observed later, never written directly -- writing
// them here would fabricate the very effect the experiment exists to
// detect. The correct invariant is therefore:
//   DirectInterventionTargets(c) subset-of Gamma_0(c)   (never equality)
//   DirectInterventionTargets(c) != empty

export interface MutationImplementation<TFixture> {
  readonly mutationId: string;
  readonly mutate: (fixture: TFixture, stimulusInstanceId: string) => TFixture;
  // The fields this mutation's OWN mutate() call is permitted to write
  // directly. Must be a subset of Gamma_0(c), never asserted equal to it.
  readonly directInterventionTargets: readonly string[];
}

// Fields touched by the mutation, outside its own declared direct-
// intervention targets, must be empty -- this checks the IMPLEMENTATION's
// own discipline, not Gamma_0 completeness (that is a separate,
// registry-level subset check performed by the caller).
export function touchedFieldsOutsideAllowed<T extends Record<string, unknown>>(
  before: T,
  after: T,
  directInterventionTargets: readonly string[],
): string[] {
  const allKeys = new Set([...Object.keys(before), ...Object.keys(after)]);
  const violations: string[] = [];
  for (const key of allKeys) {
    if (directInterventionTargets.includes(key)) continue;
    if (!fieldsEqual(before[key], after[key])) violations.push(key);
  }
  return violations;
}

function fieldsEqual(a: unknown, b: unknown): boolean {
  if (a instanceof Uint8Array && b instanceof Uint8Array) {
    return a.length === b.length && a.every((v, i) => v === b[i]);
  }
  if (a === undefined && b === undefined) return true;
  return a === b;
}

export function fieldChanged<T extends Record<string, unknown>>(before: T, after: T, field: string): boolean {
  return !fieldsEqual(before[field], after[field]);
}

// The registry-level invariant: DirectInterventionTargets(c) subset-of Gamma_0(c).
// Gamma_0 clause names and directInterventionTargets field names are not
// always the identical string (e.g. clause 'hkdf.salt' vs field 'salt'),
// so callers supply a mapping from field name -> the clause name(s) it
// corresponds to; this checks that every mapped clause is indeed declared
// in Gamma_0.
export function directTargetsAreSubsetOfGamma0(
  directInterventionTargets: readonly string[],
  fieldToClause: Readonly<Record<string, string>>,
  gamma0: readonly string[],
): { readonly isSubset: boolean; readonly unmapped: readonly string[] } {
  const unmapped = directInterventionTargets.filter((f) => {
    const clause = fieldToClause[f];
    return clause === undefined || !gamma0.includes(clause);
  });
  return { isSubset: unmapped.length === 0, unmapped };
}
