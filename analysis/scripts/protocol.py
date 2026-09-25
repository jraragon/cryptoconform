"""M5 v0.1 pre-analysis contract. No M4 outcome aggregation is permitted here."""
from dataclasses import dataclass
from itertools import combinations

RELATIONS = ("R_byte", "R_interop", "R_ser", "R_val", "R_err", "R_cap")

@dataclass(frozen=True)
class Pattern:
    operation: str
    applicability: dict
    spectrum: dict
    non_scoreable: frozenset = frozenset()

def scoreable_domain(p):
    return tuple(r for r in RELATIONS if p.applicability[r] and r not in p.non_scoreable)

def jointly_applicable(a, b):
    return tuple(r for r in RELATIONS if a.applicability[r] and b.applicability[r])

def compare_patterns(a, b):
    """Literal port of the M3-H12 ternary comparator."""
    j = jointly_applicable(a, b)
    sa, sb = set(scoreable_domain(a)), set(scoreable_domain(b))
    c = tuple(r for r in j if r in sa and r in sb)
    for r in c:
        if a.spectrum.get(r) != b.spectrum.get(r):
            return "different"
    return "same" if len(c) == len(j) else "undetermined"

def safe_partition(patterns):
    """Partition within homogeneous scoreable-domain strata.

    A declared NonScoreableCell narrows the structural domain; it is not
    missing Required evidence.  Equality is therefore an equivalence only
    among classes with the same S_c.  Cross-stratum comparisons retain the
    ternary H12 semantics and are never forced into this partition.
    """
    strata = {}
    for p in patterns:
        mask = scoreable_domain(p)
        key = tuple((r, p.spectrum[r]) for r in mask)
        strata.setdefault(mask, {}).setdefault(key, []).append(p)
    blocks = tuple(tuple(v) for mask in sorted(strata) for v in strata[mask].values())
    memberships = tuple((mask, tuple(p for values in strata[mask].values() for p in values))
                        for mask in sorted(strata))
    return blocks, memberships

def demonstrated_exclusive(p, competitors):
    verdicts = tuple(compare_patterns(p, q) for q in competitors)
    if verdicts and all(v == "different" for v in verdicts): return "demonstrated-exclusive"
    if "same" in verdicts: return "demonstrated-reproduced"
    return "undetermined-exclusive"

def relation_subsets():
    for n in range(len(RELATIONS) + 1):
        yield from combinations(RELATIONS, n)

def detected(p, relations=RELATIONS):
    domain = set(scoreable_domain(p)) & set(relations)
    return any(p.spectrum.get(r) == "fail" for r in domain)

def partition_signature(patterns, relations=RELATIONS):
    """Partition signature within the fixed full S_c strata.

    Relation ablation changes signatures but never the original comparison
    strata; otherwise removing a relation could manufacture comparability.
    """
    groups = {}
    for index, p in enumerate(patterns):
        mask = scoreable_domain(p)
        key = (mask, tuple((r, p.spectrum[r]) for r in relations if r in mask))
        groups.setdefault(key, []).append(index)
    return tuple(sorted(tuple(v) for v in groups.values()))

def adequate_subset(patterns_by_operation, relations):
    relations = tuple(relations)
    all_patterns = [p for ps in patterns_by_operation.values() for p in ps]
    if tuple(detected(p, relations) for p in all_patterns) != tuple(detected(p) for p in all_patterns):
        return False
    return all(partition_signature(ps, relations) == partition_signature(ps)
               for ps in patterns_by_operation.values())

def minimum_adequate_subsets(patterns_by_operation):
    adequate = [s for s in relation_subsets() if adequate_subset(patterns_by_operation, s)]
    if not adequate: return tuple()
    width = min(map(len, adequate))
    return tuple(s for s in adequate if len(s) == width)

def safe_detection_exclusivity(target, foreign_patterns):
    return demonstrated_exclusive(target, foreign_patterns)

def diagnostic_delta(patterns, index, relation):
    """D-052 Delta and DG inside fixed scoreable-domain strata."""
    full = partition_signature(patterns)
    reduced_relations = tuple(r for r in RELATIONS if r != relation)
    reduced = partition_signature(patterns, reduced_relations)
    def block_size(partition):
        return next(len(block) for block in partition if index in block)
    h_full, h_reduced = block_size(full), block_size(reduced)
    return h_reduced - h_full, 1 - h_full / h_reduced
