import unittest, sys
from itertools import product
sys.path.insert(0,"scripts")
from protocol import *

MASKS={"hkdf":dict(zip(RELATIONS,(1,0,0,1,1,1))),"oaep":dict(zip(RELATIONS,(0,1,0,1,1,1))),"gcm":dict(zip(RELATIONS,(1,1,0,1,1,1)))}
def p(op,val="pass",missing=()):
 a=MASKS[op]; return Pattern(op,a,{r:(val if a[r] else "n/a") for r in RELATIONS if r not in missing},frozenset(missing))
class TestProtocol(unittest.TestCase):
 def test_mask_cannot_different(self): self.assertEqual(compare_patterns(p("hkdf"),p("oaep")),"same")
 def test_witness(self): self.assertEqual(compare_patterns(p("hkdf","fail"),p("oaep")),"different")
 def test_missing_inside_j(self): self.assertEqual(compare_patterns(p("gcm",missing=("R_val",)),p("oaep")),"undetermined")
 def test_missing_outside_j(self): self.assertEqual(compare_patterns(p("gcm",missing=("R_byte",)),p("oaep")),"same")
 def test_safe_partition_stratifies_non_scoreable(self):
  groups,strata=safe_partition([p("gcm"),p("gcm",missing=("R_val",))])
  self.assertEqual((len(groups),len(strata)),(2,2))
  self.assertEqual({s[0] for s in strata}, {scoreable_domain(p("gcm")),scoreable_domain(p("gcm",missing=("R_val",)))})
 def test_non_scoreable_is_not_missing_required_evidence(self):
  a=p("gcm",missing=("R_val",)); b=p("gcm",missing=("R_val",))
  groups,strata=safe_partition([a,b])
  self.assertEqual((len(groups),len(groups[0]),len(strata)),(1,2,1))
 def test_exclusivity(self):
  self.assertEqual(demonstrated_exclusive(p("hkdf"),[p("oaep")]),"demonstrated-reproduced")
  self.assertEqual(demonstrated_exclusive(p("hkdf","fail"),[p("oaep")]),"demonstrated-exclusive")
  self.assertEqual(demonstrated_exclusive(p("hkdf"),[p("oaep",missing=("R_val",))]),"undetermined-exclusive")
 def test_64_subsets(self): self.assertEqual(len(list(relation_subsets())),64)
 def test_evidence_ablation_monotonicity(self):
  full_a, full_b = p("gcm", "pass"), p("gcm", "fail")
  self.assertEqual(compare_patterns(full_a, full_b), "different")
  for removed in RELATIONS:
   if not full_a.applicability[removed]: continue
   ablated = Pattern(full_a.operation, full_a.applicability, full_a.spectrum,
                     frozenset((removed,)))
   self.assertIn(compare_patterns(ablated, full_b), ("different", "undetermined"))
 def test_safe_same_is_equivalence_on_complete_domain(self):
  vectors = []
  applicable = tuple(r for r in RELATIONS if MASKS["gcm"][r])
  for bits in product(("pass", "fail"), repeat=len(applicable)):
   vectors.append(Pattern("gcm", MASKS["gcm"], dict(zip(applicable, bits))))
  for a in vectors: self.assertEqual(compare_patterns(a, a), "same")
  for a, b in zip(vectors, reversed(vectors)):
   self.assertEqual(compare_patterns(a, b), compare_patterns(b, a))
 def test_partition_never_merges_scoreable_masks(self):
  a=p("gcm",missing=("R_val",)); b=p("gcm",missing=("R_err",))
  self.assertNotEqual(partition_signature([a,b]), ((0,1),))
 def test_ablation_keeps_original_strata_fixed(self):
  a=p("gcm",missing=("R_val",)); b=p("gcm",missing=("R_err",))
  self.assertEqual(partition_signature([a,b],("R_byte",)),((0,),(1,)))
 def test_rmin_unique_and_multiple(self):
  a = Pattern("hkdf", MASKS["hkdf"], {"R_byte":"pass","R_val":"pass","R_err":"pass","R_cap":"pass"})
  b = Pattern("hkdf", MASKS["hkdf"], {"R_byte":"fail","R_val":"pass","R_err":"pass","R_cap":"pass"})
  self.assertEqual(minimum_adequate_subsets({"hkdf":[a,b]}), (("R_byte",),))
  c = Pattern("hkdf", MASKS["hkdf"], {"R_byte":"fail","R_val":"fail","R_err":"pass","R_cap":"pass"})
  minima = minimum_adequate_subsets({"hkdf":[a,c]})
  self.assertEqual(set(minima), {("R_byte",), ("R_val",)})
 def test_d052_known_answer(self):
  a = Pattern("hkdf", MASKS["hkdf"], {"R_byte":"pass","R_val":"pass","R_err":"pass","R_cap":"pass"})
  b = Pattern("hkdf", MASKS["hkdf"], {"R_byte":"fail","R_val":"pass","R_err":"pass","R_cap":"pass"})
  self.assertEqual(diagnostic_delta([a,b], 0, "R_byte"), (1, 0.5))
if __name__=="__main__": unittest.main()
