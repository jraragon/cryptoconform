import sys,unittest
sys.path.insert(0,"scripts")
from scientific_decisions import compare_subset,blocks_for,adequate,clause_taxonomy
from protocol import Pattern,RELATIONS

MASK=dict(zip(RELATIONS,(1,1,0,1,1,1)))
def p(values,missing=()): return Pattern("gcm",MASK,values,frozenset(missing))

class TestDecisions(unittest.TestCase):
 def test_subset_cannot_invent_difference(self):
  a=p({"R_byte":"pass","R_interop":"pass","R_val":"pass","R_err":"pass","R_cap":"pass"},("R_val",))
  b=p({"R_byte":"pass","R_interop":"pass","R_val":"fail","R_err":"pass","R_cap":"pass"})
  self.assertEqual(compare_subset(a,b,("R_val",)),"undetermined")
 def test_fixed_strata_under_ablation(self):
  a=p({"R_byte":"pass","R_interop":"pass","R_val":"pass","R_err":"pass","R_cap":"pass"},("R_val",))
  b=p({"R_byte":"pass","R_interop":"pass","R_val":"pass","R_err":"pass","R_cap":"pass"},("R_err",))
  self.assertEqual(blocks_for([a,b],()),((0,),(1,)))
 def test_adequacy_preserves_detection(self):
  a=p({"R_byte":"fail","R_interop":"pass","R_val":"pass","R_err":"pass","R_cap":"pass"})
  b=p({"R_byte":"pass","R_interop":"pass","R_val":"pass","R_err":"pass","R_cap":"pass"})
  self.assertFalse(adequate({"gcm":[a,b]},("R_interop",)))
 def test_taxonomy_parser_does_not_cross_rows(self):
  text="""\\texttt{a.one} & Input & --- & prose\\\\
  noise & not-a-kind & still-noise & prose\\\\
  \\texttt{a.two} & Parameter & Length & prose\\\\"""
  self.assertEqual(clause_taxonomy(text)["a.one"],"Input")
  self.assertEqual(clause_taxonomy(text)["a.two"],"Parameter.Length")

if __name__=="__main__":unittest.main()
