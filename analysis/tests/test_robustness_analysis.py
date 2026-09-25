import sys, unittest
sys.path.insert(0,"scripts")
from protocol import RELATIONS, Pattern
from robustness_analysis import literal_value, literal_signature, literal_blocks, literal_adequate

def p(mask,values,missing=(),op="x"):
    return Pattern(op,dict(zip(RELATIONS,mask)),values,frozenset(missing))

class TestRobustness(unittest.TestCase):
    def test_literal_mask_manufactures_difference(self):
        a=p((1,0,0,1,1,1),{"R_byte":"pass","R_val":"pass","R_err":"pass","R_cap":"pass"})
        b=p((0,1,0,1,1,1),{"R_interop":"pass","R_val":"pass","R_err":"pass","R_cap":"pass"})
        self.assertNotEqual(literal_signature(a),literal_signature(b))

    def test_non_scoreable_is_explicit_absent(self):
        a=p((1,0,0,1,1,1),{"R_byte":"pass","R_val":"pass","R_cap":"pass"},("R_err",))
        self.assertEqual(literal_value(a,"R_err"),"absent")
        self.assertEqual(literal_value(a,"R_interop"),"n/a")

    def test_literal_blocks(self):
        a=p((1,0,0,1,1,1),{"R_byte":"pass","R_val":"pass","R_err":"pass","R_cap":"pass"})
        b=p((1,0,0,1,1,1),{"R_byte":"pass","R_val":"pass","R_err":"pass","R_cap":"pass"})
        c=p((1,0,0,1,1,1),{"R_byte":"fail","R_val":"pass","R_err":"pass","R_cap":"pass"})
        self.assertEqual(literal_blocks([a,b,c]),((0,1),(2,)))

    def test_literal_adequacy_preserves_detection(self):
        a=p((1,0,0,1,1,1),{"R_byte":"fail","R_val":"pass","R_err":"pass","R_cap":"pass"})
        self.assertFalse(literal_adequate({"x":[a]},("R_val",)))

if __name__=="__main__": unittest.main()
