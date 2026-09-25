import sys, unittest
sys.path.insert(0,"scripts")
from descriptive_analysis import scope_backends, spectrum_key

class TestDescriptive(unittest.TestCase):
 def test_scope_backends(self):
  self.assertEqual(scope_backends({"kind":"single-backend","backend":{"family":"a"}}),["a"])
  self.assertEqual(scope_backends({"kind":"backend-pair","from":{"family":"a"},"to":{"family":"b"}}),["a","b"])
  self.assertEqual(scope_backends({"kind":"cross-backend-set","backends":[{"family":"a"},{"family":"b"}]}),["a","b"])
 def test_spectrum_absence_is_explicit(self):
  r={"observedSpectrum":{"R_byte":"pass"}}
  key=spectrum_key(r)
  self.assertIn("R_byte=pass",key); self.assertIn("R_err=absent",key)
if __name__=="__main__": unittest.main()
