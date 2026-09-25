import sys, tempfile, unittest
from pathlib import Path
sys.path.insert(0,"scripts")
from final_audit import sha

class TestFinalAudit(unittest.TestCase):
    def test_sha256_known_answer(self):
        with tempfile.TemporaryDirectory() as d:
            p=Path(d)/"x"; p.write_bytes(b"abc")
            self.assertEqual(sha(p),"ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")

if __name__=="__main__": unittest.main()
