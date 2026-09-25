#!/usr/bin/env python3
"""Authenticate and reconcile structure without aggregating observation.status."""
import argparse, hashlib, json, tarfile
from collections import Counter
from pathlib import Path

EXPECTED = {
 "m4_tar":"312af9cacb8dd0c02658d340675fbb6e664ca5ebcb99743904fbc8db5c182dc5",
 "m4_json":"66ec5603ed404092e51b7f4ab1b48fca69a2b8d1e83b76bc1034fcd0866daa41",
 "m3_tar":"90921bae4038b55c6f9dbf14ea1fcbef2cfde6c76f0abccd5d31ec0288e14540"}
EXPECTED_BLOCKS={"hkdf":(60,7),"gcm":(231,12),"oaep":(98,11),"pss":(96,14),"rsa-ser":(243,16),"ec-ser":(158,13)}
EXPECTED_RELATIONS={"R_byte":42,"R_interop":216,"R_ser":90,"R_val":209,"R_err":91,"R_cap":238}
def sha(p): return hashlib.sha256(Path(p).read_bytes()).hexdigest()
def main():
 ap=argparse.ArgumentParser(); ap.add_argument("--m4-tar",required=True); ap.add_argument("--json",required=True); ap.add_argument("--m3-tar",required=True); ap.add_argument("--output",required=True); a=ap.parse_args()
 checks={"m4_tar_sha256":sha(a.m4_tar),"m4_json_sha256":sha(a.json),"m3_tar_sha256":sha(a.m3_tar)}
 assert checks["m4_tar_sha256"]==EXPECTED["m4_tar"] and checks["m4_json_sha256"]==EXPECTED["m4_json"] and checks["m3_tar_sha256"]==EXPECTED["m3_tar"]
 with tarfile.open(a.m4_tar,"r:gz") as t:
  files=[m for m in t.getmembers() if m.isfile()]; assert len(files)==1
  archived=hashlib.sha256(t.extractfile(files[0]).read()).hexdigest(); assert archived==EXPECTED["m4_json"]
 d=json.loads(Path(a.json).read_text()); b=d["evidenceBundle"]; att=d["attestation"]; s=d["executionSummary"]
 assert d["schema"]=="paper4-m4-scored-run-v1" and d["runId"]=="paper4-m4-v7-run-001"
 assert att["kind"]=="scored" and att["policyVersion"]=="M3.7.4/1"
 assert att["instrumentCommit"]==EXPECTED["m3_tar"] and d["instrumentSha256"]==EXPECTED["m3_tar"]
 assert att["plannedObligations"]==1641 and att["requiredObligations"]==886
 assert d["environmentDigest"]=="fac5d3dd8a3812a1a44dc26efd2d2d38a8a168b8026aa2427e0211345be6c307"
 assert att["contentDigest"]=="8bd450be9f4139db066678372b7fe013fd292ff7868354c7c26fdbc45051a9ac"
 assert att["attestationDigest"]=="b867b0f94a3501656192f55024f9fdb2c9000ca693d5794d14a15b4cf29fd16b"
 assert len(b["observations"])==886 and len(b["executions"])==1159 and len(b["instanceResults"])==84 and len(b["scientificResults"])==73 and len(b["omittedClasses"])==0
 # Deliberately do not access observations[*].status.
 by_op=Counter(x["operation"] for x in b["scientificResults"])
 block_counts={x["operation"]:(x["obligations"],x["classes"]) for x in s["blocks"]}
 assert block_counts==EXPECTED_BLOCKS and all(x["commit"]["attempt"]==1 for x in s["blocks"])
 assert len(s["requiredKeys"])==len(set(s["requiredKeys"]))==886
 assert len(s["committedKeys"])==len(set(s["committedKeys"]))==886
 assert set(s["requiredKeys"])==set(s["committedKeys"])
 by_relation=Counter(key.split("|",3)[2] for key in s["requiredKeys"])
 assert dict(by_relation)==EXPECTED_RELATIONS
 report={"gate":"PASS","outcome_fields_read":False,"hashes":checks,"archive_files":1,"population":{"planned":1641,"required":886,"observations":886,"executions":1159,"instance_results":84,"scientific_results":73,"omitted_classes":0,"blocks":len(s["blocks"]),"required_keys":len(s["requiredKeys"]),"committed_keys":len(s["committedKeys"]),"serialization_routed":len(s["serializationRouted"]),"required_bearing_classes_by_operation":dict(sorted(by_op.items()))}}
 report["population"]["required_by_relation"]=dict(sorted(by_relation.items()))
 report["population"]["required_by_operation"]={k:v[0] for k,v in sorted(block_counts.items())}
 Path(a.output).write_text(json.dumps(report,indent=2,sort_keys=True)+"\n")
if __name__=="__main__": main()
