#!/usr/bin/env python3
"""M5 v1.0 final consolidation audit over frozen checkpoint artifacts."""
import argparse, hashlib, json, tarfile
from pathlib import Path

EXPECTED_TARS={
 "6.Paper_4_M5_Protocol_Gate_v0_1_1-FROZEN.tar.gz":"f50a94d1d6e23ce778df45d33bd476148bf1b97e5d128f3a7e8280037bea4a09",
 "6.Paper_4_M5_Descriptive_Analysis_v0_2-FROZEN.tar.gz":"2ff74965c74c21b03bd41d32f09dbf2304daecc34807b5e29f77d0bd865d2c6e",
 "6.Paper_4_M5_Scientific_Decisions_v0_3-FROZEN.tar.gz":"951cd4e846389af404d218144e542a25731fb24daa28bdf4669dbe8d201d62af",
 "6.Paper_4_M5_Robustness_v0_4-FROZEN.tar.gz":"e42608f3f0efbc5d8ca40c9c66e1328ba3b5231c5e6333cc2976735e5d1ea1ee",
}
EXPECTED_INPUTS={
 "m3Tar":"90921bae4038b55c6f9dbf14ea1fcbef2cfde6c76f0abccd5d31ec0288e14540",
 "m4Tar":"312af9cacb8dd0c02658d340675fbb6e664ca5ebcb99743904fbc8db5c182dc5",
 "m4Json":"66ec5603ed404092e51b7f4ab1b48fca69a2b8d1e83b76bc1034fcd0866daa41",
}

def sha(path):
    h=hashlib.sha256()
    with Path(path).open("rb") as f:
        for chunk in iter(lambda:f.read(1024*1024),b""): h.update(chunk)
    return h.hexdigest()

def audit(root,input_paths=None):
    root=Path(root); checks=[]
    def check(name,condition,detail):
        checks.append({"name":name,"status":"PASS" if condition else "FAIL","detail":detail})
    for name,want in EXPECTED_TARS.items():
        p=root/name; got=sha(p) if p.is_file() else None
        check(f"checkpoint-hash:{name}",got==want,{"expected":want,"actual":got})
        ok=False; members=0
        if p.is_file():
            try:
                with tarfile.open(p,"r:gz") as tf: members=len(tf.getmembers()); ok=members>0
            except tarfile.TarError: pass
        check(f"checkpoint-integrity:{name}",ok,{"members":members})
    vals={v:json.loads((root/f"derived/{v}-validation-record.json").read_text()) for v in ("v0.1.1","v0.2","v0.3","v0.4")}
    for v,d in vals.items(): check(f"validation:{v}",d.get("status",d.get("gate"))=="PASS",d.get("status",d.get("gate")))
    desc=json.loads((root/"derived/v0.2/descriptive-summary.json").read_text()); dec=json.loads((root/"derived/v0.3/scientific-decisions.json").read_text()); rob=json.loads((root/"derived/v0.4/robustness-summary.json").read_text())
    totals=desc["totals"]
    expected={"observations":886,"pass":593,"fail":293,"executions":1159,"instanceResults":84,"requiredBearingClasses":73,"registryClasses":79,"zeroRequiredClasses":6,"detectedRequiredBearingClasses":57}
    check("population-reconciliation",all(totals[k]==v for k,v in expected.items()),{k:totals[k] for k in expected})
    check("traceability",dec["traceability"]=={"requiredBearingBindings":"73/73","registryClasses":"79/79","taxonomyClauses":"76/76"},dec["traceability"])
    check("normative-Omin",dec["Omin"]["result"]==["ec-ser","gcm","pss","rsa-ser"],dec["Omin"]["result"])
    check("normative-Rmin",dec["Rmin"]["minimumFamily"]==[["R_byte","R_interop","R_ser","R_val","R_err"]],dec["Rmin"]["minimumFamily"])
    check("hypotheses",dec["hypotheses"]["H1"]==dec["hypotheses"]["H2"]==dec["hypotheses"]["H3"]=="supported",dec["hypotheses"])
    check("refutations",all(x=="not-activated" for x in dec["refutation"].values()),dec["refutation"])
    mask=rob["structuralMaskEffect"]; check("literal-mask-reproduction",mask["operationPairs"]["differentMasks"]==11 and mask["registryCrossOperationPairs"]["maskDecided"]==1756 and mask["registryCrossOperationPairs"]["total"]==2577,mask)
    check("robust-central-conclusions",rob["comparison"]["centralConclusionStable"] is True,rob["comparison"])
    check("safe-decisions-unchanged",rob["comparison"]["Omin"]["safe"]==dec["Omin"]["result"] and rob["comparison"]["Rmin"]["safe"]==dec["Rmin"],{"Omin":rob["comparison"]["Omin"],"Rmin":rob["comparison"]["Rmin"]})
    manifest=json.loads((root/"inputs/source-manifest.json").read_text())
    check("frozen-input-manifest",manifest["artifacts"]=={"m4_tar":EXPECTED_INPUTS["m4Tar"],"m4_json":EXPECTED_INPUTS["m4Json"],"m3_tar":EXPECTED_INPUTS["m3Tar"]},manifest["artifacts"])
    if input_paths:
        for key,path in input_paths.items(): check(f"input-bytes:{key}",sha(path)==EXPECTED_INPUTS[key],{"expected":EXPECTED_INPUTS[key],"actual":sha(path)})
    failed=[x for x in checks if x["status"]!="PASS"]
    return {"schema":"paper4-m5-v1.0-final-audit-v1","gate":"PASS" if not failed else "FAIL","checksPassed":len(checks)-len(failed),"checksTotal":len(checks),"checks":checks,
      "frozenScientificResult":{"population":{"observations":886,"instances":84,"requiredBearingClasses":73,"registryClasses":79,"detectedClasses":57},"Omin":["gcm","pss","rsa-ser","ec-ser"],"Rmin":["R_byte","R_interop","R_ser","R_val","R_err"],"hypotheses":{"H1":"supported","H2":"supported","H3":"supported"},"refutationsActivated":0,"normativeSemantics":"safe"}}

def main():
    ap=argparse.ArgumentParser(); ap.add_argument("--root",required=True); ap.add_argument("--m3"); ap.add_argument("--m4-tar"); ap.add_argument("--m4-json"); ap.add_argument("--output",required=True); a=ap.parse_args()
    inputs=None
    if a.m3 and a.m4_tar and a.m4_json: inputs={"m3Tar":a.m3,"m4Tar":a.m4_tar,"m4Json":a.m4_json}
    result=audit(a.root,inputs); Path(a.output).write_text(json.dumps(result,indent=2,sort_keys=True)+"\n")
    if result["gate"]!="PASS": raise SystemExit(1)

if __name__=="__main__": main()
