#!/usr/bin/env python3
"""Validate the v0.1.1 diagnostic strata without reading outcome values."""
import argparse, json
from collections import Counter, defaultdict
from pathlib import Path

RELATIONS=("R_byte","R_interop","R_ser","R_val","R_err","R_cap")

def main():
    ap=argparse.ArgumentParser()
    ap.add_argument("--json",required=True)
    ap.add_argument("--out",required=True)
    a=ap.parse_args()
    run=json.loads(Path(a.json).read_text())
    results=run["evidenceBundle"]["scientificResults"]
    by_op=defaultdict(Counter)
    old_admitted=0
    for result in results:
        absent={cell["relation"] for cell in result["nonScoreable"]}
        applicable=tuple(r for r in RELATIONS if result["applicability"][r])
        scoreable=tuple(r for r in applicable if r not in absent)
        if scoreable==applicable:
            old_admitted+=1
        by_op[result["operation"]][scoreable]+=1
    report={
      "schema":"paper4-m5-v0.1.1-strata-validation-v1",
      "status":"PASS",
      "outcomeFieldsRead":False,
      "requiredBearingClasses":len(results),
      "supersededRule":{"admittedClasses":old_admitted,"excludedClasses":len(results)-old_admitted},
      "correctedRule":{"admittedClasses":sum(sum(c.values()) for c in by_op.values()),
                       "scoreableDomainStrata":sum(len(c) for c in by_op.values())},
      "operations":{
        op:{"classes":sum(counter.values()),"strata":[
          {"scoreableDomain":list(mask),"classes":n} for mask,n in sorted(counter.items())
        ]} for op,counter in sorted(by_op.items())
      }
    }
    assert report["requiredBearingClasses"]==73
    assert report["supersededRule"]=={"admittedClasses":0,"excludedClasses":73}
    assert report["correctedRule"]["admittedClasses"]==73
    assert len(report["operations"])==6
    Path(a.out).write_text(json.dumps(report,indent=2,sort_keys=True)+"\n")

if __name__=="__main__": main()
