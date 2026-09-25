#!/usr/bin/env python3
"""M5 v0.2 descriptive analysis. No gain, minimal-set, hypothesis or refutation logic."""
import argparse, csv, json
from collections import Counter, defaultdict
from pathlib import Path

RELATIONS=("R_byte","R_interop","R_ser","R_val","R_err","R_cap")
OPERATIONS=("hkdf","gcm","oaep","pss","rsa-ser","ec-ser")

def scope_backends(scope):
    kind=scope["kind"]
    if kind in ("single-backend","manifest"): return [scope["backend"]["family"]]
    if kind=="backend-pair": return [scope["from"]["family"],scope["to"]["family"]]
    if kind=="cross-backend-set": return [x["family"] for x in scope["backends"]]
    raise ValueError(kind)

def spectrum_key(result):
    return ";".join(f"{r}={result['observedSpectrum'].get(r,'absent')}" for r in RELATIONS)

def nested(counter, keys):
    out=counter
    for key in keys: out=out[key]
    return out

def write_csv(path, header, rows):
    with Path(path).open("w",newline="") as f:
        w=csv.writer(f); w.writerow(header); w.writerows(rows)

def analyse(run, registry):
    b=run["evidenceBundle"]
    reg={e["mutationId"]:e for e in registry["entries"]}
    sci={e["mutationId"]:e for e in b["scientificResults"]}
    inst_op={e["mutationId"]:e["operation"] for e in b["instanceResults"]}
    op_of=lambda mid: sci[mid]["operation"] if mid in sci else reg[mid]["operation"]

    obs=Counter(); scopes=Counter(); providers=Counter(); directions=Counter()
    for o in b["observations"]:
        op=op_of(o["context"]["mutationId"]); rel=o["relation"]; status=o["status"]
        obs[(op,rel,status)]+=1; scopes[(o["scope"]["kind"],status)]+=1
        for provider in set(scope_backends(o["scope"])): providers[(provider,status)]+=1
        if o["scope"]["kind"]=="backend-pair":
            directions[(o["scope"]["from"]["family"],o["scope"]["to"]["family"],status)]+=1

    executions=Counter()
    for e in b["executions"]:
        executions[(e["operation"],e["subject"]["backend"]["family"],e["subject"]["path"],e["outcome"]["kind"])]+=1

    classes=[]; patterns=Counter(); non_score=Counter(); mechanisms=Counter()
    for r in b["scientificResults"]:
        ns=len(r["nonScoreable"]); complete=r["requiredEvidenceComplete"]
        detected=r["detectionSupport"]["divergentInstances"]>0
        classes.append({"mutationId":r["mutationId"],"operation":r["operation"],"mechanism":reg[r["mutationId"]]["mechanism"],
          "instances":len(r["instanceResultRefs"]),"evaluatedInstances":r["detectionSupport"]["evaluatedInstances"],
          "divergentInstances":r["detectionSupport"]["divergentInstances"],"detected":detected,
          "requiredEvidenceComplete":complete,"nonScoreableCells":ns,"spectrum":spectrum_key(r)})
        patterns[(r["operation"],spectrum_key(r))]+=1
        mechanisms[(r["operation"],reg[r["mutationId"]]["mechanism"],detected)]+=1
        for cell in r["nonScoreable"]: non_score[(r["operation"],cell["relation"],cell["cause"])]+=1

    zero=sorted(set(reg)-set(sci))
    assert len(zero)==6 and len(classes)==73 and len(b["observations"])==886
    assert sum(obs.values())==886 and sum(executions.values())==1159
    summary={
      "schema":"paper4-m5-v0.2-descriptive-v1","runId":run["runId"],
      "boundaries":{"descriptiveOnly":True,"gainsComputed":False,"minimalSetsComputed":False,
                    "hypothesesEvaluated":False,"refutationCriteriaEvaluated":False},
      "totals":{"observations":886,"pass":sum(v for (op,r,s),v in obs.items() if s=="pass"),
                "fail":sum(v for (op,r,s),v in obs.items() if s=="fail"),"executions":1159,
                "instanceResults":len(b["instanceResults"]),"requiredBearingClasses":len(classes),
                "registryClasses":len(reg),"zeroRequiredClasses":len(zero),
                "detectedRequiredBearingClasses":sum(x["detected"] for x in classes),
                "requiredEvidenceCompleteClasses":sum(x["requiredEvidenceComplete"] for x in classes),
                "requiredEvidenceIncompleteClasses":sum(not x["requiredEvidenceComplete"] for x in classes)},
      "zeroRequiredClasses":[reg[x] for x in zero],
      "nonScoreableCells":{"total":sum(non_score.values()),"byCause":dict(sorted(Counter({cause:sum(v for (op,r,c),v in non_score.items() if c==cause) for cause in {k[2] for k in non_score}}).items()))},
      "notes":["Observation counts are obligation-level and are not independent defect replicates.",
               "Provider involvement in a relational observation is not provider blame or causal attribution.",
               "Detected class means at least one divergent stimulus instance; no exclusivity or gain is evaluated."],
      "classes":classes}
    return summary,obs,scopes,providers,directions,executions,patterns,non_score,mechanisms

def main():
    ap=argparse.ArgumentParser(); ap.add_argument("--json",required=True); ap.add_argument("--registry",required=True); ap.add_argument("--outdir",required=True); a=ap.parse_args()
    run=json.loads(Path(a.json).read_text()); registry=json.loads(Path(a.registry).read_text()); out=Path(a.outdir); out.mkdir(parents=True,exist_ok=True)
    summary,obs,scopes,providers,directions,executions,patterns,non_score,mechanisms=analyse(run,registry)
    (out/"descriptive-summary.json").write_text(json.dumps(summary,indent=2,sort_keys=True)+"\n")
    write_csv(out/"observations-by-operation-relation.csv",["operation","relation","pass","fail","total"],[(op,r,obs[(op,r,"pass")],obs[(op,r,"fail")],obs[(op,r,"pass")]+obs[(op,r,"fail")]) for op in OPERATIONS for r in RELATIONS if obs[(op,r,"pass")]+obs[(op,r,"fail")]])
    write_csv(out/"observations-by-scope.csv",["scope","pass","fail","total"],[(k,scopes[(k,"pass")],scopes[(k,"fail")],scopes[(k,"pass")]+scopes[(k,"fail")]) for k in sorted({x[0] for x in scopes})])
    write_csv(out/"provider-involvement.csv",["provider","pass","fail","total"],[(k,providers[(k,"pass")],providers[(k,"fail")],providers[(k,"pass")]+providers[(k,"fail")]) for k in sorted({x[0] for x in providers})])
    write_csv(out/"directed-interop-observations.csv",["from","to","pass","fail","total"],[(f,t,directions[(f,t,"pass")],directions[(f,t,"fail")],directions[(f,t,"pass")]+directions[(f,t,"fail")]) for f,t in sorted({x[:2] for x in directions})])
    write_csv(out/"executions.csv",["operation","provider","path","outcome","count"],[(*k,v) for k,v in sorted(executions.items())])
    write_csv(out/"class-patterns.csv",["operation","spectrum","classes"],[(*k,v) for k,v in sorted(patterns.items())])
    write_csv(out/"non-scoreable.csv",["operation","relation","cause","cells"],[(*k,v) for k,v in sorted(non_score.items())])
    write_csv(out/"mechanisms.csv",["operation","mechanism","detected","classes"],[(op,m,str(d).lower(),v) for (op,m,d),v in sorted(mechanisms.items())])
    write_csv(out/"classes.csv",list(summary["classes"][0]),[[x[k] for k in summary["classes"][0]] for x in summary["classes"]])
if __name__=="__main__": main()
