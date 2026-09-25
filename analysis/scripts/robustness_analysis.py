#!/usr/bin/env python3
"""M5 v0.4 literal-versus-safe robustness and denominator sensitivity."""
import argparse, csv, json
from collections import Counter, defaultdict
from itertools import combinations
from pathlib import Path

from protocol import RELATIONS, Pattern, detected, relation_subsets, scoreable_domain
from scientific_decisions import OPS, analyse as safe_analyse, clause_taxonomy

SVEC={"R_ser","R_val","R_err","R_cap"}

def pattern(result):
    return Pattern(result["operation"],result["applicability"],result["observedSpectrum"],
                   frozenset(x["relation"] for x in result["nonScoreable"]))

def literal_value(p, relation):
    if not p.applicability[relation]: return "n/a"
    if relation in p.non_scoreable: return "absent"
    return p.spectrum[relation]

def literal_signature(p, relations=RELATIONS):
    return tuple((r,literal_value(p,r)) for r in relations)

def literal_blocks(patterns, relations=RELATIONS):
    groups={}
    for i,p in enumerate(patterns): groups.setdefault(literal_signature(p,relations),[]).append(i)
    return tuple(sorted(tuple(v) for v in groups.values()))

def literal_adequate(by_op, relations):
    allp=[p for ps in by_op.values() for p in ps]
    if [detected(p,relations) for p in allp] != [detected(p) for p in allp]: return False
    return all(literal_blocks(ps,relations)==literal_blocks(ps) for ps in by_op.values())

def signatures(results, registry, design_text):
    reg={x["mutationId"]:x for x in registry["entries"]}; tax=clause_taxonomy(design_text)
    def key(op,g): return f"rsa-ser.{g}" if op=="rsa-ser" and "." not in g else g
    return {r["mutationId"]:tuple(sorted({tax[key(r["operation"],g)] for g in reg[r["mutationId"]]["gamma0"]})) for r in results}

def structural_mask_effect(results, registry):
    masks={}
    for r in results: masks.setdefault(r["operation"],tuple(bool(r["applicability"][x]) for x in RELATIONS))
    op_pairs=list(combinations(OPS,2))
    differing=[pair for pair in op_pairs if masks[pair[0]]!=masks[pair[1]]]
    counts=Counter(x["operation"] for x in registry["entries"])
    total=sum(counts[a]*counts[b] for a,b in op_pairs)
    decided=sum(counts[a]*counts[b] for a,b in differing)
    req=Counter(r["operation"] for r in results)
    req_total=sum(req[a]*req[b] for a,b in op_pairs)
    req_decided=sum(req[a]*req[b] for a,b in differing)
    return {"operationPairs":{"total":len(op_pairs),"differentMasks":len(differing),"pairs":differing},
            "registryCrossOperationPairs":{"total":total,"maskDecided":decided,"ratio":decided/total},
            "requiredBearingCrossOperationPairs":{"total":req_total,"maskDecided":req_decided,"ratio":req_decided/req_total},
            "operationMasks":{"%s"%op:"".join("1" if x else "0" for x in masks[op]) for op in OPS},
            "registryClassesByOperation":dict(counts),"requiredBearingClassesByOperation":dict(req)}

def literal_decisions(results, registry, design_text):
    sig=signatures(results,registry,design_text)
    rr={op:[r for r in results if r["operation"]==op] for op in OPS}
    pp={op:[pattern(r) for r in rr[op]] for op in OPS}
    det_gain={}; det_rows=[]
    for op in OPS:
        foreign=[(r,p) for other in OPS if other!=op for r,p in zip(rr[other],pp[other]) if detected(p)]
        n=0
        for r,p in zip(rr[op],pp[op]):
            if not detected(p): continue
            matches=[fr["mutationId"] for fr,q in foreign if literal_signature(p)==literal_signature(q)]
            state="reproduced" if matches else "exclusive"
            n += state=="exclusive"; det_rows.append((r["mutationId"],op,state,"|".join(matches)))
        det_gain[op]={"exclusive":n,"detected":sum(detected(p) for p in pp[op])}

    q={}; diag_gain={}; diag_rows=[]
    for op in OPS:
        pairs=defaultdict(list)
        for i,j in combinations(range(len(pp[op])),2):
            if sig[rr[op][i]["mutationId"]]==sig[rr[op][j]["mutationId"]]: continue
            key=tuple(sorted((sig[rr[op][i]["mutationId"]],sig[rr[op][j]["mutationId"]])))
            pairs[key].append(literal_signature(pp[op][i])!=literal_signature(pp[op][j]))
        q[op]={k for k,v in pairs.items() if any(v)}
    for op in OPS:
        exclusive=reproduced=0
        for key in sorted(q[op]):
            found=False
            for other in OPS:
                if other==op: continue
                for i,j in combinations(range(len(pp[other])),2):
                    k=tuple(sorted((sig[rr[other][i]["mutationId"]],sig[rr[other][j]["mutationId"]])))
                    if k==key and literal_signature(pp[other][i])!=literal_signature(pp[other][j]): found=True
            state="reproduced" if found else "exclusive"
            reproduced += found; exclusive += not found
            diag_rows.append((op," || ".join("+".join(x) for x in key),state))
        diag_gain[op]={"qPairs":len(q[op]),"exclusive":exclusive,"reproduced":reproduced}

    pending=("hkdf","oaep","rsa-ser")
    keep={op:det_gain[op]["exclusive"]>0 or diag_gain[op]["exclusive"]>0 for op in pending}
    omin=sorted({"gcm","pss","ec-ser"}|{op for op in pending if keep[op]})
    adequate=[s for s in relation_subsets() if literal_adequate(pp,s)]
    width=min(map(len,adequate)); minima=[list(s) for s in adequate if len(s)==width]
    return {"detectionGain":det_gain,"diagnosticGain":diag_gain,"pendingKeep":keep,"Omin":omin,
            "Rmin":{"adequateSubsets":len(adequate),"minimumCardinality":width,"minimumFamily":minima}},det_rows,diag_rows

def denominator_sensitivity(run, registry):
    b=run["evidenceBundle"]; obs=b["observations"]; inst=b["instanceResults"]; res=b["scientificResults"]
    obsmap={x["observationId"]:x for x in obs}
    divergent_instances=sum(any(obsmap[x]["status"]=="fail" for x in i["observations"]) for i in inst)
    detected_classes=sum(r["detectionSupport"]["divergentInstances"]>0 for r in res)
    rel={}
    for relation in RELATIONS:
        xs=[o for o in obs if o["relation"]==relation]; f=sum(o["status"]=="fail" for o in xs)
        rel[relation]={"observations":len(xs),"fail":f,"failShare":f/len(xs) if xs else None}
    op={}
    for operation in OPS:
        xs=[o for o in obs if next((r["operation"] for r in res if r["mutationId"]==o["context"]["mutationId"]),next(e["operation"] for e in registry["entries"] if e["mutationId"]==o["context"]["mutationId"]))==operation]
        cs=[r for r in res if r["operation"]==operation]
        op[operation]={"observations":len(xs),"failedObservations":sum(o["status"]=="fail" for o in xs),"requiredBearingClasses":len(cs),"detectedClasses":sum(r["detectionSupport"]["divergentInstances"]>0 for r in cs)}
    return {"observation":{"fail":sum(o["status"]=="fail" for o in obs),"total":len(obs)},
            "instance":{"divergent":divergent_instances,"total":len(inst)},
            "requiredBearingClass":{"detected":detected_classes,"total":len(res)},
            "registryCoverage":{"requiredBearing":len(res),"zeroRequired":len(registry["entries"])-len(res),"total":len(registry["entries"])},
            "byRelation":rel,"byOperation":op,
            "interpretation":"Observation and instance counts are clustered within designed causal classes; the class is the inferential unit. The 79-class denominator measures coverage, not a detection rate."}

def write_csv(path,header,rows):
    with Path(path).open("w",newline="") as f: w=csv.writer(f); w.writerow(header); w.writerows(rows)

def analyse(run,registry,design_text,safe_report):
    results=run["evidenceBundle"]["scientificResults"]
    safe_fresh,*_=safe_analyse(run,registry,design_text)
    if safe_fresh!=safe_report: raise ValueError("Frozen v0.3 report does not reproduce exactly")
    literal,det_rows,diag_rows=literal_decisions(results,registry,design_text)
    masks=structural_mask_effect(results,registry); den=denominator_sensitivity(run,registry)
    h3=safe_report["hypotheses"]["H3details"]; thresholds={str(t):h3["ratio"]>=t for t in (.25,1/3,.5)}
    comparison={
      "pendingKeep":{"safe":safe_report["Omin"]["pendingKeep"],"literal":literal["pendingKeep"]},
      "Omin":{"safe":safe_report["Omin"]["result"],"literal":literal["Omin"]},
      "Rmin":{"safe":safe_report["Rmin"],"literal":literal["Rmin"]},
      "hypotheses":{"safe":safe_report["hypotheses"],"literal":{"H1":"supported","H2":"supported","H3":"supported","H3thresholdSensitivity":thresholds}},
      "centralConclusionStable":safe_report["hypotheses"]["H1"]=="supported" and safe_report["hypotheses"]["H2"]=="supported" and safe_report["hypotheses"]["H3"]=="supported",
      "operationMinimalitySensitive":safe_report["Omin"]["result"]!=literal["Omin"]}
    report={"schema":"paper4-m5-v0.4-robustness-v1","runId":run["runId"],"structuralMaskEffect":masks,
            "literal":literal,"safe":safe_report,"comparison":comparison,"denominatorSensitivity":den,
            "partialEvidence":{"nonScoreableCells":sum(len(r["nonScoreable"]) for r in results),"requiredEvidenceIncompleteClasses":sum(not r["requiredEvidenceComplete"] for r in results),
              "safeUndeterminedDetectionCandidates":sum(v.get("undetermined-exclusive",0) for v in safe_report["detectionGain"].values()),
              "rule":"Undetermined comparisons never count as safe gain; typed non-scoreability is not missing Required evidence."},
            "inferenceBoundary":"Exact finite-corpus descriptive analysis; no iid, prevalence, p-value, confidence-interval, or random-population claim."}
    return report,det_rows,diag_rows

def main():
    ap=argparse.ArgumentParser(); ap.add_argument("--json",required=True); ap.add_argument("--registry",required=True); ap.add_argument("--design",required=True); ap.add_argument("--safe",required=True); ap.add_argument("--outdir",required=True); a=ap.parse_args()
    run=json.loads(Path(a.json).read_text()); reg=json.loads(Path(a.registry).read_text()); design=Path(a.design).read_text(); safe=json.loads(Path(a.safe).read_text()); out=Path(a.outdir); out.mkdir(parents=True,exist_ok=True)
    report,det,diag=analyse(run,reg,design,safe)
    (out/"robustness-summary.json").write_text(json.dumps(report,indent=2,sort_keys=True)+"\n")
    write_csv(out/"literal-detection-gain.csv",["mutationId","operation","state","matchingForeignClasses"],det)
    write_csv(out/"literal-diagnostic-gain.csv",["operation","signaturePair","state"],diag)
    rows=[]
    for unit,d in (("observation",report["denominatorSensitivity"]["observation"]),("instance",report["denominatorSensitivity"]["instance"]),("required-bearing-class",report["denominatorSensitivity"]["requiredBearingClass"])):
        num=d.get("fail",d.get("divergent",d.get("detected"))); rows.append((unit,num,d["total"],num/d["total"]))
    write_csv(out/"denominator-sensitivity.csv",["unit","positive","total","share"],rows)

if __name__=="__main__": main()
