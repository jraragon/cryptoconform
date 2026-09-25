\# Analysis



This directory contains the analysis code and selected machine-readable

outputs used to derive and audit the results reported for CryptoConform.



The analysis was performed over the frozen scored execution evidence in

`../evidence/cryptoconform-scored-run-v1.json`. The files published here

preserve the analysis logic and the principal derived results used in the

study. They do not constitute a new experimental execution.



\## Structure



\- `scripts/` contains the analysis and audit programs used during the

&#x20; scientific analysis.

\- `tests/` contains the corresponding analysis tests.

\- `inputs/` contains the frozen experimental design used as an analysis

&#x20; input, provided as LaTeX for machine processing and as PDF for human

&#x20; inspection.

\- `derived/` contains selected frozen machine-readable outputs from the

&#x20; completed analysis.



\## Analysis stages



The analysis proceeded through four frozen stages:



1\. Protocol and pre-analysis validation.

&#x20;  `preanalysis\_audit.py`, `protocol.py`, and

&#x20;  `validate\_v011\_strata.py` implement the integrity checks and the

&#x20;  safe-comparison rules applied before scientific aggregation.



2\. Descriptive analysis.

&#x20;  `descriptive\_analysis.py` derives the observation, scope, provider,

&#x20;  interoperability, class-pattern, non-scoreability, and mechanism

&#x20;  summaries. The selected outputs are included in `derived/`.



3\. Scientific decisions.

&#x20;  `scientific\_decisions.py` derives the class-level diagnostic summary,

&#x20;  detection and diagnostic gain analyses, and the D-052 relation-ablation

&#x20;  results. These outputs are preserved in `derived/`.



4\. Robustness and final audit.

&#x20;  `robustness\_analysis.py` evaluates literal-versus-safe sensitivity and

&#x20;  denominator sensitivity. `final\_audit.py` was used in the original

&#x20;  frozen analysis package to consolidate the final audit.



The safe formulation is the normative analysis. Literal formulations are

retained only as sensitivity analyses.



\## Published derived outputs



\### Descriptive results



\- `descriptive-summary.json`

\- `classes.csv`

\- `class-patterns.csv`

\- `observations-by-operation-relation.csv`

\- `observations-by-scope.csv`

\- `provider-involvement.csv`

\- `directed-interop-observations.csv`

\- `non-scoreable.csv`

\- `mechanisms.csv`



\### Scientific-decision results



\- `scientific-decisions.json`

\- `class-diagnostic-summary.csv`

\- `d052.csv`

\- `detection-gain.csv`

\- `diagnostic-gain.csv`



\### Robustness results



\- `robustness-summary.json`

\- `denominator-sensitivity.csv`

\- `literal-detection-gain.csv`

\- `literal-diagnostic-gain.csv`



\### Final audit



\- `final-audit.json`



The raw execution aggregation `executions.csv` from the original descriptive

checkpoint is not duplicated here because the canonical scored execution

evidence is already preserved in

`../evidence/cryptoconform-scored-run-v1.json`.



\## Reproduction notes



The Python analysis tests used in the frozen analysis can be run with:



`python3 -m unittest discover -s analysis/tests -v`



The descriptive analysis consumes the frozen scored evidence and registry

inventory. The registry inventory distributed with this package is:



`analysis/derived/registry-inventory.json`



The scientific-decision stage additionally requires the frozen experimental

design:



`--json <scored-run.json> --registry <registry-inventory.json> --design analysis/inputs/experimental-design.tex --outdir <directory>`





The LaTeX source is required because the analysis code parses the frozen

contract-clause taxonomy directly from the design document. A PDF rendering

of the same design is provided alongside it for human inspection.



The robustness stage additionally consumes the safe scientific-decision

report produced by the preceding stage.



Some audit utilities retain the paths and checkpoint assumptions of the

original frozen analysis package. In particular, `final\_audit.py` was

designed to authenticate and consolidate the complete internal checkpoint

package. The selected public `derived/` directory therefore exposes the

frozen results used by the study without reproducing the original internal

checkpoint layout byte-for-byte.



\## Interpretation



The derived files report contractual conformance observations and analyses.

A failing relation denotes an observed contractual divergence under the

corresponding typed relation; it must not be interpreted automatically as a

provider defect.



The analysis concerns the exact finite experimental corpus. It does not

assume independent and identically distributed sampling and does not make

population-prevalence, p-value, confidence-interval, or random-population

claims.

