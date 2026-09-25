\# CryptoConform



\## Replication Package for Typed Multi-Relation Conformance Testing of Heterogeneous Cryptographic SDKs



CryptoConform is the experimental instrument and replication package accompanying the paper:



“Typed Multi-Relation Conformance Testing for Heterogeneous Cryptographic SDKs”



The project implements a typed conformance-testing framework for evaluating a common cryptographic SDK contract across heterogeneous provider realizations.



The evaluated realizations are:



\- Chromium WebCrypto

\- Crypto++

\- Bouncy Castle



The experimental scope covers six operation families:



\- HKDF-SHA-256

\- AES-GCM

\- RSA-OAEP

\- RSA-PSS

\- RSA key serialization

\- EC P-256 key serialization



Conformance evidence is evaluated through six typed relations:



\- byte equality (`R\_byte`)

\- directed interoperability (`R\_interop`)

\- serialization (`R\_ser`)

\- validation (`R\_val`)

\- error semantics (`R\_err`)

\- capability conformance (`R\_cap`)



\## Repository Contents



The repository contains the experimental instrument, scored evidence, and

scientific-analysis material associated with the study.



The main directories are:



\- `src/` — portable contract definitions and provider-specific adapters.

\- `harness/` — mutation registry, stimulus materialization, typed relation

&#x20;  evaluators, orchestration, evidence structures, and integrity mechanisms.

\- `manifests/` — portable and provider-specific capability declarations.

\- `tests/` — contract, adapter, harness, and orchestration tests.

\- `scripts/` — reconstruction and supporting execution utilities.

\- `evidence/` — the frozen scored execution evidence used in the study.

\- `analysis/` — analysis code, tests, frozen inputs, and selected

&#x20;  machine-readable derived results.



The canonical scored evidence is distributed as:



`evidence/cryptoconform-scored-run-v1.json`



The analysis directory contains its own README describing the analysis stages,

inputs, derived outputs, and reproduction notes.



\## Experimental Scope



The frozen causal registry contains 79 designed causal classes. Of these,

73 classes carry scored evidence in the experimental corpus. The scored

dataset contains 886 typed relation observations derived from 1,159

persisted executions across 84 realized stimulus instances.



The causal class is the primary inferential unit. Relation-level failures

represent divergence from the corresponding portable-contract predicate;

they should not be interpreted automatically as defects in the underlying

cryptographic provider.



\## Requirements



The scored environment used for the study was based on:



\- Ubuntu 26.04.1 LTS (x86-64)

\- Node.js 24.20.0

\- npm 11.19.0

\- OpenJDK 21.0.12

\- Chromium 151.0.7922.34 through Playwright 1.62.1

\- Crypto++ pinned to commit `782425901d36fe0944b16aae37801b8ec2fa9000`

\- Bouncy Castle `bcprov-jdk18on-1.77.jar`



The exact provider identities and frozen experimental inputs are preserved in

the replication material.



\## Installation



Install the Node.js dependencies from the committed lockfile:



`npm ci`



Build the TypeScript sources:



`npm run build`



The native Crypto++ and Bouncy Castle backends are built through the native

reconstruction script. The required external locations are supplied explicitly

through `CRYPTOPP\_DIR` and `BC\_JAR`:



`CRYPTOPP\_DIR=<path-to-cryptopp>`

`BC\_JAR=<path-to-bcprov-jdk18on-1.77.jar>`

`npm run build:native`



\## Validation



The repository includes the contract, adapter, harness, and orchestration test

suite used during development and experimental validation.



With the required native dependencies available, run:



`BC\_JAR=<path-to-bcprov-jdk18on-1.77.jar> npm test`



The published scored evidence is frozen experimental evidence. Re-running the

test suite or reconstructing the backends does not modify or replace the

published scored run.



\## Scored Evidence



The canonical scored run is:



`evidence/cryptoconform-scored-run-v1.json`



Its SHA-256 digest is:



`66ec5603ed404092e51b7f4ab1b48fca69a2b8d1e83b76bc1034fcd0866daa41`



The file preserves the original frozen run identifiers and provenance

metadata. Its public filename was chosen for clarity; the internal identifiers

remain unchanged.



\## Scientific Analysis



The `analysis/` directory publishes the analysis programs, their tests, the

frozen experimental design required by the analysis, the registry inventory,

and selected machine-readable outputs supporting the reported results.



See `analysis/README.md` for the analysis structure and reproduction notes.



\## Reproducibility Scope



This repository preserves the instrument, scored evidence, and analysis

material for the exact finite experimental corpus reported in the paper.



The package is intended to support inspection, reconstruction, validation,

and reproduction of the reported analyses. It does not imply that a newly

executed experiment must reproduce the frozen evidence byte-for-byte across

different software versions or execution environments.



\## License



License information will be added before the archival release.



\## Citation



Citation information and the archival DOI will be added when the replication

package is released.

