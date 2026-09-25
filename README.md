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



\- byte equality (R\_byte)

\- directed interoperability (R\_interop)

\- serialization (R\_ser)

\- validation (R\_val)

\- error semantics (R\_err)

\- capability conformance (R\_cap)



\## Repository Contents



The repository contains the experimental instrument used to construct the

scored evidence reported in the paper, including:



\- the portable SDK contract;

\- provider-specific adapters;

\- the frozen causal mutation registry;

\- Phase-C stimulus materialization;

\- typed relation evaluators;

\- multi-backend orchestration;

\- scored-execution and integrity mechanisms;

\- conformance and harness tests;

\- native Crypto++ and Bouncy Castle CLI sources; and

\- reconstruction and replication documentation.



The scored evidence and analysis material associated with the paper are

distributed as part of the same replication package.



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

\- npm

\- OpenJDK 21.0.12

\- Chromium 151.0.7922.34 through Playwright 1.62.1

\- Crypto++ pinned to commit

&#x20; 782425901d36fe0944b16aae37801b8ec2fa9000

\- Bouncy Castle bcprov-jdk18on-1.77.jar



The exact environment and reconstruction procedure are documented in the

replication material.



\## Installation



Install the Node.js dependencies from the committed lockfile:



npm ci

