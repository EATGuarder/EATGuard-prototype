# TDH2 benchmark

`main.go` implements the local cryptographic workload used for the F3B comparison, following Section 5.2.1 of [F3B](https://drops.dagstuhl.de/entities/document/10.4230/LIPIcs.AFT.2023.3).

It uses [SmartContractKit TDH2](https://github.com/smartcontractkit/tdh2/tree/e8ec0386b06c/go/tdh2) at the version pinned in `go.mod`, with P-256 and AES-256-GCM. Both schemes use the same backend and paired plaintexts. Trustee work runs sequentially. The experiment excludes distributed consensus, data transport, and F3B's deposit/refund workflow.

TDH2 is a dependency, not vendored code. Its MIT license and the MPL-2.0 notices on its group and sharing components remain with the upstream module.
