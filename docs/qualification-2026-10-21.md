# Dolly clean qualification — 2026-10-21

Dolly `8da5d718c0255ebd2541c719ca5c7046538d9483`, published on `master`,
passed qualification with its exact pinned KERIpy dependency
`64e14e086f16a4fd02eb9fc02ce07a2236175ca7` from fresh clean GitHub clones.
The installed versions were `dolly 0.1.0.dev0` and `keri 2.1.0.dev1`.
Docker builds copied source into Linux images; LMDB used named volumes with
no host bind mounts. The composed KERIpy qualification command exited zero.

| Gate | Result |
|---|---|
| Dolly application and installed HTTP/TCP/restart suite | 26 passed in 117.38 seconds; two released-peer cases intentionally skipped here |
| Actual installed KERIpy 1.2.14 and 1.3.6 peers | Both skipped cases separately passed in 17.61 seconds |
| V1 Bash operator story | Passed issuance, negotiation/local admission, HTTP/TCP hooks, and genuine revocation refusal with no third hook |
| Six separate v2 Bash stories in KERIpy | All passed; two hooks each, alternating HTTP/TCP, holder and separate discloser capability paths |
| Shared KERIpy core/application/CLI gate | 986 passed in 342.54 seconds |

Dolly and peer runs each reported the existing pysodium ctypes deprecation;
KERIpy additionally reported seven semver deprecations. No test failed.
The complete result is 1,014 passing Python tests plus seven Bash workflows.

## V1 operator evidence

- [Exact manifest, received hooks and revoked-grant refusal](results/2026-10-21/v1/result.json)
- [Recorded installed CLI commands](results/2026-10-21/v1/commands.txt)
- [Twenty public CESR streams](results/2026-10-21/v1/public-evidence.tar.gz)
- [Copied artifact SHA-256 hashes](results/2026-10-21/v1/SHA256SUMS)

The manifest names both clean source revisions and actual installed wheel hashes.
Each archived stream was rehashed against its manifest before publication.
This story has a separate issuer and Dolly as recipient/verifier, three witness
processes and quorum two. It asserts local signed/verified admission and ordinary
subsequent issuer Parser intake, not independently observed remote admission
acknowledgment. The revoked grant is rejected as not currently issued, with
`delivered=false`, and produces no third hook. V1 requires no KRAM evidence.

The six v2 manifests, exact transcripts and public proof archives belong to
[KERIpy's qualification report](https://github.com/kentbull/keripy/blob/v2-e2e/docs/v2-e2e/qualification-2026-10-21.md).
Those stories establish full-then-graduated holder presentation, partial-then-more
receipt, supplied openings, scoped holder custody, and separate disclosers with
openings or custody. V2 retains core KRAM authentication and liveness checks.

## Scope and provenance

This is the documented provisional R&D profile, not a production release or
unqualified protocol-conformance claim. See the shared report for observer
freshness, schema/graph, custody and source-service lifecycle limits. Plaintext
custody provisioning remains an explicit optional R&D adapter; it is not part
of ordinary v1/v2 held-material presentation. There is no automatic custody
AEID migration or distributed exactly-once webhook guarantee.

The runtime/operator-source ledger snapshot is `b9aa9d4`. Git diff confirms that
`8da5d71` adds only the planned dependency pin. This report, copied result,
command transcript, public proof archive and README/provenance links are locally
compiled execution documentation by the Codex implementation owner under Kent's
request. No new runtime function, class, constant or protocol design is added.
Later result commits are documentation/evidence only; the tested pair above is
not relabeled as their future hashes. Private keys, passcodes, custody transfer
files and LMDB state are excluded; public per-event openings are intentional.
