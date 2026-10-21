# Extraction and qualification status

This is an active R&D implementation, published at Kent Bull's explicit request.
The standalone operator workflow is not yet qualified.

## Source lineage

Application code and existing application tests were moved from
`kentbull/keripy:v2-e2e`, using the implementation through commit
`e999aa9c4a457b7c52e05e3bb3dd03f6e3c8f83c` as the extraction source:

| Previous KERIpy path | Dolly path |
| --- | --- |
| `src/keri/app/dolly/serving.py` | `src/dolly/serving.py` |
| `src/keri/app/dolly/projecting.py` | `src/dolly/projecting.py` |
| `src/keri/cli/commands/dolly/start.py` | `src/dolly/cli.py` (adapted) |
| `tests/app/test_dolly.py` | `tests/test_dolly.py` |
| `tests/app/test_dolly_historical.py` | `tests/test_dolly_historical.py` |

Sally's service composition at commit
`ed789de4aa5f536d5838b4ff0d4d48a4e9dbf525` informed the original application.
The core verification remains in KERIpy. Standalone packaging, direct TCP intake,
schema packaging, local submission inspection, and their tests are local R&D
adaptations. A more detailed symbol-level attribution and documentation pass is
in progress. Git author metadata does not establish original idea authorship.
Apache-2.0 licensing and notices accompany this source.

## Current validation and known gaps

The extraction worker built and installed both package wheels and verified
imports resolve to site-packages. Relocated historical and HTTP native
regressions passed. Focused raw TCP native intake and legacy fresh-state webhook
cases passed (two tests). Schema manifest isolation and fragmented/consecutive/
malformed connection isolation checks passed.

Installed console startup and health checks passed for encrypted and unencrypted
identities, but both installed-console tests currently encounter HTTP 500 during
evidence intake. Diagnosis is in progress; restart and inspection acceptance
are not claimed. Six Bash disclosure scenarios, the final transport/version
matrix, comprehensive method documentation, and clean pinned-artifact
qualification remain open.

The dependency is pinned to KERIpy commit
`6aadd69beaf6fc7803f12e273b4ca101e6364e49`. Earlier focused tests used a copied
working tree based on `60761c7a` with the optional-custody changes; final validation
of this exact published pin remains required. Docker qualification copies source
and uses Linux-owned state volumes, never host-mounted LMDB directories.
