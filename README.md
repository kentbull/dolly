# Dolly

Dolly is an R&D credential reporting service using KERIpy for KERI/ACDC
verification. It supports direct HTTP/TCP intake and policy-controlled webhook
delivery. ACDC v2 IPEX requires KRAM; v1 follows its established verification path.

Use Python 3.14 and the dependency pinned in `pyproject.toml`. After installation,
run `dolly --help` for commands. Component tests remain in `tests/`.

Detailed operator guides, qualification records and lineage ledgers belong to
the independent `keri-v2` experiment workspace. In-code attribution and LICENSE /
NOTICE remain here. This package makes no universal conformance or production
readiness claim.
