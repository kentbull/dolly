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

Current-standing acquisition requires explicit HTTPS observer trust in the
JSON policy. Configure `observer` as `{"url": "https://observer.example/",
"cafilepath": "/absolute/path/to/observer-ca.pem"}`. When the URL connects by
IP to a certificate issued for a DNS name, add `"certedhost":
"observer.example"`. Dolly rejects plaintext or missing observer trust and does
not follow observer redirects. This authenticates the configured response hop;
local KERI/ACDC proof and freshness validation still determine standing, and no
observation is a global-latest claim.
