# Dolly

Dolly is an R&D credential reporting service using KERIpy for KERI/ACDC
verification. It supports direct HTTP/TCP intake and policy-controlled webhook
delivery. ACDC v2 IPEX requires KRAM; v1 follows its established verification path.

Use Python 3.14 and the dependency pinned in `pyproject.toml`. After installation,
run `dolly --help` for commands. Component tests remain in `tests/`.

For the installed test environment, use `uv` 0.9.18 and run
`uv sync --locked --extra test --no-editable`, followed by `uv pip check`,
`uv run --no-sync ruff check src tests`, and
`uv run --no-sync python -m pytest --import-mode=importlib tests`.
The test extra includes the pinned Registrar and Observer services used by the
real HTTP integration tests. CI runs these commands on Linux and macOS without
a source-path override.

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
local KERI/ACDC verification determines authentication. Native observer headers
and observation age do not grant authority. Dolly rechecks each exact retained
Grant through KERIpy and requires every disclosed issuer-registry node to have
an authenticated `issued` state before reporting. Conventional v1 TSN source
and timing policy remains separate. No observation is a global-latest claim.

Native composition is pinned to KERIpy `633be0b8bbcf1a9a7076dee6f4760792f2f9e362`.
One application-owned Kevery/Regery/Parser and KRAM pruner serve HTTP and TCP;
one Exchanger selects native v2 or genuine v1 IPEX handlers per message.
Historical inspection displays exact retained views and optional `exrs`
recorded observations, with no current-validity claim. Expanded JSON schema
sections enter the ordinary schema cache on intake/startup; other sections
never expand a retained Grant. Non-JSON schema sections stay held without
transcoding their IDs. Admit-triggered reporting and Unblind acquisition are
separate follow-up work; this unit adds neither gate.

| Prior test requirement | Selected native contract / retained coverage |
| --- | --- |
| Bare Grant rejected by author | Vacuous Grant accepted but non-reportable; later real hooks and reopen remain. |
| Digest/partial TEL seal | Full `{i,s,d}` seal; same participants, ordinals and registry-first retry. |
| Independent section owner | Normal Reger held sections; JSON schema reconciliation, missing-schema escrow, exact partial views and full reopen. |
| Edge schema only an application dependency | Native IPEX admission waits for the schema; normal replay resolves it. |
| Observer age/header gate | Configured TLS identity and exact response accepted-slot/head telemetry; source-local pending versus unrelated escrow and stale response-head refusals. |
| Historical verifier bypass/custom graph policy | Same native read-only current recheck; recorded observations remain visible through revocation/opaque successors without asserting current validity. |
| Donor Wallet/Peer test facades | Real holder processors and HTTP intake; same two-node/three-registry workflow, rotations, disclosure, webhook and protocol Admit messages. |

The maintained base retains scheduler fairness, bounded webhook backoff and
socket/decoder failure containment. The later donor's native observer-policy
removal and source-scoped evidence checks are incorporated explicitly; retired
core facades and duplicate section/graph owners are removed rather than merged.
