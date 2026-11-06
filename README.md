# Dolly

Dolly is an R&D credential reporting service using KERIpy for KERI/ACDC
verification. It supports direct HTTP/TCP intake and policy-controlled webhook
delivery. V2 ACDC/IPEX requires KRAM; unsupported protocol versions are
rejected before processor dispatch.

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
local KERI/ACDC verification determines authentication. v2 observer headers
and observation age do not grant authority. Dolly rechecks each exact retained
Grant through KERIpy and requires every disclosed issuer-registry node to have
an authenticated `issued` state before reporting. No observation is a
global-latest claim.

V2 KERI/IPEX composition uses the complete KERIpy commit pinned in `pyproject.toml`.
One application-owned Kevery/Regery/Parser and KRAM pruner serve HTTP and TCP;
one ordinary Exchanger owns the v2 IPEX handlers.
Historical inspection displays exact retained views and optional `exrs`
recorded observations, with no current-validity claim. Expanded JSON schema
sections enter the ordinary schema cache on intake/startup; other sections
never expand a retained Grant. Non-JSON schema sections stay held without
transcoding their IDs.

For individual v2 presentations, Dolly requests missing issuer openings only
once the configured observer's public evidence accepts and the exact disclosed
view meets application policy. The process owns one approved, frozen Unblind
query; a changed public head or expired/terminated transaction cannot renew it.
An interrupted request needs a fresh presentation after restart. Ordinary v2
Grant verification and the `issued` policy run again after the reply. Reporting
then requires the exact locally accepted Admit; its SAID appears as `admit` in
the webhook payload. Dolly submits that same retained Admit through authenticated
controller, agent, mailbox or witness routing. `admitSubmitted` records transport
submission; `delivered` records webhook acknowledgement. Neither proves the
presenter's receipt, and lost acknowledgements may cause retransmission.

| Prior test requirement | Selected v2 contract / retained coverage |
| --- | --- |
| Bare Grant rejected by author | Vacuous Grant accepted but non-reportable; later real hooks and reopen remain. |
| Digest/partial TEL seal | Full `{i,s,d}` seal; same participants, ordinals and registry-first retry. |
| Independent section owner | Normal Reger held sections; JSON schema reconciliation, missing-schema escrow, exact partial views and full reopen. |
| Edge schema only an application dependency | v2 IPEX admission waits for the schema; normal replay resolves it. |
| Observer age/header gate | Configured TLS identity and exact response accepted-slot/head telemetry; source-local pending versus unrelated escrow and stale response-head refusals. |
| Historical verifier bypass/custom graph policy | Same v2 read-only current recheck; recorded observations remain visible through revocation/opaque successors without asserting current validity. |
| Donor Wallet/Peer test facades | Real holder processors and HTTP intake; same two-node/three-registry workflow, rotations, disclosure, webhook and protocol Admit messages. |

The maintained base retains scheduler fairness, bounded webhook backoff and
socket/decoder failure containment. The later donor's v2 observer-policy
removal and source-scoped evidence checks are incorporated explicitly; retired
core facades and duplicate section/graph owners are removed rather than merged.
