# Extraction and qualification status

This is an active R&D implementation, published at Kent Bull's explicit request.
Current evidence supports the bounded scenarios below, not production readiness
or universal protocol conformance.

## Review units and source lineage

Application code and existing application tests moved from `kentbull/keripy:v2-e2e`
through `e999aa9c4a457b7c52e05e3bb3dd03f6e3c8f83c`. The supplementary independent
process and released-peer tests/assets use donor
`6aadd69beaf6fc7803f12e273b4ca101e6364e49`. [The symbol ledger](provenance.md)
records immutable per-symbol donor links and retained/adapted/new distinctions.

| Previous KERIpy path | Dolly path |
| --- | --- |
| `src/keri/app/dolly/{__init__,serving,projecting}.py` | `src/dolly/{__init__,serving,projecting}.py` |
| `src/keri/cli/commands/dolly/start.py` | `src/dolly/cli.py` (adapted) |
| `tests/app/test_dolly.py` | `tests/test_dolly.py` |
| `tests/app/test_dolly_historical.py` | `tests/test_dolly_historical.py` |
| `tests/app/test_legacy_peer_profiles.py` | `tests/test_legacy_peer_profiles.py` |
| `tests/app/test_native_e2e.py` | `tests/test_native_e2e.py` |
| `scripts/v2-e2e/legacy-peers/*` | `scripts/legacy-peers/*` |

The move rewrites imports and console paths and removes application wrappers from
KERIpy. Existing real verification, current-reporting and retained-disclosure
assertions remain. The supplementary process test retains three witnesses,
quorum two, and independent holder/observer/registrar/Dolly processes.

Separate additions are standalone packaging, an explicit local schema layer,
connection-local direct TCP intake, authenticated local read-only submission
inspection, and installed-console integration tests. TCP delegates incremental
framing to existing core Parser; it does not copy verification. Both transports
share the same core owners; native v2 KRAM stays enabled and v1 keeps core v1
semantics. No request mutates shared authentication policy.

Ordinary unencrypted verifier identities are supported with `bran=None`;
encrypted identities keep existing passcode authentication. Dolly requires an
existing signing identity but owns no derivation salt and has no custody-only
encryption prerequisite. Packaged schema resources carry a SAID manifest and
explicit local fixture origins; neither schema packaging nor allowlisting grants
issuer trust. Independent schema-section regressions still deliver sections
through real transport without legacy schema-cache preloads.

Sally composition at `ed789de4aa5f536d5838b4ff0d4d48a4e9dbf525` informed the original
application. Apache-2.0 source/license and attribution remain. Git metadata is
not treated as evidence of original idea authorship. All 149 inventoried Python
classes/functions, including helpers/dunders, have explanatory docstrings.

## Resolved startup and restart findings

Installed-console experiments exposed missing sender bootstrap surfacing as
HTTP 500. That specific core `MissingSenderKeyStateError` now maps to HTTP 400;
the refused request creates no misleading persisted pending submission. After
actual public KEL bootstrap, retry succeeds. Tests wait for a real accepted hook
before retry and restart; elapsed delay alone is not readiness.

A stronger restart without KEL replay then exposed core Kramer cache lookups
that missed persisted key state. KERIpy repaired those four lookups; Dolly's
regression was kept unchanged. Both encrypted and unencrypted installed-console
stop/restart cases now pass without replay. They inspect accepted/delivered
states through the public local command and verify no encryption migration.

## Executed evidence

Copied Linux sources and named state volumes were used throughout; no macOS LMDB
or host-mounted source/state test was used. Actual KERIpy and Dolly wheels install
into site-packages, and tests run outside the source tree.

```sh
KERI_SOURCE=/Users/kbull/enc/keri/worktrees/keripy/v2-e2e scripts/check.sh
DOLLY_MATRIX_IMAGE=dolly-v2-refactor:dev scripts/legacy-peers/check.sh
```

The latest full Dolly run produced **25 passed, 2 skipped, 1 failed** in 107.71s.
The skips are the isolated released-peer profiles; their separate runner passed
**2 tests** in 17.69s against actual `keri==1.2.14` and `keri==1.3.6` source
archives with hash/installed-version verification. Their existing explicit TSN
control adapter remains documented; no released dependency is imported into the
current verifier process.

The initial full-run failure was the supplementary witnessed process regression:
current KERIpy WIP `cesr_sending.send` called `owner.extend([owner])` after `owner`
was rebound to `ClientDoer`. The holder process exits before its listener starts.
Dolly bootstrap/refusal fix was published in
`2cccc95cb3017de804a27fc7a2d7dbfdeaf0d53c`. The core owner repaired the sender
name shadowing. The exact moved regression then
passed in 47.62s; its topology and assertions remain unchanged.

Passing scenarios include native top/inner/one-way binding over HTTP and raw TCP,
legacy raw/header HTTP and raw TCP with fresh source TSN, empty native grants
followed by later submissions across reopen, independent schema arrival/reopen,
exact retained partial projection despite fuller caches, historical bound graph
inspection after far revocation, invalid historical proof refusal, fragmented
and consecutive TCP streams, malformed client isolation, and installed dual
listener process start/stop/restart with authenticated local inspection.

## Snapshot and remaining qualification

The last build copied KERIpy HEAD `0fcbaa9afe5609746560c5134ac9a15ea6d9a627`
plus the printed current working-tree changes (including public-evidence CLI
work). This is not a clean immutable artifact qualification. The published
Dolly dependency now pins `0fcbaa9afe5609746560c5134ac9a15ea6d9a627`, including the
KRAM retained-state repair. The passing supplementary rerun additionally copied
the then-current core sender fix and documentation WIP. Final qualification must
validate the final clean compatible core pin.

- Dolly wheel SHA-256 (passing supplementary rerun): `5b08b726509c9e342927e78388fa1143df93e83b0d45b6fd3af20f785ba87674`.
- Core wheel SHA-256: `583b3a9ce5db793ffc28f421f188cefe0dd4d048aadffd9476b22aea730d35a0`.
- Dolly image manifest list: `605e3dbde2165cdf2de3adb6cab9ec358b9b596c12ab8afc681fdc5f78a9a850`.
- Core image manifest list: `9d9b4037cea07132465894df1e59338b2086dfc303b4f6c140932e3435e585ac`.

The independent Bash disclosure matrix, final pin/artifact qualification, and
final cross-repository source reference review remain open. The present evidence does not claim all hostile
transport/version combinations have been exercised.
