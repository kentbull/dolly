# Application extraction and behavior

This is an active R&D implementation, published at Kent Bull's explicit request.
The documented contracts describe a bounded implementation, not production readiness
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

The move rewrites imports and console paths and removes application wrappers from
KERIpy. Existing real verification, current-reporting and retained-disclosure
assertions remain. External process and released-peer tests have moved to the independent
experiment repository; application tests remain beside the implementation.

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
not treated as evidence of original idea authorship. The retained symbol ledger includes classes/functions, helpers and dunders;
the original 149-symbol snapshot also covered now-extracted test infrastructure.

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


## Experiment ownership

Cross-repository recipes, external acceptance scenarios and dated evidence are
owned by the independent `keri-v2` experiment repository. They are not required
to run this component. [Pre-extraction record](https://github.com/kentbull/dolly/blob/a48799219a45aeb3e3a0414888a0aae8dbce2851/docs/extraction.md) preserves the
historical source and execution scope. The extraction changes ownership only;
runtime dependencies and verification contracts remain unchanged.
