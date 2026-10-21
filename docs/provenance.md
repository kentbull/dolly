# Source and symbol provenance

This ledger identifies code ancestry, not original idea authorship. KERIpy donor
authors are not independently established here; Git author fields are not proof.
Apache-2.0 source and Sally attribution are retained in LICENSE, NOTICE, and modules.

The immutable donor columns distinguish a retained syntax body (ignoring docstrings)
from an adapted body. Import rewrites and module-level changes are recorded separately.
A new local symbol has no exact donor claim: it was agent-generated under Kent's
standalone extraction and direct HTTP/TCP/operator-inspection request. New API policy
was approved in that request; core protocol verification is imported, never copied.

## Module and artifact lineage

| Destination | Immutable donor or local origin | Adaptation |
| --- | --- | --- |
| `src/dolly/__init__.py` | [KERIpy `e999aa9c`](https://github.com/kentbull/keripy/blob/e999aa9c4a457b7c52e05e3bb3dd03f6e3c8f83c/src/keri/app/dolly/__init__.py) | Import/command/path rewrites and explanatory documentation; symbol deltas below. |
| `src/dolly/serving.py` | [KERIpy `e999aa9c`](https://github.com/kentbull/keripy/blob/e999aa9c4a457b7c52e05e3bb3dd03f6e3c8f83c/src/keri/app/dolly/serving.py) | Import/command/path rewrites and explanatory documentation; symbol deltas below. |
| `src/dolly/projecting.py` | [KERIpy `e999aa9c`](https://github.com/kentbull/keripy/blob/e999aa9c4a457b7c52e05e3bb3dd03f6e3c8f83c/src/keri/app/dolly/projecting.py) | Import/command/path rewrites and explanatory documentation; symbol deltas below. |
| `src/dolly/cli.py` | [KERIpy `e999aa9c`](https://github.com/kentbull/keripy/blob/e999aa9c4a457b7c52e05e3bb3dd03f6e3c8f83c/src/keri/cli/commands/dolly/start.py) | Import/command/path rewrites and explanatory documentation; symbol deltas below. |
| `tests/test_dolly.py` | [KERIpy `e999aa9c`](https://github.com/kentbull/keripy/blob/e999aa9c4a457b7c52e05e3bb3dd03f6e3c8f83c/tests/app/test_dolly.py) | Import/command/path rewrites and explanatory documentation; symbol deltas below. |
| `tests/test_dolly_historical.py` | [KERIpy `e999aa9c`](https://github.com/kentbull/keripy/blob/e999aa9c4a457b7c52e05e3bb3dd03f6e3c8f83c/tests/app/test_dolly_historical.py) | Import/command/path rewrites and explanatory documentation; symbol deltas below. |
| `tests/test_legacy_peer_profiles.py` | [KERIpy `6aadd69b`](https://github.com/kentbull/keripy/blob/6aadd69beaf6fc7803f12e273b4ca101e6364e49/tests/app/test_legacy_peer_profiles.py) | Import/command/path rewrites and explanatory documentation; symbol deltas below. |
| `tests/test_native_e2e.py` | [KERIpy `6aadd69b`](https://github.com/kentbull/keripy/blob/6aadd69beaf6fc7803f12e273b4ca101e6364e49/tests/app/test_native_e2e.py) | Import/command/path rewrites and explanatory documentation; symbol deltas below. |
| `scripts/legacy-peers/run.py` | [KERIpy `6aadd69b`](https://github.com/kentbull/keripy/blob/6aadd69beaf6fc7803f12e273b4ca101e6364e49/scripts/v2-e2e/legacy-peers/run.py) | Import/command/path rewrites and explanatory documentation; symbol deltas below. |
| `scripts/legacy-peers/requirements-1.2.14.lock` | [KERIpy `6aadd69b`](https://github.com/kentbull/keripy/blob/6aadd69beaf6fc7803f12e273b4ca101e6364e49/scripts/v2-e2e/legacy-peers/requirements-1.2.14.lock) | Build-context paths rewritten where required; released pins/locks retained. |
| `scripts/legacy-peers/Dockerfile` | [KERIpy `6aadd69b`](https://github.com/kentbull/keripy/blob/6aadd69beaf6fc7803f12e273b4ca101e6364e49/scripts/v2-e2e/legacy-peers/Dockerfile) | Build-context paths rewritten where required; released pins/locks retained. |
| `scripts/legacy-peers/profiles.json` | [KERIpy `6aadd69b`](https://github.com/kentbull/keripy/blob/6aadd69beaf6fc7803f12e273b4ca101e6364e49/scripts/v2-e2e/legacy-peers/profiles.json) | Build-context paths rewritten where required; released pins/locks retained. |
| `scripts/legacy-peers/peer.py` | [KERIpy `6aadd69b`](https://github.com/kentbull/keripy/blob/6aadd69beaf6fc7803f12e273b4ca101e6364e49/scripts/v2-e2e/legacy-peers/peer.py) | Import/command/path rewrites and explanatory documentation; symbol deltas below. |
| `scripts/legacy-peers/check.sh` | [KERIpy `6aadd69b`](https://github.com/kentbull/keripy/blob/6aadd69beaf6fc7803f12e273b4ca101e6364e49/scripts/v2-e2e/legacy-peers/check.sh) | Build-context paths rewritten where required; released pins/locks retained. |
| `scripts/legacy-peers/install.py` | [KERIpy `6aadd69b`](https://github.com/kentbull/keripy/blob/6aadd69beaf6fc7803f12e273b4ca101e6364e49/scripts/v2-e2e/legacy-peers/install.py) | Import/command/path rewrites and explanatory documentation; symbol deltas below. |
| `scripts/legacy-peers/requirements-1.3.6.lock` | [KERIpy `6aadd69b`](https://github.com/kentbull/keripy/blob/6aadd69beaf6fc7803f12e273b4ca101e6364e49/scripts/v2-e2e/legacy-peers/requirements-1.3.6.lock) | Build-context paths rewritten where required; released pins/locks retained. |
| `src/dolly/schemas/*` | Local fixture layer; manifest carries exact SAIDs and origins. | Legacy JSON extracted from donor test, native entitlement schema locally authored; no external ecosystem provenance asserted. |
| `tests/test_transport.py` | New local integration tests. | Actual installed console, sockets, authenticated processors, hooks, restart, and inspection; no core test-module imports. |
| `pyproject.toml`, `scripts/check.sh`, `scripts/Dockerfile` | New local packaging and copied-source qualification. | Installed wheels and Linux named state volumes; KERIpy dependency pin is explicit. |
| `README.md`, `docs/extraction.md`, this ledger | New local operator/evidence documentation. | No production or universal conformance claim. |

`TcpIntake` adapts the lifecycle pattern of KERIpy
[Directant.serviceDo](https://github.com/kentbull/keripy/blob/e999aa9c4a457b7c52e05e3bb3dd03f6e3c8f83c/src/keri/app/directing.py) and calls the existing
core incremental Parser on each hio remoter buffer. `StreamParser` adds only an
application dispatch hook. CLI identity opening calls existing Keeper/setupHby;
read-only inspection uses LMDBer's existing readonly option. Sally composition
inspiration is pinned in NOTICE, not claimed as an exact donor for new methods.

## Python symbols

Stable identity is `dolly:<destination>:<qualified symbol>`; nested test helpers
are listed because their verification role and origin also matter. Line links point
to immutable donors. Current line numbers are intentionally omitted so normal
documentation edits do not silently invalidate the ledger.

| Destination / qualified symbol | Origin | Body status |
| --- | --- | --- |
| `scripts/legacy-peers/peer.py:Peer` | [same qualified symbol](https://github.com/kentbull/keripy/blob/6aadd69beaf6fc7803f12e273b4ca101e6364e49/scripts/v2-e2e/legacy-peers/peer.py#L25) | adapted; review destination against donor |
| `scripts/legacy-peers/peer.py:Peer.__init__` | [same qualified symbol](https://github.com/kentbull/keripy/blob/6aadd69beaf6fc7803f12e273b4ca101e6364e49/scripts/v2-e2e/legacy-peers/peer.py#L26) | adapted; review destination against donor |
| `scripts/legacy-peers/peer.py:Peer.anchor` | [same qualified symbol](https://github.com/kentbull/keripy/blob/6aadd69beaf6fc7803f12e273b4ca101e6364e49/scripts/v2-e2e/legacy-peers/peer.py#L53) | retained syntax; documentation may expand |
| `scripts/legacy-peers/peer.py:Peer.artifacts` | [same qualified symbol](https://github.com/kentbull/keripy/blob/6aadd69beaf6fc7803f12e273b4ca101e6364e49/scripts/v2-e2e/legacy-peers/peer.py#L59) | retained syntax; documentation may expand |
| `scripts/legacy-peers/peer.py:Peer.grant` | [same qualified symbol](https://github.com/kentbull/keripy/blob/6aadd69beaf6fc7803f12e273b4ca101e6364e49/scripts/v2-e2e/legacy-peers/peer.py#L88) | retained syntax; documentation may expand |
| `scripts/legacy-peers/peer.py:Peer.revoke` | [same qualified symbol](https://github.com/kentbull/keripy/blob/6aadd69beaf6fc7803f12e273b4ca101e6364e49/scripts/v2-e2e/legacy-peers/peer.py#L93) | retained syntax; documentation may expand |
| `scripts/legacy-peers/peer.py:Peer.replyDo` | [same qualified symbol](https://github.com/kentbull/keripy/blob/6aadd69beaf6fc7803f12e273b4ca101e6364e49/scripts/v2-e2e/legacy-peers/peer.py#L111) | retained syntax; documentation may expand |
| `scripts/legacy-peers/peer.py:Peer.shutdown` | [same qualified symbol](https://github.com/kentbull/keripy/blob/6aadd69beaf6fc7803f12e273b4ca101e6364e49/scripts/v2-e2e/legacy-peers/peer.py#L140) | retained syntax; documentation may expand |
| `scripts/legacy-peers/peer.py:QueryEnd` | [same qualified symbol](https://github.com/kentbull/keripy/blob/6aadd69beaf6fc7803f12e273b4ca101e6364e49/scripts/v2-e2e/legacy-peers/peer.py#L147) | retained syntax; documentation may expand |
| `scripts/legacy-peers/peer.py:QueryEnd.__init__` | [same qualified symbol](https://github.com/kentbull/keripy/blob/6aadd69beaf6fc7803f12e273b4ca101e6364e49/scripts/v2-e2e/legacy-peers/peer.py#L148) | retained syntax; documentation may expand |
| `scripts/legacy-peers/peer.py:QueryEnd.on_post` | [same qualified symbol](https://github.com/kentbull/keripy/blob/6aadd69beaf6fc7803f12e273b4ca101e6364e49/scripts/v2-e2e/legacy-peers/peer.py#L151) | retained syntax; documentation may expand |
| `scripts/legacy-peers/peer.py:ProfileEnd` | [same qualified symbol](https://github.com/kentbull/keripy/blob/6aadd69beaf6fc7803f12e273b4ca101e6364e49/scripts/v2-e2e/legacy-peers/peer.py#L162) | retained syntax; documentation may expand |
| `scripts/legacy-peers/peer.py:ProfileEnd.__init__` | [same qualified symbol](https://github.com/kentbull/keripy/blob/6aadd69beaf6fc7803f12e273b4ca101e6364e49/scripts/v2-e2e/legacy-peers/peer.py#L163) | retained syntax; documentation may expand |
| `scripts/legacy-peers/peer.py:ProfileEnd.on_get` | [same qualified symbol](https://github.com/kentbull/keripy/blob/6aadd69beaf6fc7803f12e273b4ca101e6364e49/scripts/v2-e2e/legacy-peers/peer.py#L166) | retained syntax; documentation may expand |
| `scripts/legacy-peers/peer.py:ArtifactsEnd` | [same qualified symbol](https://github.com/kentbull/keripy/blob/6aadd69beaf6fc7803f12e273b4ca101e6364e49/scripts/v2-e2e/legacy-peers/peer.py#L178) | retained syntax; documentation may expand |
| `scripts/legacy-peers/peer.py:ArtifactsEnd.__init__` | [same qualified symbol](https://github.com/kentbull/keripy/blob/6aadd69beaf6fc7803f12e273b4ca101e6364e49/scripts/v2-e2e/legacy-peers/peer.py#L179) | retained syntax; documentation may expand |
| `scripts/legacy-peers/peer.py:ArtifactsEnd.on_post` | [same qualified symbol](https://github.com/kentbull/keripy/blob/6aadd69beaf6fc7803f12e273b4ca101e6364e49/scripts/v2-e2e/legacy-peers/peer.py#L182) | retained syntax; documentation may expand |
| `scripts/legacy-peers/peer.py:RevokeEnd` | [same qualified symbol](https://github.com/kentbull/keripy/blob/6aadd69beaf6fc7803f12e273b4ca101e6364e49/scripts/v2-e2e/legacy-peers/peer.py#L186) | retained syntax; documentation may expand |
| `scripts/legacy-peers/peer.py:RevokeEnd.__init__` | [same qualified symbol](https://github.com/kentbull/keripy/blob/6aadd69beaf6fc7803f12e273b4ca101e6364e49/scripts/v2-e2e/legacy-peers/peer.py#L187) | retained syntax; documentation may expand |
| `scripts/legacy-peers/peer.py:RevokeEnd.on_post` | [same qualified symbol](https://github.com/kentbull/keripy/blob/6aadd69beaf6fc7803f12e273b4ca101e6364e49/scripts/v2-e2e/legacy-peers/peer.py#L190) | retained syntax; documentation may expand |
| `scripts/legacy-peers/peer.py:ControlEnd` | [same qualified symbol](https://github.com/kentbull/keripy/blob/6aadd69beaf6fc7803f12e273b4ca101e6364e49/scripts/v2-e2e/legacy-peers/peer.py#L194) | retained syntax; documentation may expand |
| `scripts/legacy-peers/peer.py:ControlEnd.__init__` | [same qualified symbol](https://github.com/kentbull/keripy/blob/6aadd69beaf6fc7803f12e273b4ca101e6364e49/scripts/v2-e2e/legacy-peers/peer.py#L195) | retained syntax; documentation may expand |
| `scripts/legacy-peers/peer.py:ControlEnd.on_post` | [same qualified symbol](https://github.com/kentbull/keripy/blob/6aadd69beaf6fc7803f12e273b4ca101e6364e49/scripts/v2-e2e/legacy-peers/peer.py#L198) | retained syntax; documentation may expand |
| `src/dolly/cli.py:buildParser` | new local symbol; no exact donor asserted | locally generated implementation/test |
| `src/dolly/cli.py:openIdentity` | new local symbol; no exact donor asserted | locally generated implementation/test |
| `src/dolly/cli.py:handler` | [same qualified symbol](https://github.com/kentbull/keripy/blob/e999aa9c4a457b7c52e05e3bb3dd03f6e3c8f83c/src/keri/cli/commands/dolly/start.py#L27) | adapted; review destination against donor |
| `src/dolly/cli.py:inspectSubmission` | new local symbol; no exact donor asserted | locally generated implementation/test |
| `src/dolly/cli.py:main` | new local symbol; no exact donor asserted | locally generated implementation/test |
| `src/dolly/cli.py:main.stop` | new local symbol; no exact donor asserted | locally generated implementation/test |
| `src/dolly/projecting.py:project` | [same qualified symbol](https://github.com/kentbull/keripy/blob/e999aa9c4a457b7c52e05e3bb3dd03f6e3c8f83c/src/keri/app/dolly/projecting.py#L8) | retained syntax; documentation may expand |
| `src/dolly/schemas/__init__.py:manifest` | new local symbol; no exact donor asserted | locally generated implementation/test |
| `src/dolly/schemas/__init__.py:load` | new local symbol; no exact donor asserted | locally generated implementation/test |
| `src/dolly/serving.py:Submission` | [same qualified symbol](https://github.com/kentbull/keripy/blob/e999aa9c4a457b7c52e05e3bb3dd03f6e3c8f83c/src/keri/app/dolly/serving.py#L34) | retained syntax; documentation may expand |
| `src/dolly/serving.py:Observation` | [same qualified symbol](https://github.com/kentbull/keripy/blob/e999aa9c4a457b7c52e05e3bb3dd03f6e3c8f83c/src/keri/app/dolly/serving.py#L44) | retained syntax; documentation may expand |
| `src/dolly/serving.py:LegacyQuery` | [same qualified symbol](https://github.com/kentbull/keripy/blob/e999aa9c4a457b7c52e05e3bb3dd03f6e3c8f83c/src/keri/app/dolly/serving.py#L51) | retained syntax; documentation may expand |
| `src/dolly/serving.py:DollyBaser` | [same qualified symbol](https://github.com/kentbull/keripy/blob/e999aa9c4a457b7c52e05e3bb3dd03f6e3c8f83c/src/keri/app/dolly/serving.py#L59) | retained syntax; documentation may expand |
| `src/dolly/serving.py:DollyBaser.reopen` | [same qualified symbol](https://github.com/kentbull/keripy/blob/e999aa9c4a457b7c52e05e3bb3dd03f6e3c8f83c/src/keri/app/dolly/serving.py#L63) | retained syntax; documentation may expand |
| `src/dolly/serving.py:Notices` | [same qualified symbol](https://github.com/kentbull/keripy/blob/e999aa9c4a457b7c52e05e3bb3dd03f6e3c8f83c/src/keri/app/dolly/serving.py#L71) | retained syntax; documentation may expand |
| `src/dolly/serving.py:Notices.add` | [same qualified symbol](https://github.com/kentbull/keripy/blob/e999aa9c4a457b7c52e05e3bb3dd03f6e3c8f83c/src/keri/app/dolly/serving.py#L72) | retained syntax; documentation may expand |
| `src/dolly/serving.py:Context` | [same qualified symbol](https://github.com/kentbull/keripy/blob/e999aa9c4a457b7c52e05e3bb3dd03f6e3c8f83c/src/keri/app/dolly/serving.py#L77) | adapted; review destination against donor |
| `src/dolly/serving.py:Context.__init__` | [same qualified symbol](https://github.com/kentbull/keripy/blob/e999aa9c4a457b7c52e05e3bb3dd03f6e3c8f83c/src/keri/app/dolly/serving.py#L78) | retained syntax; documentation may expand |
| `src/dolly/serving.py:Context._parser` | [same qualified symbol](https://github.com/kentbull/keripy/blob/e999aa9c4a457b7c52e05e3bb3dd03f6e3c8f83c/src/keri/app/dolly/serving.py#L127) | adapted; review destination against donor |
| `src/dolly/serving.py:Context.ingest` | [same qualified symbol](https://github.com/kentbull/keripy/blob/e999aa9c4a457b7c52e05e3bb3dd03f6e3c8f83c/src/keri/app/dolly/serving.py#L137) | adapted; review destination against donor |
| `src/dolly/serving.py:Context.dispatch` | new local symbol; no exact donor asserted | locally generated implementation/test |
| `src/dolly/serving.py:Context.fresh` | [same qualified symbol](https://github.com/kentbull/keripy/blob/e999aa9c4a457b7c52e05e3bb3dd03f6e3c8f83c/src/keri/app/dolly/serving.py#L178) | retained syntax; documentation may expand |
| `src/dolly/serving.py:Context.observe` | [same qualified symbol](https://github.com/kentbull/keripy/blob/e999aa9c4a457b7c52e05e3bb3dd03f6e3c8f83c/src/keri/app/dolly/serving.py#L187) | retained syntax; documentation may expand |
| `src/dolly/serving.py:Context._nativeCredential` | [same qualified symbol](https://github.com/kentbull/keripy/blob/e999aa9c4a457b7c52e05e3bb3dd03f6e3c8f83c/src/keri/app/dolly/serving.py#L208) | retained syntax; documentation may expand |
| `src/dolly/serving.py:Context._nativeDisclosure` | [same qualified symbol](https://github.com/kentbull/keripy/blob/e999aa9c4a457b7c52e05e3bb3dd03f6e3c8f83c/src/keri/app/dolly/serving.py#L222) | retained syntax; documentation may expand |
| `src/dolly/serving.py:Context.inspectHistorical` | [same qualified symbol](https://github.com/kentbull/keripy/blob/e999aa9c4a457b7c52e05e3bb3dd03f6e3c8f83c/src/keri/app/dolly/serving.py#L238) | retained syntax; documentation may expand |
| `src/dolly/serving.py:Context._historicalSources` | [same qualified symbol](https://github.com/kentbull/keripy/blob/e999aa9c4a457b7c52e05e3bb3dd03f6e3c8f83c/src/keri/app/dolly/serving.py#L263) | retained syntax; documentation may expand |
| `src/dolly/serving.py:Context._nativeCurrentStanding` | [same qualified symbol](https://github.com/kentbull/keripy/blob/e999aa9c4a457b7c52e05e3bb3dd03f6e3c8f83c/src/keri/app/dolly/serving.py#L295) | retained syntax; documentation may expand |
| `src/dolly/serving.py:Context._legacyCredential` | [same qualified symbol](https://github.com/kentbull/keripy/blob/e999aa9c4a457b7c52e05e3bb3dd03f6e3c8f83c/src/keri/app/dolly/serving.py#L319) | adapted; review destination against donor |
| `src/dolly/serving.py:Context._queryLegacy` | [same qualified symbol](https://github.com/kentbull/keripy/blob/e999aa9c4a457b7c52e05e3bb3dd03f6e3c8f83c/src/keri/app/dolly/serving.py#L356) | retained syntax; documentation may expand |
| `src/dolly/serving.py:Context._legacyReports` | [same qualified symbol](https://github.com/kentbull/keripy/blob/e999aa9c4a457b7c52e05e3bb3dd03f6e3c8f83c/src/keri/app/dolly/serving.py#L372) | retained syntax; documentation may expand |
| `src/dolly/serving.py:Context.process` | [same qualified symbol](https://github.com/kentbull/keripy/blob/e999aa9c4a457b7c52e05e3bb3dd03f6e3c8f83c/src/keri/app/dolly/serving.py#L398) | retained syntax; documentation may expand |
| `src/dolly/serving.py:Context.request` | [same qualified symbol](https://github.com/kentbull/keripy/blob/e999aa9c4a457b7c52e05e3bb3dd03f6e3c8f83c/src/keri/app/dolly/serving.py#L445) | retained syntax; documentation may expand |
| `src/dolly/serving.py:Context.workDo` | [same qualified symbol](https://github.com/kentbull/keripy/blob/e999aa9c4a457b7c52e05e3bb3dd03f6e3c8f83c/src/keri/app/dolly/serving.py#L464) | retained syntax; documentation may expand |
| `src/dolly/serving.py:Context.close` | [same qualified symbol](https://github.com/kentbull/keripy/blob/e999aa9c4a457b7c52e05e3bb3dd03f6e3c8f83c/src/keri/app/dolly/serving.py#L510) | retained syntax; documentation may expand |
| `src/dolly/serving.py:IntakeEnd` | [same qualified symbol](https://github.com/kentbull/keripy/blob/e999aa9c4a457b7c52e05e3bb3dd03f6e3c8f83c/src/keri/app/dolly/serving.py#L524) | adapted; review destination against donor |
| `src/dolly/serving.py:IntakeEnd.__init__` | [same qualified symbol](https://github.com/kentbull/keripy/blob/e999aa9c4a457b7c52e05e3bb3dd03f6e3c8f83c/src/keri/app/dolly/serving.py#L525) | retained syntax; documentation may expand |
| `src/dolly/serving.py:IntakeEnd.decode` | [same qualified symbol](https://github.com/kentbull/keripy/blob/e999aa9c4a457b7c52e05e3bb3dd03f6e3c8f83c/src/keri/app/dolly/serving.py#L530) | retained syntax; documentation may expand |
| `src/dolly/serving.py:IntakeEnd.on_post` | [same qualified symbol](https://github.com/kentbull/keripy/blob/e999aa9c4a457b7c52e05e3bb3dd03f6e3c8f83c/src/keri/app/dolly/serving.py#L555) | adapted; review destination against donor |
| `src/dolly/serving.py:HealthEnd` | [same qualified symbol](https://github.com/kentbull/keripy/blob/e999aa9c4a457b7c52e05e3bb3dd03f6e3c8f83c/src/keri/app/dolly/serving.py#L576) | retained syntax; documentation may expand |
| `src/dolly/serving.py:HealthEnd.on_get` | [same qualified symbol](https://github.com/kentbull/keripy/blob/e999aa9c4a457b7c52e05e3bb3dd03f6e3c8f83c/src/keri/app/dolly/serving.py#L577) | retained syntax; documentation may expand |
| `src/dolly/serving.py:StreamParser` | new local symbol; no exact donor asserted | locally generated implementation/test |
| `src/dolly/serving.py:StreamParser.__init__` | new local symbol; no exact donor asserted | locally generated implementation/test |
| `src/dolly/serving.py:StreamParser.msgProcess` | new local symbol; no exact donor asserted | locally generated implementation/test |
| `src/dolly/serving.py:TcpIntake` | new local symbol; no exact donor asserted | locally generated implementation/test |
| `src/dolly/serving.py:TcpIntake.__init__` | new local symbol; no exact donor asserted | locally generated implementation/test |
| `src/dolly/serving.py:TcpIntake.recur` | new local symbol; no exact donor asserted | locally generated implementation/test |
| `src/dolly/serving.py:TcpIntake._close` | new local symbol; no exact donor asserted | locally generated implementation/test |
| `src/dolly/serving.py:TcpIntake.exit` | new local symbol; no exact donor asserted | locally generated implementation/test |
| `src/dolly/serving.py:setup` | [same qualified symbol](https://github.com/kentbull/keripy/blob/e999aa9c4a457b7c52e05e3bb3dd03f6e3c8f83c/src/keri/app/dolly/serving.py#L581) | adapted; review destination against donor |
| `tests/test_dolly.py:native` | [same qualified symbol](https://github.com/kentbull/keripy/blob/e999aa9c4a457b7c52e05e3bb3dd03f6e3c8f83c/tests/app/test_dolly.py#L29) | retained syntax; documentation may expand |
| `tests/test_dolly.py:test_empty_grant_is_terminal_and_later_grants_report_after_reopen` | [same qualified symbol](https://github.com/kentbull/keripy/blob/e999aa9c4a457b7c52e05e3bb3dd03f6e3c8f83c/tests/app/test_dolly.py#L34) | adapted; review destination against donor |
| `tests/test_dolly.py:test_empty_grant_is_terminal_and_later_grants_report_after_reopen.Hook` | [same qualified symbol](https://github.com/kentbull/keripy/blob/e999aa9c4a457b7c52e05e3bb3dd03f6e3c8f83c/tests/app/test_dolly.py#L46) | retained syntax; documentation may expand |
| `tests/test_dolly.py:test_empty_grant_is_terminal_and_later_grants_report_after_reopen.Hook.on_post` | [same qualified symbol](https://github.com/kentbull/keripy/blob/e999aa9c4a457b7c52e05e3bb3dd03f6e3c8f83c/tests/app/test_dolly.py#L49) | retained syntax; documentation may expand |
| `tests/test_dolly.py:test_http_json_native_registry_first_and_invalid_framing` | [same qualified symbol](https://github.com/kentbull/keripy/blob/e999aa9c4a457b7c52e05e3bb3dd03f6e3c8f83c/tests/app/test_dolly.py#L111) | adapted; review destination against donor |
| `tests/test_dolly.py:test_dolly_independent_schema_http_arrival_preserves_disclosure` | [same qualified symbol](https://github.com/kentbull/keripy/blob/e999aa9c4a457b7c52e05e3bb3dd03f6e3c8f83c/tests/app/test_dolly.py#L173) | adapted; review destination against donor |
| `tests/test_dolly.py:test_dolly_independent_schema_http_arrival_preserves_disclosure.Hook` | [same qualified symbol](https://github.com/kentbull/keripy/blob/e999aa9c4a457b7c52e05e3bb3dd03f6e3c8f83c/tests/app/test_dolly.py#L195) | retained syntax; documentation may expand |
| `tests/test_dolly.py:test_dolly_independent_schema_http_arrival_preserves_disclosure.Hook.on_post` | [same qualified symbol](https://github.com/kentbull/keripy/blob/e999aa9c4a457b7c52e05e3bb3dd03f6e3c8f83c/tests/app/test_dolly.py#L198) | retained syntax; documentation may expand |
| `tests/test_dolly.py:test_dolly_independent_schema_http_arrival_preserves_disclosure.signed` | [same qualified symbol](https://github.com/kentbull/keripy/blob/e999aa9c4a457b7c52e05e3bb3dd03f6e3c8f83c/tests/app/test_dolly.py#L226) | retained syntax; documentation may expand |
| `tests/test_dolly.py:test_dolly_independent_schema_http_arrival_preserves_disclosure.post` | [same qualified symbol](https://github.com/kentbull/keripy/blob/e999aa9c4a457b7c52e05e3bb3dd03f6e3c8f83c/tests/app/test_dolly.py#L250) | retained syntax; documentation may expand |
| `tests/test_dolly.py:test_dolly_independent_schema_http_arrival_preserves_disclosure.section` | [same qualified symbol](https://github.com/kentbull/keripy/blob/e999aa9c4a457b7c52e05e3bb3dd03f6e3c8f83c/tests/app/test_dolly.py#L258) | retained syntax; documentation may expand |
| `tests/test_dolly.py:test_reopened_dolly_requires_active_observer_observation` | [same qualified symbol](https://github.com/kentbull/keripy/blob/e999aa9c4a457b7c52e05e3bb3dd03f6e3c8f83c/tests/app/test_dolly.py#L320) | adapted; review destination against donor |
| `tests/test_dolly.py:test_reopened_dolly_requires_active_observer_observation.context` | [same qualified symbol](https://github.com/kentbull/keripy/blob/e999aa9c4a457b7c52e05e3bb3dd03f6e3c8f83c/tests/app/test_dolly.py#L348) | retained syntax; documentation may expand |
| `tests/test_dolly.py:test_native_partial_full_grants_observer_acquisition_and_real_webhooks` | [same qualified symbol](https://github.com/kentbull/keripy/blob/e999aa9c4a457b7c52e05e3bb3dd03f6e3c8f83c/tests/app/test_dolly.py#L378) | adapted; review destination against donor |
| `tests/test_dolly.py:test_native_partial_full_grants_observer_acquisition_and_real_webhooks.Requests` | [same qualified symbol](https://github.com/kentbull/keripy/blob/e999aa9c4a457b7c52e05e3bb3dd03f6e3c8f83c/tests/app/test_dolly.py#L417) | retained syntax; documentation may expand |
| `tests/test_dolly.py:test_native_partial_full_grants_observer_acquisition_and_real_webhooks.Requests.process_request` | [same qualified symbol](https://github.com/kentbull/keripy/blob/e999aa9c4a457b7c52e05e3bb3dd03f6e3c8f83c/tests/app/test_dolly.py#L418) | retained syntax; documentation may expand |
| `tests/test_dolly.py:test_native_partial_full_grants_observer_acquisition_and_real_webhooks.Hook` | [same qualified symbol](https://github.com/kentbull/keripy/blob/e999aa9c4a457b7c52e05e3bb3dd03f6e3c8f83c/tests/app/test_dolly.py#L423) | retained syntax; documentation may expand |
| `tests/test_dolly.py:test_native_partial_full_grants_observer_acquisition_and_real_webhooks.Hook.on_post` | [same qualified symbol](https://github.com/kentbull/keripy/blob/e999aa9c4a457b7c52e05e3bb3dd03f6e3c8f83c/tests/app/test_dolly.py#L424) | retained syntax; documentation may expand |
| `tests/test_dolly.py:test_native_partial_full_grants_observer_acquisition_and_real_webhooks.send` | new local symbol; no exact donor asserted | locally generated implementation/test |
| `tests/test_dolly.py:test_legacy_current_source_tsn_and_same_real_webhook_contract` | [same qualified symbol](https://github.com/kentbull/keripy/blob/e999aa9c4a457b7c52e05e3bb3dd03f6e3c8f83c/tests/app/test_dolly.py#L531) | adapted; review destination against donor |
| `tests/test_dolly.py:test_legacy_current_source_tsn_and_same_real_webhook_contract.Hook` | [same qualified symbol](https://github.com/kentbull/keripy/blob/e999aa9c4a457b7c52e05e3bb3dd03f6e3c8f83c/tests/app/test_dolly.py#L567) | retained syntax; documentation may expand |
| `tests/test_dolly.py:test_legacy_current_source_tsn_and_same_real_webhook_contract.Hook.on_post` | [same qualified symbol](https://github.com/kentbull/keripy/blob/e999aa9c4a457b7c52e05e3bb3dd03f6e3c8f83c/tests/app/test_dolly.py#L568) | retained syntax; documentation may expand |
| `tests/test_dolly.py:test_legacy_current_source_tsn_and_same_real_webhook_contract.Source` | [same qualified symbol](https://github.com/kentbull/keripy/blob/e999aa9c4a457b7c52e05e3bb3dd03f6e3c8f83c/tests/app/test_dolly.py#L572) | retained syntax; documentation may expand |
| `tests/test_dolly.py:test_legacy_current_source_tsn_and_same_real_webhook_contract.Source.on_post` | [same qualified symbol](https://github.com/kentbull/keripy/blob/e999aa9c4a457b7c52e05e3bb3dd03f6e3c8f83c/tests/app/test_dolly.py#L573) | retained syntax; documentation may expand |
| `tests/test_dolly.py:test_legacy_current_source_tsn_and_same_real_webhook_contract.replies` | [same qualified symbol](https://github.com/kentbull/keripy/blob/e999aa9c4a457b7c52e05e3bb3dd03f6e3c8f83c/tests/app/test_dolly.py#L615) | retained syntax; documentation may expand |
| `tests/test_dolly.py:test_two_node_chain_declared_presentation_registry_and_full_ipex_over_http` | [same qualified symbol](https://github.com/kentbull/keripy/blob/e999aa9c4a457b7c52e05e3bb3dd03f6e3c8f83c/tests/app/test_dolly.py#L677) | retained syntax; documentation may expand |
| `tests/test_dolly.py:test_two_node_chain_declared_presentation_registry_and_full_ipex_over_http.anchor` | [same qualified symbol](https://github.com/kentbull/keripy/blob/e999aa9c4a457b7c52e05e3bb3dd03f6e3c8f83c/tests/app/test_dolly.py#L692) | retained syntax; documentation may expand |
| `tests/test_dolly.py:test_two_node_chain_declared_presentation_registry_and_full_ipex_over_http.Hook` | [same qualified symbol](https://github.com/kentbull/keripy/blob/e999aa9c4a457b7c52e05e3bb3dd03f6e3c8f83c/tests/app/test_dolly.py#L727) | retained syntax; documentation may expand |
| `tests/test_dolly.py:test_two_node_chain_declared_presentation_registry_and_full_ipex_over_http.Hook.on_post` | [same qualified symbol](https://github.com/kentbull/keripy/blob/e999aa9c4a457b7c52e05e3bb3dd03f6e3c8f83c/tests/app/test_dolly.py#L728) | retained syntax; documentation may expand |
| `tests/test_dolly.py:test_two_node_chain_declared_presentation_registry_and_full_ipex_over_http.send` | [same qualified symbol](https://github.com/kentbull/keripy/blob/e999aa9c4a457b7c52e05e3bb3dd03f6e3c8f83c/tests/app/test_dolly.py#L761) | retained syntax; documentation may expand |
| `tests/test_dolly_historical.py:native` | [same qualified symbol](https://github.com/kentbull/keripy/blob/e999aa9c4a457b7c52e05e3bb3dd03f6e3c8f83c/tests/app/test_dolly_historical.py#L32) | retained syntax; documentation may expand |
| `tests/test_dolly_historical.py:test_historical_bound_graph_inspection_is_not_current_reporting` | [same qualified symbol](https://github.com/kentbull/keripy/blob/e999aa9c4a457b7c52e05e3bb3dd03f6e3c8f83c/tests/app/test_dolly_historical.py#L38) | retained syntax; documentation may expand |
| `tests/test_dolly_historical.py:test_historical_bound_graph_inspection_is_not_current_reporting.Hook` | [same qualified symbol](https://github.com/kentbull/keripy/blob/e999aa9c4a457b7c52e05e3bb3dd03f6e3c8f83c/tests/app/test_dolly_historical.py#L48) | retained syntax; documentation may expand |
| `tests/test_dolly_historical.py:test_historical_bound_graph_inspection_is_not_current_reporting.Hook.on_post` | [same qualified symbol](https://github.com/kentbull/keripy/blob/e999aa9c4a457b7c52e05e3bb3dd03f6e3c8f83c/tests/app/test_dolly_historical.py#L51) | retained syntax; documentation may expand |
| `tests/test_dolly_historical.py:test_historical_bound_graph_inspection_is_not_current_reporting.publish` | [same qualified symbol](https://github.com/kentbull/keripy/blob/e999aa9c4a457b7c52e05e3bb3dd03f6e3c8f83c/tests/app/test_dolly_historical.py#L86) | retained syntax; documentation may expand |
| `tests/test_legacy_peer_profiles.py:peer_request` | [same qualified symbol](https://github.com/kentbull/keripy/blob/6aadd69beaf6fc7803f12e273b4ca101e6364e49/tests/app/test_legacy_peer_profiles.py#L27) | retained syntax; documentation may expand |
| `tests/test_legacy_peer_profiles.py:test_released_legacy_issuer_current_source_and_dolly_webhook` | [same qualified symbol](https://github.com/kentbull/keripy/blob/6aadd69beaf6fc7803f12e273b4ca101e6364e49/tests/app/test_legacy_peer_profiles.py#L36) | adapted; review destination against donor |
| `tests/test_legacy_peer_profiles.py:test_released_legacy_issuer_current_source_and_dolly_webhook.Hook` | [same qualified symbol](https://github.com/kentbull/keripy/blob/6aadd69beaf6fc7803f12e273b4ca101e6364e49/tests/app/test_legacy_peer_profiles.py#L53) | retained syntax; documentation may expand |
| `tests/test_legacy_peer_profiles.py:test_released_legacy_issuer_current_source_and_dolly_webhook.Hook.on_post` | [same qualified symbol](https://github.com/kentbull/keripy/blob/6aadd69beaf6fc7803f12e273b4ca101e6364e49/tests/app/test_legacy_peer_profiles.py#L54) | retained syntax; documentation may expand |
| `tests/test_legacy_peer_profiles.py:test_released_legacy_issuer_current_source_and_dolly_webhook.phases` | [same qualified symbol](https://github.com/kentbull/keripy/blob/6aadd69beaf6fc7803f12e273b4ca101e6364e49/tests/app/test_legacy_peer_profiles.py#L87) | retained syntax; documentation may expand |
| `tests/test_native_e2e.py:port` | [same qualified symbol](https://github.com/kentbull/keripy/blob/6aadd69beaf6fc7803f12e273b4ca101e6364e49/tests/app/test_native_e2e.py#L44) | retained syntax; documentation may expand |
| `tests/test_native_e2e.py:eventually` | [same qualified symbol](https://github.com/kentbull/keripy/blob/6aadd69beaf6fc7803f12e273b4ca101e6364e49/tests/app/test_native_e2e.py#L50) | retained syntax; documentation may expand |
| `tests/test_native_e2e.py:Processes` | [same qualified symbol](https://github.com/kentbull/keripy/blob/6aadd69beaf6fc7803f12e273b4ca101e6364e49/tests/app/test_native_e2e.py#L64) | adapted; review destination against donor |
| `tests/test_native_e2e.py:Processes.__init__` | [same qualified symbol](https://github.com/kentbull/keripy/blob/6aadd69beaf6fc7803f12e273b4ca101e6364e49/tests/app/test_native_e2e.py#L65) | retained syntax; documentation may expand |
| `tests/test_native_e2e.py:Processes.command` | [same qualified symbol](https://github.com/kentbull/keripy/blob/6aadd69beaf6fc7803f12e273b4ca101e6364e49/tests/app/test_native_e2e.py#L71) | adapted; review destination against donor |
| `tests/test_native_e2e.py:Processes.invoke` | [same qualified symbol](https://github.com/kentbull/keripy/blob/6aadd69beaf6fc7803f12e273b4ca101e6364e49/tests/app/test_native_e2e.py#L75) | retained syntax; documentation may expand |
| `tests/test_native_e2e.py:Processes.start` | [same qualified symbol](https://github.com/kentbull/keripy/blob/6aadd69beaf6fc7803f12e273b4ca101e6364e49/tests/app/test_native_e2e.py#L84) | retained syntax; documentation may expand |
| `tests/test_native_e2e.py:Processes.exportKel` | [same qualified symbol](https://github.com/kentbull/keripy/blob/6aadd69beaf6fc7803f12e273b4ca101e6364e49/tests/app/test_native_e2e.py#L91) | retained syntax; documentation may expand |
| `tests/test_native_e2e.py:Processes.stop` | [same qualified symbol](https://github.com/kentbull/keripy/blob/6aadd69beaf6fc7803f12e273b4ca101e6364e49/tests/app/test_native_e2e.py#L97) | retained syntax; documentation may expand |
| `tests/test_native_e2e.py:Processes.close` | [same qualified symbol](https://github.com/kentbull/keripy/blob/6aadd69beaf6fc7803f12e273b4ca101e6364e49/tests/app/test_native_e2e.py#L106) | retained syntax; documentation may expand |
| `tests/test_native_e2e.py:http` | [same qualified symbol](https://github.com/kentbull/keripy/blob/6aadd69beaf6fc7803f12e273b4ca101e6364e49/tests/app/test_native_e2e.py#L112) | retained syntax; documentation may expand |
| `tests/test_native_e2e.py:test_independent_cli_witness_holder_observer_dolly_restart_and_revocation` | [same qualified symbol](https://github.com/kentbull/keripy/blob/6aadd69beaf6fc7803f12e273b4ca101e6364e49/tests/app/test_native_e2e.py#L121) | adapted; review destination against donor |
| `tests/test_native_e2e.py:test_independent_cli_witness_holder_observer_dolly_restart_and_revocation.received` | [same qualified symbol](https://github.com/kentbull/keripy/blob/6aadd69beaf6fc7803f12e273b4ca101e6364e49/tests/app/test_native_e2e.py#L156) | retained syntax; documentation may expand |
| `tests/test_native_e2e.py:test_independent_cli_witness_holder_observer_dolly_restart_and_revocation.delivered` | [same qualified symbol](https://github.com/kentbull/keripy/blob/6aadd69beaf6fc7803f12e273b4ca101e6364e49/tests/app/test_native_e2e.py#L159) | retained syntax; documentation may expand |
| `tests/test_native_e2e.py:test_independent_cli_witness_holder_observer_dolly_restart_and_revocation.signed` | [same qualified symbol](https://github.com/kentbull/keripy/blob/6aadd69beaf6fc7803f12e273b4ca101e6364e49/tests/app/test_native_e2e.py#L166) | retained syntax; documentation may expand |
| `tests/test_native_e2e.py:test_independent_cli_witness_holder_observer_dolly_restart_and_revocation.publish` | [same qualified symbol](https://github.com/kentbull/keripy/blob/6aadd69beaf6fc7803f12e273b4ca101e6364e49/tests/app/test_native_e2e.py#L171) | retained syntax; documentation may expand |
| `tests/test_native_e2e.py:test_independent_cli_witness_holder_observer_dolly_restart_and_revocation.query` | [same qualified symbol](https://github.com/kentbull/keripy/blob/6aadd69beaf6fc7803f12e273b4ca101e6364e49/tests/app/test_native_e2e.py#L214) | retained syntax; documentation may expand |
| `tests/test_native_e2e.py:test_independent_cli_witness_holder_observer_dolly_restart_and_revocation.accepted` | [same qualified symbol](https://github.com/kentbull/keripy/blob/6aadd69beaf6fc7803f12e273b4ca101e6364e49/tests/app/test_native_e2e.py#L240) | retained syntax; documentation may expand |
| `tests/test_native_e2e.py:test_independent_cli_witness_holder_observer_dolly_restart_and_revocation.retained` | [same qualified symbol](https://github.com/kentbull/keripy/blob/6aadd69beaf6fc7803f12e273b4ca101e6364e49/tests/app/test_native_e2e.py#L245) | retained syntax; documentation may expand |
| `tests/test_native_e2e.py:test_independent_cli_witness_holder_observer_dolly_restart_and_revocation.negotiate` | [same qualified symbol](https://github.com/kentbull/keripy/blob/6aadd69beaf6fc7803f12e273b4ca101e6364e49/tests/app/test_native_e2e.py#L251) | retained syntax; documentation may expand |
| `tests/test_native_e2e.py:test_independent_cli_witness_holder_observer_dolly_restart_and_revocation.negotiate.exchange` | [same qualified symbol](https://github.com/kentbull/keripy/blob/6aadd69beaf6fc7803f12e273b4ca101e6364e49/tests/app/test_native_e2e.py#L259) | retained syntax; documentation may expand |
| `tests/test_native_e2e.py:test_independent_cli_witness_holder_observer_dolly_restart_and_revocation.currentHead` | [same qualified symbol](https://github.com/kentbull/keripy/blob/6aadd69beaf6fc7803f12e273b4ca101e6364e49/tests/app/test_native_e2e.py#L344) | retained syntax; documentation may expand |
| `tests/test_transport.py:signed` | new local symbol; no exact donor asserted | locally generated implementation/test |
| `tests/test_transport.py:test_packaged_schema_manifest_and_no_application_in_keripy` | new local symbol; no exact donor asserted | locally generated implementation/test |
| `tests/test_transport.py:test_tcp_fragmented_consecutive_and_malformed_connections_are_isolated` | new local symbol; no exact donor asserted | locally generated implementation/test |
| `tests/test_transport.py:test_tcp_fragmented_consecutive_and_malformed_connections_are_isolated.Hook` | new local symbol; no exact donor asserted | locally generated implementation/test |
| `tests/test_transport.py:test_tcp_fragmented_consecutive_and_malformed_connections_are_isolated.Hook.on_post` | new local symbol; no exact donor asserted | locally generated implementation/test |
| `tests/test_transport.py:test_tcp_fragmented_consecutive_and_malformed_connections_are_isolated.finish` | new local symbol; no exact donor asserted | locally generated implementation/test |
| `tests/test_transport.py:freePort` | new local symbol; no exact donor asserted | locally generated implementation/test |
| `tests/test_transport.py:test_installed_wheel_dual_listener_start_stop_restart_and_local_inspect` | new local symbol; no exact donor asserted | locally generated implementation/test |
| `tests/test_transport.py:test_installed_wheel_dual_listener_start_stop_restart_and_local_inspect.Hook` | new local symbol; no exact donor asserted | locally generated implementation/test |
| `tests/test_transport.py:test_installed_wheel_dual_listener_start_stop_restart_and_local_inspect.Hook.do_POST` | new local symbol; no exact donor asserted | locally generated implementation/test |
| `tests/test_transport.py:test_installed_wheel_dual_listener_start_stop_restart_and_local_inspect.Hook.log_message` | new local symbol; no exact donor asserted | locally generated implementation/test |
| `tests/test_transport.py:test_installed_wheel_dual_listener_start_stop_restart_and_local_inspect.waitFor` | new local symbol; no exact donor asserted | locally generated implementation/test |
| `tests/test_transport.py:test_installed_wheel_dual_listener_start_stop_restart_and_local_inspect.ready` | new local symbol; no exact donor asserted | locally generated implementation/test |
| `tests/test_transport.py:test_installed_wheel_dual_listener_start_stop_restart_and_local_inspect.inspect` | new local symbol; no exact donor asserted | locally generated implementation/test |

Every listed source/test/helper class and function has a meaningful docstring.
Tests document their real evidence boundaries; comments explain non-obvious framing,
retained disclosure, current-standing, or scheduler invariants. That coverage does
not certify protocol correctness; executable qualification is recorded separately.

Inventory: 149 explicit Python symbols.


## Installed v1 operator artifacts

The `scripts/operator/` workflow is a new local Bash orchestration under Kent's
request for visible installed-CLI issuance, negotiation, admission, reporting
and revocation. It is not copied from a Python lifecycle test. No exact donor
is asserted for `legacy-v1.sh`, `run-legacy-v1.sh`, `Dockerfile`,
`json_helpers.py` or its README. The runner's copied-wheel/named-volume build
pattern follows this repository's `scripts/check.sh` and KERIpy's scenario
runner; its operation sequence is newly composed from existing KLI commands.

The script sources the infrastructure functions and standard-library HTTP/JSON
helper from KERIpy commit
[`63453fe3b7bf39f4cbfc5e618bd9e0c4b09b6d4e`](https://github.com/kentbull/keripy/tree/63453fe3b7bf39f4cbfc5e618bd9e0c4b09b6d4e/scripts/v2-e2e/scenarios).
It uses `value`, `assert_json`, `cleanup`, `k`, `spawn`, `stop`, `poll` and
`delivered`, plus helper port/readiness/hook operations. It does not invoke
`prepare`, `services` or other credential lifecycle setup. Those imported
functions keep their KERIpy definitions and documentation; no copied Python
protocol implementation is added to Dolly.

The separate generic evidence source is KERIpy's `legacy_evidence.Source` and
`vc.registry.serve`, composed from the normal Parser, Tevery, Hab.reply and
accepted TEL replay writer. It is invoked as an installed operator command;
Dolly owns only the reporting policy and hooks. The v1 script relies on the
established-version witness adapter (`f42647d194545a20d97a4386d3fcd868f72a9479`),
legacy author adapters (`b0d30d05c0c1f4df330cd63f477820d93441f641`), and
reviewed direct IPEX command paths. These references explain dependencies,
not original idea authorship; each run records its actual source revisions,
dirty flags, installed versions and wheel hashes independently.

`json_helpers.py` has no function/class symbols. Its module contract documents
all three argument forms, emitted artifacts and failure behavior. Both Bash
entry points document build/state/error/cleanup responsibilities in their
companion README; lifecycle comments identify protocol evidence boundaries.
The workflow asserts local admit creation and verification, not independently
observed remote admission acknowledgement. Successful hook assertions exercise
actual source TSN acceptance through Dolly's normal core processors. This is
one bounded v1 story, not universal protocol conformance or readiness.
