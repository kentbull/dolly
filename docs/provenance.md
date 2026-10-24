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
| `src/dolly/schemas/*` | Local fixture layer; manifest carries exact SAIDs and origins. | Legacy JSON extracted from donor test, native entitlement schema locally authored; no external ecosystem provenance asserted. |
| `tests/test_transport.py` | New local integration tests. | Actual installed console, sockets, authenticated processors, hooks, restart, and inspection; no core test-module imports. |
| `pyproject.toml` | New local standalone packaging. | KERIpy dependency pin is explicit; composed builds are experiment-owned. |
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

Inventory: 99 retained Python symbols, selected from the original 149-symbol
snapshot. External peer/process symbols remain in the experiment provenance copy.



## Packaged native map schema

The optional `acm-default-v2` packaged schema is the exact committed schema
returned by KERIpy `acmSchemaDefault` at `64b5c6af`. Git blame traces that function
to Samuel M Smith's `18dd8825` in the former `src/keri/vc/messaging.py`.
Packaging and explicit scenario selection are local integration decisions. The
schema is permissive structural validation, not an issuer allowlist or acceptance
policy. It is needed when Locksmith sends a credential with a schema digest
instead of an embedded schema; Dolly still enforces its configured issuer,
schema and field policy. It is loaded only when explicitly requested.


## Runtime dependency

The declared KERIpy revision remains
`993b58266992b786d044fd3938e114a19d76f62f`. Ownership extraction does not change
this dependency or the supported packaged schema resources.

## Experiment ownership

Cross-repository recipes, external acceptance scenarios and dated evidence are
owned by the independent `keri-v2` experiment repository. They are not required
to run this component. [Pre-extraction record](https://github.com/kentbull/dolly/blob/a48799219a45aeb3e3a0414888a0aae8dbce2851/docs/provenance.md) preserves the
historical source and execution scope. The extraction changes ownership only;
runtime dependencies and verification contracts remain unchanged.
