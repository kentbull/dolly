# Dolly

Dolly owns credential reporting policy, retained disclosure projection, historical
inspection, submissions, and webhook delivery. KERIpy owns protocol parsing,
authentication, KEL/TEL/ACDC verification, IPEX, and protocol escrows.

This R&D package is not a production-readiness or universal conformance claim.
See `docs/extraction.md` for source lineage, behavior changes, and validation.

## Install and run

Use Python 3.14. KERIpy is pinned in `pyproject.toml`. For an offline qualified
installation, install its matching wheel and locked dependencies first, then
`pip install --no-deps dolly-0.1.0.dev0-py3-none-any.whl`.

Create the verifier identity with the installed KERIpy `kli` commands. Both
supported unencrypted identities and authenticated encrypted identities work;
Dolly does not require registry derivation custody. Encrypted identities retain
their normal passcode authentication. An unencrypted identity is opened without
supplying a passcode, so starting Dolly cannot silently migrate its encryption.

```sh
dolly server start --direct --name verifier --alias verifier \
  --config policy.json --http 6644 --tcp 6645 --no-prompt
```

Policy JSON contains `issuers`, `schemas`, `fields`, optional `required`,
`observer`, `webhook`, and optional `legacySources`. See the tests for concrete
non-vLEI examples. TCP and HTTP ports are independent; select either or both.
TCP carries raw CESR, with one parser/buffer per connection. HTTP accepts
`application/cesr`, raw streams or one body plus `CESR-ATTACHMENT`. A 202 means
intake, never credential acceptance or hook delivery. Malformed HTTP is refused;
malformed/incomplete TCP evidence stays connection-local.

`--kel FILE` bootstraps signed public KEL evidence (`--kel-genus 1` for v1).
`--schema FILE` explicitly loads a legacy schema, and `--packaged-schema NAME`
loads a manifest-verified packaged fixture. These are explicit inputs; independent
native schema sections also arrive through either listener and remain separate
from application schema allowlists.

Native v2 uses the core's enabled KRAM policy. V1 follows the core v1 processor;
no connection or request toggles shared authentication settings.

To inspect a persisted application decision locally, authenticate its identity:

```sh
dolly inspect --name verifier --base BASE --grant GRANT_SAID --no-prompt
```

The JSON includes `state`, `reason`, projected `payload`, and `delivered`; an
unknown grant has `state="unknown"`. This opens Dolly's submission store read-only.
`accepted` means reporting policy passed; `delivered` records a hook 2xx response.
It does not independently revalidate proof or establish current freshness.

Historical inspection is the Python API `Context.inspectHistorical(grantSaid)`.
It reads retained authenticated native evidence, labels standing unevaluated,
and never emits an acceptance hook or freshness/publication-time claim.

## Component tests and provenance

Install the package and its declared dependencies in Python 3.14, then run
`python -m pytest -q tests`. The retained suite covers verifier policy, historical
inspection, and actual HTTP/TCP listener/restart behavior. Linux-owned state
volumes avoid host LMDB limitations. The independent experiment repository owns
composed images, released-peer environments and operator scenarios.

See [source provenance](docs/provenance.md) for module and symbol ancestry.

## Experiment ownership

Cross-repository recipes, external acceptance scenarios and dated evidence are
owned by the independent `keri-v2` experiment repository. They are not required
to run this component. [Pre-extraction record](https://github.com/kentbull/dolly/blob/a48799219a45aeb3e3a0414888a0aae8dbce2851/README.md) preserves the
historical source and execution scope. The extraction changes ownership only;
runtime dependencies and verification contracts remain unchanged.
