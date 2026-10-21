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

Historical inspection is the Python API `Context.inspectHistorical(grantSaid)`.
It reads retained authenticated native evidence, labels standing unevaluated,
and never emits an acceptance hook or freshness/publication-time claim.

## Linux qualification

Run with copied source and named Linux state volumes, without host bind mounts:

```sh
KERI_SOURCE=/absolute/path/to/qualified/keripy scripts/check.sh
```

The script builds and installs actual KERIpy and Dolly wheels. The Docker image
contains the copied tests; imports resolve to installed packages, not editable
checkouts. Exact source state and artifact hashes are reported during the build.
