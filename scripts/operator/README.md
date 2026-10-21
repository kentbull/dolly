# Installed CLI v1 operator walkthrough

Run the complete script from this repository with Docker available:

```sh
KERI_SOURCE=/absolute/path/to/qualified/keripy \
KERI_IMAGE=keripy-v1-operator:base \
DOLLY_IMAGE=dolly-v1-operator:dev \
DOLLY_OPERATOR_VOLUME=dolly-v1-operator \
bash scripts/operator/run-legacy-v1.sh
```

`KERI_SOURCE` must contain the generic `kli vc registry serve --version 1.0`
command and the scenario infrastructure under `scripts/v2-e2e/scenarios`.
The runner builds copied-source images, installs actual KERIpy and Dolly wheels,
and uses named Linux volumes for `/tmp` and `/usr/local/var`; it uses no host
state bind mounts. Optional `DEBUG_KLI=1` enables CLI tracebacks. Source revisions,
dirty flags, installed package versions and wheel hashes appear in
`/artifacts/manifest.json` and the resulting scenario JSON. A dirty-source run
is development evidence, not qualification of immutable clean pins.

`legacy-v1.sh` visibly runs installed protocol commands: v1 identity and registry
inception, issuance, apply/offer/agree/grant, admit and genuine revocation. Three
independent witness processes serve the issuer and Dolly identities with quorum
two. Dolly serves both recipient and verifier roles in this bounded story; it
is a separate process and store from the issuer. The packaged non-vLEI
`legacy-status-v1` schema requires the disclosed business field `a/status`.
There is no KRAM v1 path or authentication-policy toggle.

One negotiated grant reaches Dolly by HTTP and another by raw TCP. Each must
produce exactly one accepted real webhook with the expected credential,
presenter and `status=authorized`. HTTP 202 and sender transmission output do
not establish acceptance. Public `dolly inspect` confirms delivery. Both admit
files are signed and locally verified; the subsequent issuer command ingests
them through the ordinary Parser. This story does not independently assert a
remote admission acknowledgement. The dedicated core negotiation regression
covers remote linked-admit acceptance separately.

The generic KERIpy evidence source answers normal signed registry queries from
the explicit Dolly reader AID. Signed issuer endpoint replies establish the
source URL; responses go only to the operator-configured fixed Dolly HTTP URL.
The source does not author credentials or supply application decisions. Stop
it before external revocation and restart it afterward to reopen genuine
issuer state; the script makes this ownership/cache policy explicit. After
revocation, another grant must be terminally rejected as `credential is not
currently issued`, with no third hook.

The shared KERIpy `common.sh` supplies process supervision, CLI output checks,
public-result polling, endpoint readiness and cleanup. Its credential setup
functions are not invoked. `json_helpers.py` uses only the standard library to
write config and inspect JSON/public artifacts; it never imports protocol APIs
or writes accepted database rows. Every lifecycle operation remains visible
in Bash.

A failed assertion, CLI error, 45-second command timeout or bounded polling
expiry exits nonzero. The EXIT trap stops and waits for owned child processes
and retains the run directory in the named volume. `result.json` records all
actor AIDs, stream hashes, exact hooks, rejection and manifest. `commands.log`,
per-process logs, `source-issued.log`, public CESR files and inspection JSON
remain available for diagnosis. These volumes contain private test identity
state; ordinary result manifests contain no passcode or registry salt. The
runner generates a fresh passcode in its process environment for each run.
