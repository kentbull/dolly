#!/usr/bin/env bash
# Real v1 CLI issuance, negotiation, admission, source-observed reporting/revocation.
set -Eeuo pipefail
export PYTHONUNBUFFERED=1
source /workspace/scripts/v2-e2e/scenarios/common.sh
RUN_DIR=$(mktemp -d /tmp/dolly-legacy-v1.XXXXXXXX)
STORE_BASE="legacy-${RUN_DIR##*/}"
export KLI_KEYSTORE_PASSCODE
KLI_KEYSTORE_PASSCODE=$(kli passcode generate)
trap cleanup EXIT
kli version > "$RUN_DIR/kli-version.txt"
ROLES=(witness1 witness2 witness3 issuer dolly)
python "$JSON" ports "${ROLES[@]}" witness1tcp witness2tcp witness3tcp dollytcp hook source > "$RUN_DIR/ports.json"
for ROLE in "${ROLES[@]}" witness1tcp witness2tcp witness3tcp dollytcp hook source; do PORTS[$ROLE]=$(value "$RUN_DIR/ports.json" "$ROLE"); done
for ROLE in "${ROLES[@]}"; do NAMES[$ROLE]="${RUN_DIR##*/}-$ROLE"; done
printf '{"transferable":false,"wits":[],"toad":0,"icount":1,"isith":"1","ncount":0,"nsith":"0"}\n' > "$RUN_DIR/witness.json"
printf '{"transferable":true,"wits":[],"toad":0,"icount":1,"isith":"1","ncount":1,"nsith":"1"}\n' > "$RUN_DIR/plain.json"
: > "$RUN_DIR/witnesses.cesr"
for ROLE in witness1 witness2 witness3; do
    k "$ROLE" init --version 1.0
    k "$ROLE" incept -a "$ROLE" --version 1.0 --file "$RUN_DIR/witness.json"
    AIDS[$ROLE]=$(kli aid --name "${NAMES[$ROLE]}" --base "$STORE_BASE" -a "$ROLE")
    k "$ROLE" location add -a "$ROLE" --version 1.0 --url "http://127.0.0.1:${PORTS[$ROLE]}/"
    k "$ROLE" ends add -a "$ROLE" --version 1.0 --role controller --eid "${AIDS[$ROLE]}"
    k "$ROLE" kel export -a "$ROLE" --version 1.0 --ends --output "$RUN_DIR/$ROLE.cesr"
    cat "$RUN_DIR/$ROLE.cesr" >> "$RUN_DIR/witnesses.cesr"
    spawn "$ROLE" kli witness start --name "${NAMES[$ROLE]}" --base "$STORE_BASE" -a "$ROLE" --no-prompt -H "${PORTS[$ROLE]}" -T "${PORTS[${ROLE}tcp]}"
    python "$JSON" ready "http://127.0.0.1:${PORTS[$ROLE]}/oobi" 15
done
for ROLE in issuer dolly; do
    k "$ROLE" init --version 1.0
    k "$ROLE" kel import --version 1.0 --file "$RUN_DIR/witnesses.cesr"
    k "$ROLE" incept -a "$ROLE" --version 1.0 --file "$RUN_DIR/plain.json" --receipt-endpoint \
        --wits "${AIDS[witness1]}" --wits "${AIDS[witness2]}" --wits "${AIDS[witness3]}" --toad 2
    AIDS[$ROLE]=$(kli aid --name "${NAMES[$ROLE]}" --base "$STORE_BASE" -a "$ROLE")
    k "$ROLE" kel export -a "$ROLE" --version 1.0 --output "$RUN_DIR/$ROLE-initial.cesr"
done
for ROLE in "${ROLES[@]}"; do printf '%s\n' "${AIDS[$ROLE]}" > "$RUN_DIR/$ROLE.aid"; done
k issuer kel import --version 1.0 --file "$RUN_DIR/dolly-initial.cesr"
k dolly kel import --version 1.0 --file "$RUN_DIR/issuer-initial.cesr"
SCHEMA_FILE=/dolly/src/dolly/schemas/legacy-status-v1.json
SCHEMA=$(value "$SCHEMA_FILE" '$id')
k issuer vc schema import_ --schema "$SCHEMA_FILE"
k issuer vc registry incept -a issuer -r legacy
k issuer vc create -a issuer -r legacy --schema "$SCHEMA" --recipient "${AIDS[dolly]}" --data '{"status":"authorized"}'
k issuer vc list -a issuer --issued --said > "$RUN_DIR/credential.ref"
CREDENTIAL=$(tail -1 "$RUN_DIR/credential.ref")
[[ $CREDENTIAL == E* && ${#CREDENTIAL} == 44 ]]
# Authentic controller endpoints allow conventional Dolly queries to the issuer.
SOURCE_URL="http://127.0.0.1:${PORTS[source]}/"
DOLLY_URL="http://127.0.0.1:${PORTS[dolly]}/ingest"
k issuer location add -a issuer --version 1.0 --url "$SOURCE_URL"
k issuer ends add -a issuer --version 1.0 --role controller --eid "${AIDS[issuer]}"
k issuer kel export -a issuer --version 1.0 --ends --output "$RUN_DIR/issuer-endpoints.cesr"
k dolly kel import --version 1.0 --file "$RUN_DIR/issuer-endpoints.cesr"
k issuer kel export -a issuer --version 1.0 --output "$RUN_DIR/issuer-current.cesr"
python /dolly/scripts/operator/json_helpers.py config "$RUN_DIR/policy.json" "${AIDS[issuer]}" "$SCHEMA" "$SOURCE_URL" "http://127.0.0.1:${PORTS[hook]}/hook"
spawn hook python -u "$JSON" hook "${PORTS[hook]}" "$RUN_DIR/hooks.jsonl"
python "$JSON" ready "http://127.0.0.1:${PORTS[hook]}/" 15
spawn dolly dolly server start --direct --name "${NAMES[dolly]}" --base "$STORE_BASE" -a dolly --no-prompt \
    --config "$RUN_DIR/policy.json" --packaged-schema legacy-status-v1 --kel-genus 1 \
    --kel "$RUN_DIR/issuer-current.cesr" --http "${PORTS[dolly]}" --tcp "${PORTS[dollytcp]}"
python "$JSON" ready "http://127.0.0.1:${PORTS[dolly]}/health" 15
spawn source kli vc registry serve --version 1.0 --name "${NAMES[issuer]}" --base "$STORE_BASE" -a issuer -r legacy \
    --reader "${AIDS[dolly]}" --reply-to "$DOLLY_URL" --port "${PORTS[source]}" --no-prompt
python "$JSON" ready "${SOURCE_URL}health" 15

# First complete negotiated grant over HTTP; only delivered hook proves reporting.
k dolly ipex apply -a dolly -r "${AIDS[issuer]}" --schema "$SCHEMA" --attributes '{"status":"authorized"}' --output "$RUN_DIR/apply-http.cesr"
APPLY_HTTP=$(value "$RUN_DIR/latest-dolly.jsonl" exchange)
k issuer ipex offer -a issuer -r "${AIDS[dolly]}" -s "$CREDENTIAL" --prior "$APPLY_HTTP" --input "$RUN_DIR/apply-http.cesr" --output "$RUN_DIR/offer-http.cesr"
OFFER_HTTP=$(value "$RUN_DIR/latest-issuer.jsonl" exchange)
k dolly ipex agree -a dolly -s "$OFFER_HTTP" --input "$RUN_DIR/offer-http.cesr" --output "$RUN_DIR/agree-http.cesr"
AGREE_HTTP=$(value "$RUN_DIR/latest-dolly.jsonl" exchange)
k issuer ipex grant -a issuer -r "${AIDS[dolly]}" -s "$CREDENTIAL" --prior "$AGREE_HTTP" --input "$RUN_DIR/agree-http.cesr" --endpoint "$DOLLY_URL" --output "$RUN_DIR/grant-http.cesr"
GRANT_HTTP=$(value "$RUN_DIR/latest-issuer.jsonl" exchange)
poll delivered "$GRANT_HTTP"
python /dolly/scripts/operator/json_helpers.py hooks "$RUN_DIR/hooks.jsonl" 1 "$CREDENTIAL" "${AIDS[issuer]}"
k dolly ipex admit -a dolly -s "$GRANT_HTTP" --output "$RUN_DIR/admit-http.cesr"

# Admission files are signed/locally verified. Subsequent issuer input uses
# the ordinary Parser; remote acceptance is not independently asserted here.
# A second independent negotiation exercises raw TCP to the same verifier.
k dolly ipex apply -a dolly -r "${AIDS[issuer]}" --schema "$SCHEMA" --output "$RUN_DIR/apply-tcp.cesr"
APPLY_TCP=$(value "$RUN_DIR/latest-dolly.jsonl" exchange)
cat "$RUN_DIR/admit-http.cesr" "$RUN_DIR/apply-tcp.cesr" > "$RUN_DIR/admit-and-apply.cesr"
k issuer ipex offer -a issuer -r "${AIDS[dolly]}" -s "$CREDENTIAL" --prior "$APPLY_TCP" --input "$RUN_DIR/admit-and-apply.cesr" --output "$RUN_DIR/offer-tcp.cesr"
OFFER_TCP=$(value "$RUN_DIR/latest-issuer.jsonl" exchange)
k dolly ipex agree -a dolly -s "$OFFER_TCP" --input "$RUN_DIR/offer-tcp.cesr" --output "$RUN_DIR/agree-tcp.cesr"
AGREE_TCP=$(value "$RUN_DIR/latest-dolly.jsonl" exchange)
k issuer ipex grant -a issuer -r "${AIDS[dolly]}" -s "$CREDENTIAL" --prior "$AGREE_TCP" --input "$RUN_DIR/agree-tcp.cesr" --endpoint "tcp://127.0.0.1:${PORTS[dollytcp]}" --output "$RUN_DIR/grant-tcp.cesr"
GRANT_TCP=$(value "$RUN_DIR/latest-issuer.jsonl" exchange)
poll delivered "$GRANT_TCP"
python /dolly/scripts/operator/json_helpers.py hooks "$RUN_DIR/hooks.jsonl" 2 "$CREDENTIAL" "${AIDS[issuer]}"
k dolly ipex admit -a dolly -s "$GRANT_TCP" --output "$RUN_DIR/admit-tcp.cesr"
# Public source is explicitly restarted after external genuine authoring.
stop source
mv "$RUN_DIR/source.log" "$RUN_DIR/source-issued.log"
k issuer vc revoke -a issuer -r legacy --said "$CREDENTIAL"
spawn source kli vc registry serve --version 1.0 --name "${NAMES[issuer]}" --base "$STORE_BASE" -a issuer -r legacy \
    --reader "${AIDS[dolly]}" --reply-to "$DOLLY_URL" --port "${PORTS[source]}" --no-prompt
python "$JSON" ready "${SOURCE_URL}health" 15
k issuer ipex grant -a issuer -r "${AIDS[dolly]}" -s "$CREDENTIAL" --input "$RUN_DIR/admit-tcp.cesr" --endpoint "$DOLLY_URL" --output "$RUN_DIR/grant-revoked.cesr"
REVOKED=$(value "$RUN_DIR/latest-issuer.jsonl" exchange)
# Inspect terminal application refusal through the public operator CLI.
for ATTEMPT in {1..60}; do
    dolly inspect --name "${NAMES[dolly]}" --base "$STORE_BASE" --grant "$REVOKED" --no-prompt > "$RUN_DIR/revoked.json"
    [[ $(value "$RUN_DIR/revoked.json" state) == rejected ]] && break
    sleep 0.2
done
assert_json "$RUN_DIR/revoked.json" state '"rejected"'
assert_json "$RUN_DIR/revoked.json" delivered false
assert_json "$RUN_DIR/revoked.json" reason '"credential is not currently issued"'
python /dolly/scripts/operator/json_helpers.py hooks "$RUN_DIR/hooks.jsonl" 2 "$CREDENTIAL" "${AIDS[issuer]}"
python /dolly/scripts/operator/json_helpers.py result "$RUN_DIR" "$CREDENTIAL" "$SCHEMA" "$GRANT_HTTP" "$GRANT_TCP" "$REVOKED" "${AIDS[issuer]}" "${AIDS[dolly]}"
cat "$RUN_DIR/result.json"
