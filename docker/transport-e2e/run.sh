#!/usr/bin/env bash
# Transport end-to-end fallback test.
#
# Runs one server, a native-side stub, and an Android-side stub in Docker. Both stubs are
# handed a dead direct candidate, so authenticated hole punching cannot succeed and the
# session must continue over the relay: the point of the test is that neither peer notices
# the fallback and frames still cross with their request ids intact.
#
# Requires Docker with the compose plugin and python3 for JSON handling.

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
COMPOSE=(docker compose -f "$ROOT/docker/transport-e2e/compose.yaml")
BASE="http://127.0.0.1:18080"
# Compose interpolates this for every subcommand, so export it once. It is a throwaway
# test-only token for a loopback server that is removed by the cleanup trap.
export PHONECONNECT_ADMIN_TOKEN="${PHONECONNECT_ADMIN_TOKEN:-transport-e2e-admin-token}"
ADMIN_TOKEN="$PHONECONNECT_ADMIN_TOKEN"
LOG_DIR="$ROOT/target/transport-e2e"
DEAD_CANDIDATE="127.0.0.1:9"

mkdir -p "$LOG_DIR"
DEVICE_LOG="$LOG_DIR/device-stub.log"
CLIENT_LOG="$LOG_DIR/client-stub.log"

cleanup() {
    "${COMPOSE[@]}" down --volumes --remove-orphans >/dev/null 2>&1 || true
}
trap cleanup EXIT

json() {
    python3 -c "import json,sys; value=json.load(sys.stdin); print(eval(sys.argv[1], {'v': value, 'json': json}))" "$1"
}

echo "building the server and stub images"
"${COMPOSE[@]}" build server client-stub >/dev/null

echo "generating the pinned identity keys for both stubs"
CLIENT_IDENTITY=$(docker run --rm phoneconnect-path-stub:dev --generate-identity)
DEVICE_IDENTITY=$(docker run --rm phoneconnect-path-stub:dev --generate-identity)
CLIENT_SECRET=$(printf '%s' "$CLIENT_IDENTITY" | sed -n 1p)
CLIENT_PUBLIC=$(printf '%s' "$CLIENT_IDENTITY" | sed -n 2p)
DEVICE_SECRET=$(printf '%s' "$DEVICE_IDENTITY" | sed -n 1p)
DEVICE_PUBLIC=$(printf '%s' "$DEVICE_IDENTITY" | sed -n 2p)

echo "starting the server"
"${COMPOSE[@]}" up -d --wait server >/dev/null

for _ in $(seq 1 30); do
    if curl -fsS "$BASE/health" >/dev/null 2>&1; then
        break
    fi
    sleep 1
done

TOKEN=$(curl -fsS -X POST "$BASE/api/enrollment-tokens" \
    -H "Authorization: Bearer $ADMIN_TOKEN" \
    -H "Content-Type: application/json" \
    -d '{"owner_id":"docker-e2e","expires_in_seconds":900}' | json 'v["token"]')

ENROLL=$(curl -fsS -X POST "$BASE/api/devices/enroll" \
    -H "Content-Type: application/json" \
    -d "{\"token\":\"$TOKEN\",\"identity_key\":\"$DEVICE_PUBLIC\"}")
DEVICE_ID=$(printf '%s' "$ENROLL" | json 'v["device_id"]')
CREDENTIAL=$(printf '%s' "$ENROLL" | json 'v["credential"]')

# The relay refuses a client's control frame on a read-only session, and this test proves a
# control frame crosses processes. Grant the owner control, then create a control session so
# the stub's CONTROL frames are authorized end to end.
curl -fsS -X POST "$BASE/api/devices/$DEVICE_ID/lease" \
    -H "Authorization: Bearer $ADMIN_TOKEN" \
    -H "Content-Type: application/json" \
    -d '{"actor_id":"docker-e2e","expires_in_seconds":900}' >/dev/null

SESSION=$(curl -fsS -X POST "$BASE/api/sessions" \
    -H "Authorization: Bearer $ADMIN_TOKEN" \
    -H "Content-Type: application/json" \
    -d "{\"device_id\":\"$DEVICE_ID\",\"client_identity_key\":\"$CLIENT_PUBLIC\",\"control\":true,\"user_id\":\"docker-e2e\"}")
SESSION_ID=$(printf '%s' "$SESSION" | json 'v["session_id"]')
CAPABILITY=$(printf '%s' "$SESSION" | json 'v["capability"]')
VERIFICATION_KEY=$(printf '%s' "$SESSION" | json 'v["verification_key"]')
CLIENT_TICKET=$(printf '%s' "$SESSION" | json 'json.dumps(v["ticket"])')

DEVICE_TICKET=$(curl -fsS "$BASE/api/sessions/$SESSION_ID/ticket" \
    -H "Authorization: Bearer $CREDENTIAL" | json 'json.dumps(v["ticket"])')

# Candidate exchange goes through the real rendezvous route: each peer registers the
# endpoint it observed for itself, redeeming its ticket, and receives the peer's view. The
# registered address is a dead port on purpose, so direct negotiation must fail and the
# session must continue over the relay.
register_candidate() {
    curl -fsS -X POST "$BASE/api/sessions/$SESSION_ID/candidates" \
        -H "Authorization: Bearer $1" \
        -H "Content-Type: application/json" \
        -d "{\"ticket\":$2,\"endpoint\":\"$DEAD_CANDIDATE\"}"
}

register_candidate "$CAPABILITY" "$CLIENT_TICKET" >/dev/null
register_candidate "$CREDENTIAL" "$DEVICE_TICKET" >/dev/null

# Re-read both views once each peer has registered: the response to the first registration
# cannot contain the other peer's nonce yet, and the nonce pair is the connection epoch both
# stubs need before they can derive the same traffic keys.
CLIENT_CANDIDATES=$(curl -fsS "$BASE/api/sessions/$SESSION_ID/candidates" \
    -H "Authorization: Bearer $CAPABILITY")
DEVICE_CANDIDATES=$(curl -fsS "$BASE/api/sessions/$SESSION_ID/candidates" \
    -H "Authorization: Bearer $CREDENTIAL")

ensure_peer_nonce() {
    printf '%s' "$1" | grep -q '"peer_nonce"' || {
        echo "rendezvous did not exchange the peer nonce" >&2
        exit 1
    }
}
ensure_peer_nonce "$CLIENT_CANDIDATES"
ensure_peer_nonce "$DEVICE_CANDIDATES"

RELAY_URL="ws://server:8080/api/sessions/$SESSION_ID/relay"
COMMON=(-e "STUB_RELAY_URL=$RELAY_URL" -e "STUB_PAYLOAD=fallback")

echo "starting the Android-side (device) stub"
"${COMPOSE[@]}" run --rm --no-deps -T \
    -e "STUB_ROLE=device" \
    -e "STUB_TARGET=android" \
    -e "STUB_TICKET=$DEVICE_TICKET" \
    -e "STUB_BEARER=$CREDENTIAL" \
    -e "STUB_IDENTITY_KEY=$DEVICE_SECRET" \
    -e "STUB_CANDIDATES=$DEVICE_CANDIDATES" \
    "${COMMON[@]}" device-stub >"$DEVICE_LOG" 2>&1 &
DEVICE_PID=$!

echo "starting the native-side (client) stub"
set +e
"${COMPOSE[@]}" run --rm --no-deps -T \
    -e "STUB_ROLE=client" \
    -e "STUB_TARGET=native" \
    -e "STUB_TICKET=$CLIENT_TICKET" \
    -e "STUB_BEARER=$CAPABILITY" \
    -e "STUB_IDENTITY_KEY=$CLIENT_SECRET" \
    -e "STUB_CANDIDATES=$CLIENT_CANDIDATES" \
    "${COMMON[@]}" native-stub >"$CLIENT_LOG" 2>&1
CLIENT_STATUS=$?
wait "$DEVICE_PID"
DEVICE_STATUS=$?
set -e

echo "--- native-side stub ---"
cat "$CLIENT_LOG"
echo "--- Android-side stub ---"
cat "$DEVICE_LOG"

failures=0
if [ "$CLIENT_STATUS" -ne 0 ]; then
    echo "native-side stub exited $CLIENT_STATUS" >&2
    failures=1
fi
if [ "$DEVICE_STATUS" -ne 0 ]; then
    echo "Android-side stub exited $DEVICE_STATUS" >&2
    failures=1
fi
if ! grep -q "PATH=relay" "$CLIENT_LOG"; then
    echo "native-side stub did not report the relay fallback" >&2
    failures=1
fi
if ! grep -q "PATH=relay" "$DEVICE_LOG"; then
    echo "Android-side stub did not report the relay fallback" >&2
    failures=1
fi
if ! grep -q "RECEIVED=req-docker-e2e PAYLOAD=native:fallback" "$DEVICE_LOG"; then
    echo "the Android-side stub did not receive the native frame intact" >&2
    failures=1
fi
if ! grep -q "RECEIVED=req-docker-e2e-reply PAYLOAD=android:echo" "$CLIENT_LOG"; then
    echo "the native-side stub did not receive the reply intact" >&2
    failures=1
fi

if [ "$failures" -ne 0 ]; then
    echo "transport end-to-end fallback test FAILED" >&2
    exit 1
fi
echo "transport end-to-end fallback test passed: both peers stayed on the relay and frames crossed intact"
