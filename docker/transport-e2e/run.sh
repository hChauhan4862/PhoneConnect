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
    -d "{\"token\":\"$TOKEN\"}")
DEVICE_ID=$(printf '%s' "$ENROLL" | json 'v["device_id"]')
CREDENTIAL=$(printf '%s' "$ENROLL" | json 'v["credential"]')

SESSION=$(curl -fsS -X POST "$BASE/api/sessions" \
    -H "Authorization: Bearer $ADMIN_TOKEN" \
    -H "Content-Type: application/json" \
    -d "{\"device_id\":\"$DEVICE_ID\"}")
SESSION_ID=$(printf '%s' "$SESSION" | json 'v["session_id"]')
CAPABILITY=$(printf '%s' "$SESSION" | json 'v["capability"]')
VERIFICATION_KEY=$(printf '%s' "$SESSION" | json 'v["verification_key"]')
CLIENT_TICKET=$(printf '%s' "$SESSION" | json 'json.dumps(v["ticket"])')

DEVICE_TICKET=$(curl -fsS "$BASE/api/sessions/$SESSION_ID/ticket" \
    -H "Authorization: Bearer $CREDENTIAL" | json 'json.dumps(v["ticket"])')

# Both peers see the relay route plus one direct candidate that nothing listens on, which
# is what a restrictive firewall or symmetric NAT looks like to the probing peer.
CANDIDATES=$(python3 - "$BASE" "$SESSION_ID" "$VERIFICATION_KEY" "$DEAD_CANDIDATE" <<'PY'
import json, sys
base, session_id, verification_key, dead = sys.argv[1:5]
print(json.dumps({
    "session_id": session_id,
    "expires_at": 4102444800000,
    "verification_key": verification_key,
    "candidates": [
        {"kind": "server_observed", "endpoint": dead, "priority": 150},
        {"kind": "relay", "endpoint": f"{base}/api/sessions/{session_id}/relay", "priority": 100},
    ],
}))
PY
)

RELAY_URL="ws://server:8080/api/sessions/$SESSION_ID/relay"
COMMON=(-e "STUB_CANDIDATES=$CANDIDATES" -e "STUB_RELAY_URL=$RELAY_URL" -e "STUB_PAYLOAD=fallback")

echo "starting the Android-side (device) stub"
"${COMPOSE[@]}" run --rm --no-deps -T \
    -e "STUB_ROLE=device" \
    -e "STUB_TARGET=android" \
    -e "STUB_TICKET=$DEVICE_TICKET" \
    -e "STUB_BEARER=$CREDENTIAL" \
    "${COMMON[@]}" device-stub >"$DEVICE_LOG" 2>&1 &
DEVICE_PID=$!

echo "starting the native-side (client) stub"
set +e
"${COMPOSE[@]}" run --rm --no-deps -T \
    -e "STUB_ROLE=client" \
    -e "STUB_TARGET=native" \
    -e "STUB_TICKET=$CLIENT_TICKET" \
    -e "STUB_BEARER=$CAPABILITY" \
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
