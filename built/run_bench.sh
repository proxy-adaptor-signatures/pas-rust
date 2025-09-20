#!/usr/bin/env bash
set -euo pipefail

# Usage:
#   ./run_bench.sh [-i ITERS] [-s SERVER] [-m MESSAGE_HEX] t1,n1 [t2,n2 ...]
# Defaults:
#   ITERS=64
#   SERVER=http://127.0.0.1:8000
#   MESSAGE_HEX=bytes_hex:4d6573736167653a2050524f58595f45584348414e47455f44454d4f

ITERS=32
SERVER="http://127.0.0.1:8000"
MESSAGE_HEX="bytes_hex:4d6573736167653a2050524f58595f45584348414e47455f44454d4f"

while getopts ":i:s:m:" opt; do
  case ${opt} in
    i) ITERS=${OPTARG} ;;
    s) SERVER=${OPTARG} ;;
    m) MESSAGE_HEX=${OPTARG} ;;
    *) echo "Usage: $0 [-i iters] [-s server] [-m message_hex] t1,n1 [t2,n2 ...]" >&2; exit 1 ;;
  esac
done
shift $((OPTIND-1))

if [[ $# -lt 1 ]]; then
  echo "Usage: $0 [-i iters] [-s server] [-m message_hex] t1,n1 [t2,n2 ...]" >&2
  exit 1
fi

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
REPO_ROOT="$SCRIPT_DIR"

BENCH_DIR="$REPO_ROOT/benchmarks"
SPARKLE_TEST_BIN="$REPO_ROOT/sparkle_test"
LUBAN_BIN="$REPO_ROOT/luban_manager"
LUBAN_DB="$REPO_ROOT/luban.db"

mkdir -p "$BENCH_DIR"

if [[ ! -x "$SPARKLE_TEST_BIN" ]]; then
  if [[ -x "$REPO_ROOT/target/release/sparkle_test" ]]; then
    SPARKLE_TEST_BIN="$REPO_ROOT/target/release/sparkle_test"
  else
    echo "sparkle_test binary not found at $SPARKLE_TEST_BIN or target/release. Build first." >&2
    exit 1
  fi
fi

if [[ ! -x "$LUBAN_BIN" ]]; then
  if [[ -x "$REPO_ROOT/target/release/luban_manager" ]]; then
    LUBAN_BIN="$REPO_ROOT/target/release/luban_manager"
  else
    echo "luban_manager binary not found at $LUBAN_BIN or target/release. Build first." >&2
    exit 1
  fi
fi

# Clean state and start Luban manager
rm -f "$LUBAN_DB"
LOG_STAMP=$(date +%Y%m%d_%H%M%S)
LUBAN_LOG="$BENCH_DIR/luban_$LOG_STAMP.log"
(
  cd "$REPO_ROOT" 2>/dev/null || cd "$REPO_ROOT"
  "$LUBAN_BIN" >"$LUBAN_LOG" 2>&1 &
  echo $! >"$BENCH_DIR/luban.pid"
)
LUBAN_PID=$(cat "$BENCH_DIR/luban.pid")

cleanup() {
  if kill -0 "$LUBAN_PID" >/dev/null 2>&1; then
    kill "$LUBAN_PID" >/dev/null 2>&1 || true
    wait "$LUBAN_PID" >/dev/null 2>&1 || true
  fi
  rm -f "$BENCH_DIR/luban.pid"
}
trap cleanup EXIT

# Give manager a moment to start
sleep 1.5

# Run benchmarks for each t,n pair
for pair in "$@"; do
  if [[ "$pair" != *","* ]]; then
    echo "Invalid config '$pair'. Expected format t,n (e.g., 2,3)." >&2
    exit 1
  fi
  T=${pair%,*}
  N=${pair#*,}
  if ! [[ "$T" =~ ^[0-9]+$ && "$N" =~ ^[0-9]+$ ]]; then
    echo "Invalid numeric values in '$pair'." >&2
    exit 1
  fi

  OUT_CSV="$BENCH_DIR/bench_t${T}_n${N}_$(date +%Y%m%d_%H%M%S).csv"
  echo "Running Bench for t=$T n=$N (iters=$ITERS) -> $OUT_CSV"

  "$SPARKLE_TEST_BIN" bench \
    --server "$SERVER" \
    --t "$T" \
    --n "$N" \
    --iters "$ITERS" \
    --message "$MESSAGE_HEX" \
    --out "$OUT_CSV"
done

echo "All benchmarks complete. Outputs in $BENCH_DIR"


