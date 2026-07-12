#!/usr/bin/env bash
# Levanta el proxy, corre estrés y genera gráficos.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

make -s all

SOCKS_PORT="${SOCKS_PORT:-11080}"
MNG_PORT="${MNG_PORT:-18080}"
OUT="${OUT:-scripts/results}"
QUICK="${QUICK:-}"

mkdir -p "$OUT"
rm -f "$OUT"/*.csv "$OUT"/*.png

./bin/server -p "$SOCKS_PORT" -P "$MNG_PORT" -A stresssecret >"$OUT/server.log" 2>&1 &
SERVER_PID=$!
cleanup() {
  kill "$SERVER_PID" 2>/dev/null || true
  wait "$SERVER_PID" 2>/dev/null || true
}
trap cleanup EXIT

sleep 0.5
if ! kill -0 "$SERVER_PID" 2>/dev/null; then
  echo "server failed to start:" >&2
  cat "$OUT/server.log" >&2
  exit 1
fi

ARGS=(--socks-port "$SOCKS_PORT" --out "$OUT")
if [[ -n "$QUICK" ]]; then
  ARGS+=(--quick)
fi
python3 scripts/stress.py "${ARGS[@]}"

if python3 -c "import matplotlib" 2>/dev/null; then
  python3 scripts/plot_results.py
else
  echo "matplotlib no disponible; CSV generados, sin PNG" >&2
fi

./bin/client -P "$MNG_PORT" -A stresssecret get-metrics || true
