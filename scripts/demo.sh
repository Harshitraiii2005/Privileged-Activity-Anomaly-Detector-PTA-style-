#!/usr/bin/env bash
# One-command local demo (no Docker): fresh API + dashboard in the background,
# replay a simulated attack through the API, and always stop both on exit.
# Usage: scripts/demo.sh [privguard.demo args...]   (run via `make demo`, which trains first)
set -euo pipefail
cd "$(dirname "$0")/.."

PYTHON=${PYTHON:-.venv/bin/python}
API_PORT=${API_PORT:-8000}
DASH_PORT=${DASH_PORT:-8501}
export PRIVGUARD_DB_PATH=${PRIVGUARD_DB_PATH:-data/demo.db}
export PRIVGUARD_API_URL=http://127.0.0.1:$API_PORT
LOGS=$(dirname "$PRIVGUARD_DB_PATH")

if curl -s -o /dev/null "$PRIVGUARD_API_URL/health"; then
  echo "Port $API_PORT is already serving something (make api?). Stop it or set API_PORT." >&2
  exit 1
fi

mkdir -p "$LOGS"
rm -f "$PRIVGUARD_DB_PATH"
pids=()
cleanup() {
  [ ${#pids[@]} -eq 0 ] || kill "${pids[@]}" 2>/dev/null || true
  wait 2>/dev/null || true
}
trap cleanup EXIT
trap 'exit 130' INT TERM

"$PYTHON" -m uvicorn privguard.api:app --host 127.0.0.1 --port "$API_PORT" --log-level warning \
  >"$LOGS/demo-api.log" 2>&1 &
api_pid=$!
pids+=("$api_pid")
"$PYTHON" -m streamlit run src/privguard/dashboard.py --server.port "$DASH_PORT" --server.headless true \
  --browser.gatherUsageStats false >"$LOGS/demo-dashboard.log" 2>&1 &
pids+=($!)

echo "Starting API on $PRIVGUARD_API_URL (fresh DB: $PRIVGUARD_DB_PATH) ..."
for _ in $(seq 60); do
  curl -sf -o /dev/null "$PRIVGUARD_API_URL/health" && break
  if ! kill -0 "$api_pid" 2>/dev/null; then
    echo "API failed to start; log follows ($LOGS/demo-api.log):" >&2
    cat "$LOGS/demo-api.log" >&2
    exit 1
  fi
  sleep 0.5
done

"$PYTHON" -m privguard.demo --api "$PRIVGUARD_API_URL" --dashboard "http://localhost:$DASH_PORT" "$@"

if [ -t 0 ]; then
  read -r -p "Dashboard is live at http://localhost:$DASH_PORT - press Enter to stop the demo. " || true
fi
