#!/usr/bin/env bash
# Start / stop the mock command-and-control consumer.
set -u
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PID="$ROOT/.c2.pid"
LOG="${PRAHARI_C2_LOG:-/tmp/prahari-c2.log}"
PORT="${PRAHARI_C2_PORT:-9200}"

case "${1:-start}" in
  start)
    if [ -f "$PID" ] && kill -0 "$(cat "$PID")" 2>/dev/null; then
      echo "mock C2 already running (pid $(cat "$PID"))"; exit 0
    fi
    cd "$ROOT"
    nohup python3 -m prahari.tools.mock_c2 --port "$PORT" >"$LOG" 2>&1 &
    echo $! > "$PID"
    sleep 2
    echo "mock C2 started (pid $(cat "$PID")) -> http://127.0.0.1:$PORT/events"
    ;;
  stop)
    if [ -f "$PID" ]; then
      kill "$(cat "$PID")" 2>/dev/null && echo "mock C2 stopped"
      rm -f "$PID"
    else
      echo "no pidfile"
    fi
    ;;
  log) cat "$LOG" ;;
  *) echo "usage: $0 {start|stop|log}"; exit 2 ;;
esac
