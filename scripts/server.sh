#!/usr/bin/env bash
# Start / stop the Prahari control plane with a pidfile.
set -u
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PID="$ROOT/.server.pid"
LOG="${PRAHARI_SERVER_LOG:-/tmp/prahari-server.log}"

case "${1:-start}" in
  start)
    if [ -f "$PID" ] && kill -0 "$(cat "$PID")" 2>/dev/null; then
      echo "server already running (pid $(cat "$PID"))"; exit 0
    fi
    cd "$ROOT"
    nohup python3 -m uvicorn prahari.server.app:app \
      --host 127.0.0.1 --port 8000 --log-level warning >"$LOG" 2>&1 &
    echo $! > "$PID"
    sleep "${2:-6}"
    if kill -0 "$(cat "$PID")" 2>/dev/null; then
      echo "server started (pid $(cat "$PID")) -> http://127.0.0.1:8000"
    else
      echo "server failed to start:"; cat "$LOG"; exit 1
    fi
    ;;
  stop)
    if [ -f "$PID" ]; then
      kill "$(cat "$PID")" 2>/dev/null && echo "server stopped"
      rm -f "$PID"
    else
      echo "no pidfile"
    fi
    ;;
  restart) "$0" stop; sleep 1; "$0" start "${2:-6}" ;;
  log) tail -n "${2:-40}" "$LOG" ;;
  *) echo "usage: $0 {start|stop|restart|log}"; exit 2 ;;
esac
