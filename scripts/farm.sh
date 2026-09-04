#!/usr/bin/env bash
# Start / stop the simulated DVR farm with a pidfile.
set -u
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PID="$ROOT/.farm.pid"
LOG="${PRAHARI_FARM_LOG:-/tmp/prahari-farm.log}"

case "${1:-start}" in
  start)
    if [ -f "$PID" ] && kill -0 "$(cat "$PID")" 2>/dev/null; then
      echo "farm already running (pid $(cat "$PID"))"; exit 0
    fi
    cd "$ROOT"
    nohup python3 -m prahari.sim.farm >"$LOG" 2>&1 &
    echo $! > "$PID"
    sleep "${2:-6}"
    if kill -0 "$(cat "$PID")" 2>/dev/null; then
      echo "farm started (pid $(cat "$PID")), log: $LOG"
    else
      echo "farm failed to start:"; cat "$LOG"; exit 1
    fi
    ;;
  stop)
    if [ -f "$PID" ]; then
      kill "$(cat "$PID")" 2>/dev/null && echo "farm stopped"
      rm -f "$PID"
    else
      echo "no pidfile"
    fi
    ;;
  restart)
    "$0" stop; sleep 1; "$0" start "${2:-6}"
    ;;
  log)
    tail -n "${2:-40}" "$LOG"
    ;;
  *)
    echo "usage: $0 {start|stop|restart|log}"; exit 2
    ;;
esac
