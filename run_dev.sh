#!/usr/bin/env bash
# Restart the PhishGuard backend on :8000, detached from this shell.
set -euo pipefail
cd "$(dirname "$0")"

PORT="${PORT:-8000}"

# Stop any previous instance. `pkill -f uvicorn` is avoided deliberately: it also
# matches the shell running this script. Resolve the listening PID instead, using
# whichever tool the machine actually has.
stop_existing() {
  local pids=""
  if command -v lsof > /dev/null 2>&1; then
    pids=$(lsof -ti "tcp:${PORT}" 2>/dev/null || true)
  elif command -v fuser > /dev/null 2>&1; then
    pids=$(fuser -n tcp "${PORT}" 2>/dev/null | tr -d ' ' || true)
  else
    pids=$(python3 - "$PORT" <<'PY' 2>/dev/null || true
import os, sys, glob, re
port = int(sys.argv[1])
hexport = f"{port:04X}"
inodes = set()
for proto in ("/proc/net/tcp", "/proc/net/tcp6"):
    try:
        for line in open(proto).readlines()[1:]:
            f = line.split()
            if f[1].split(":")[1] == hexport and f[3] == "0A":
                inodes.add(f[9])
    except OSError:
        pass
out = []
for fd in glob.glob("/proc/[0-9]*/fd/*"):
    try:
        target = os.readlink(fd)
    except OSError:
        continue
    m = re.fullmatch(r"socket:\[(\d+)\]", target)
    if m and m.group(1) in inodes:
        out.append(fd.split("/")[2])
print(" ".join(sorted(set(out))))
PY
)
  fi
  for pid in $pids; do
    [ "$pid" = "$$" ] && continue
    kill "$pid" 2>/dev/null || true
  done
  [ -n "$pids" ] && sleep 1 || true
}
stop_existing

nohup uvicorn backend.main:app --host 127.0.0.1 --port "${PORT}" \
  > /tmp/phishguard-uvicorn.log 2>&1 < /dev/null &

for _ in $(seq 1 25); do
  if curl -sf "http://127.0.0.1:${PORT}/health" > /dev/null 2>&1; then
    echo "PhishGuard backend ready on http://127.0.0.1:${PORT}"
    exit 0
  fi
  sleep 0.4
done

echo "backend failed to start; last log lines:" >&2
tail -20 /tmp/phishguard-uvicorn.log >&2
exit 1
