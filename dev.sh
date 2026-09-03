#!/usr/bin/env bash
#
# Developer helper for the Dockerised scanner.
# Run ./dev.sh with no arguments to see the available commands.

set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")"

SERVICE="api"
PORT="${JUSSIAI_PORT:-8000}"

if docker compose version >/dev/null 2>&1; then
  DC=(docker compose)
elif command -v docker-compose >/dev/null 2>&1; then
  DC=(docker-compose)
else
  echo "error: neither 'docker compose' nor 'docker-compose' is available" >&2
  exit 1
fi

info() { printf '\033[36m==>\033[0m %s\n' "$*"; }
warn() { printf '\033[33m warning:\033[0m %s\n' "$*" >&2; }
die()  { printf '\033[31m error:\033[0m %s\n' "$*" >&2; exit 1; }

require_daemon() {
  docker info >/dev/null 2>&1 || die "the Docker daemon is not reachable. Start Docker Desktop, or: sudo systemctl start docker"
}

# A stray host process on the same port silently shadows the container: requests
# reach the host process and the container looks broken or stale.
check_port_conflict() {
  local pids
  pids="$(ss -tlnp 2>/dev/null | awk -v p=":${PORT}\$" '$4 ~ p {print}' | grep -v docker || true)"
  if [[ -n "$pids" ]]; then
    warn "something other than Docker is already listening on port ${PORT}:"
    printf '%s\n' "$pids" >&2
    warn "requests to localhost:${PORT} may reach that process instead of the container."
    warn "stop it, or run with a different port: JUSSIAI_PORT=8010 ./dev.sh up"
  fi
}

wait_for_health() {
  local id tries=0
  id="$(${DC[@]} ps -q "$SERVICE" 2>/dev/null || true)"
  [[ -n "$id" ]] || return 0
  info "waiting for the health check..."
  while (( tries < 60 )); do
    case "$(docker inspect --format '{{if .State.Health}}{{.State.Health.Status}}{{else}}none{{end}}' "$id" 2>/dev/null)" in
      healthy) info "healthy"; return 0 ;;
      unhealthy) die "container reported unhealthy. See: ./dev.sh logs" ;;
      none) return 0 ;;
    esac
    tries=$((tries + 1))
    sleep 1
  done
  warn "gave up waiting for the health check; see ./dev.sh logs"
}

cmd_up() {
  require_daemon
  check_port_conflict
  info "starting ${SERVICE}"
  "${DC[@]}" up -d --build "$@"
  wait_for_health
  info "API      http://localhost:${PORT}"
  info "test page http://localhost:${PORT}/test-url"
  info "API docs  http://localhost:${PORT}/docs"
}

cmd_down() {
  require_daemon
  info "stopping and removing containers"
  "${DC[@]}" down "$@"
}

cmd_restart() {
  require_daemon
  info "restarting ${SERVICE}"
  "${DC[@]}" restart "$@"
  wait_for_health
}

cmd_build() {
  require_daemon
  info "building the image"
  "${DC[@]}" build "$@"
}

cmd_rebuild() {
  require_daemon
  info "rebuilding from scratch (no cache)"
  "${DC[@]}" build --no-cache "$@"
  cmd_up
}

cmd_logs() {
  require_daemon
  "${DC[@]}" logs -f --tail=100 "${@:-$SERVICE}"
}

cmd_ps() {
  require_daemon
  "${DC[@]}" ps
}

cmd_shell() {
  require_daemon
  info "opening a shell in ${SERVICE} (unprivileged user, read-only filesystem)"
  "${DC[@]}" exec "$SERVICE" /bin/bash 2>/dev/null || "${DC[@]}" exec "$SERVICE" /bin/sh
}

cmd_health() {
  require_daemon
  "${DC[@]}" exec -T "$SERVICE" python -c \
    "import urllib.request;print(urllib.request.urlopen('http://127.0.0.1:8000/health',timeout=5).read().decode())"
}

# Scans through the container rather than the host, so what is exercised is the
# code in the image.
cmd_scan() {
  require_daemon
  [[ $# -ge 1 ]] || die "usage: ./dev.sh scan <url>"
  "${DC[@]}" exec -T "$SERVICE" python - "$1" <<'PY'
import json, sys, urllib.error, urllib.request

req = urllib.request.Request(
    "http://127.0.0.1:8000/scan",
    data=json.dumps({"url": sys.argv[1]}).encode(),
    headers={"Content-Type": "application/json"},
)
try:
    data = json.loads(urllib.request.urlopen(req, timeout=120).read())
except urllib.error.HTTPError as exc:
    print(f"HTTP {exc.code}: {json.loads(exc.read()).get('detail')}")
    raise SystemExit(1)

print(f"{data['final_url']}  ->  HTTP {data['status_code']}  ({data['duration_ms']:.0f} ms)")
print("  " + "  ".join(f"{v} {k}" for k, v in data["counts"].items()))
for note in data["notes"]:
    print(f"  note: {note}")
print()
order = {"high": 0, "medium": 1, "low": 2, "info": 3}
for f in sorted(data["findings"], key=lambda f: order[f["severity"]]):
    print(f"[{f['severity']:6}] {f['title']}")
    if f["remediation"] and f["remediation"] != "No action needed.":
        print(f"          fix: {f['remediation']}")
PY
}

# Runs the test suite inside a throwaway container built with the dev extras, so
# results do not depend on the host having a working local venv.
cmd_test() {
  require_daemon
  info "running the suite in a throwaway container"
  docker run --rm -v "$PWD:/src:ro" -w /src python:3.12-slim-bookworm bash -c '
    python -m venv /tmp/venv &&
    /tmp/venv/bin/pip install -q --upgrade pip &&
    /tmp/venv/bin/pip install -q -e ".[dev]" 2>/dev/null || /tmp/venv/bin/pip install -q ".[dev]";
    /tmp/venv/bin/ruff check . &&
    /tmp/venv/bin/ruff format --check . &&
    /tmp/venv/bin/mypy &&
    /tmp/venv/bin/pytest -q'
}

cmd_clean() {
  require_daemon
  info "removing containers, volumes and the built image"
  "${DC[@]}" down -v --remove-orphans
  docker image rm jussiai-web-security-scanner:local 2>/dev/null || true
}

usage() {
  cat <<'USAGE'
JussiAI Web Security Scanner - Docker helper

  ./dev.sh <command> [args]

Lifecycle
  up          Build if needed, start in the background, wait for healthy
  down        Stop and remove the containers
  restart     Restart the api service
  build       Build the image
  rebuild     Build with --no-cache, then start
  clean       Remove containers, volumes and the built image

Inspect
  ps          Show container status
  logs        Follow the logs (Ctrl-C to stop)
  health      Print /health from inside the container
  shell       Open a shell in the running container

Use
  scan <url>  Scan a URL through the container and print the findings
  test        Run ruff, mypy and pytest in a throwaway container

Environment
  JUSSIAI_PORT   Host port to report in messages (default 8000)
USAGE
}

case "${1:-}" in
  up)       shift; cmd_up "$@" ;;
  down)     shift; cmd_down "$@" ;;
  restart)  shift; cmd_restart "$@" ;;
  build)    shift; cmd_build "$@" ;;
  rebuild)  shift; cmd_rebuild "$@" ;;
  clean)    shift; cmd_clean "$@" ;;
  ps)       shift; cmd_ps "$@" ;;
  logs)     shift; cmd_logs "$@" ;;
  health)   shift; cmd_health "$@" ;;
  shell)    shift; cmd_shell "$@" ;;
  scan)     shift; cmd_scan "$@" ;;
  test)     shift; cmd_test "$@" ;;
  ""|-h|--help|help) usage ;;
  *)        echo "unknown command: $1" >&2; echo >&2; usage; exit 1 ;;
esac
