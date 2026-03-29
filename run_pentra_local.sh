#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LOG_DIR="${PENTRA_LOCAL_LOG_DIR:-$ROOT_DIR/.local/pentra}"
PID_DIR="$LOG_DIR/pids"

API_PORT="${PENTRA_API_PORT:-8000}"
ORCHESTRATOR_PORT="${PENTRA_ORCHESTRATOR_PORT:-8001}"
FRONTEND_PORT="${PENTRA_FRONTEND_PORT:-3006}"
DEMO_PORT="${PENTRA_PHASE3_DEMO_PORT:-8088}"
POSTGRES_PORT="${PENTRA_POSTGRES_PORT:-5433}"
REDIS_PORT="${PENTRA_REDIS_PORT:-6379}"

ALLOWED_ORIGINS="${ALLOWED_ORIGINS:-[\"http://localhost:${FRONTEND_PORT}\",\"http://127.0.0.1:${FRONTEND_PORT}\"]}"
WORKER_LIVE_TOOLS="${WORKER_LIVE_TOOLS:-scope_check,amass,nmap_discovery,httpx_probe,ffuf,nuclei,sqlmap,sqlmap_verify,custom_poc,web_interact,dalfox,graphql_cop,cors_scanner}"
WORKER_FAMILIES=(recon network web vuln exploit)

mkdir -p "$LOG_DIR" "$PID_DIR"

compose_cmd() {
  if command -v docker >/dev/null 2>&1 && docker compose version >/dev/null 2>&1; then
    docker compose -f "$ROOT_DIR/docker-compose.local.yml" "$@"
    return
  fi

  if command -v docker-compose >/dev/null 2>&1; then
    docker-compose -f "$ROOT_DIR/docker-compose.local.yml" "$@"
    return
  fi

  echo "Docker Compose is required to run the local Pentra stack." >&2
  exit 1
}

require_cmd() {
  local cmd="$1"
  local hint="$2"
  if ! command -v "$cmd" >/dev/null 2>&1; then
    echo "$hint" >&2
    exit 1
  fi
}

is_port_listening() {
  local port="$1"
  ss -ltn "( sport = :$port )" 2>/dev/null | grep -q LISTEN
}

worker_health_port() {
  case "$1" in
    recon) echo "9101" ;;
    network) echo "9102" ;;
    web) echo "9103" ;;
    vuln) echo "9104" ;;
    exploit) echo "9105" ;;
    *) echo "9199" ;;
  esac
}

spawn_detached() {
  if command -v setsid >/dev/null 2>&1; then
    setsid "$@" </dev/null &
    return
  fi

  nohup "$@" </dev/null &
}

wait_for_port() {
  local port="$1"
  local label="$2"
  local attempts="${3:-60}"

  for _ in $(seq 1 "$attempts"); do
    if is_port_listening "$port"; then
      return 0
    fi
    sleep 1
  done

  echo "$label did not start on port $port in time." >&2
  return 1
}

wait_for_container_health() {
  local container="$1"
  local label="$2"
  local attempts="${3:-60}"

  for _ in $(seq 1 "$attempts"); do
    local status
    status="$(docker inspect --format '{{if .State.Health}}{{.State.Health.Status}}{{else}}{{.State.Status}}{{end}}' "$container" 2>/dev/null || true)"
    if [[ "$status" == "healthy" || "$status" == "running" ]]; then
      return 0
    fi
    sleep 1
  done

  echo "$label container did not become healthy." >&2
  return 1
}

container_exists() {
  local container="$1"
  docker inspect "$container" >/dev/null 2>&1
}

ensure_named_container_running() {
  local container="$1"
  local label="$2"

  if ! container_exists "$container"; then
    return 1
  fi

  local status
  status="$(docker inspect --format '{{.State.Status}}' "$container" 2>/dev/null || true)"
  if [[ "$status" != "running" ]]; then
    echo "[infra] Reusing existing $label container: $container"
    docker start "$container" >/dev/null
  else
    echo "[infra] $label container already running: $container"
  fi

  return 0
}

start_port_process() {
  local name="$1"
  local port="$2"
  shift 2

  if is_port_listening "$port"; then
    echo "[skip] $name already listening on :$port"
    return 0
  fi

  local log_file="$LOG_DIR/${name}.log"
  echo "[start] $name -> $log_file"
  spawn_detached "$@" >"$log_file" 2>&1
  local pid=$!
  echo "$pid" >"$PID_DIR/${name}.pid"

  for _ in $(seq 1 60); do
    if is_port_listening "$port"; then
      echo "[ok] $name listening on :$port"
      return 0
    fi
    if ! kill -0 "$pid" 2>/dev/null; then
      echo "[error] $name exited early. Last log lines:" >&2
      tail -n 40 "$log_file" >&2 || true
      return 1
    fi
    sleep 1
  done

  echo "[error] $name did not open port :$port in time. Last log lines:" >&2
  tail -n 40 "$log_file" >&2 || true
  return 1
}

start_background_process() {
  local name="$1"
  shift

  local pid_file="$PID_DIR/${name}.pid"
  if [[ -f "$pid_file" ]]; then
    local existing_pid
    existing_pid="$(cat "$pid_file" 2>/dev/null || true)"
    if [[ -n "$existing_pid" ]] && kill -0 "$existing_pid" 2>/dev/null; then
      echo "[skip] $name already running (pid $existing_pid)"
      return 0
    fi
  fi

  local log_file="$LOG_DIR/${name}.log"
  echo "[start] $name -> $log_file"
  spawn_detached "$@" >"$log_file" 2>&1
  local pid=$!
  echo "$pid" >"$pid_file"
  sleep 2

  if ! kill -0 "$pid" 2>/dev/null; then
    echo "[error] $name exited early. Last log lines:" >&2
    tail -n 40 "$log_file" >&2 || true
    return 1
  fi

  echo "[ok] $name running (pid $pid)"
}

stop_pid_file_process() {
  local name="$1"
  local pid_file="$PID_DIR/${name}.pid"

  if [[ ! -f "$pid_file" ]]; then
    return 0
  fi

  local pid
  pid="$(cat "$pid_file" 2>/dev/null || true)"
  if [[ -n "$pid" ]] && kill -0 "$pid" 2>/dev/null; then
    echo "[stop] $name (pid $pid)"
    kill "$pid" 2>/dev/null || true
  fi
  rm -f "$pid_file"
}

ensure_backend_env() {
  if [[ ! -x "$ROOT_DIR/.venv-phase0/bin/python" ]]; then
    echo "[setup] Bootstrapping backend virtualenv"
    "$ROOT_DIR/pentra_core/scripts/local/bootstrap_backend_env.sh"
  fi
}

run_validation_suites() {
  ensure_backend_env
  "$ROOT_DIR/pentra_core/scripts/local/run_backend_validations.sh"
}

# ── Startup config validation ────────────────────────────────────────

validate_config() {
  local errors=0

  echo "[validate] Checking startup configuration"

  # Check required tools
  for cmd in docker python3 pnpm ss; do
    if ! command -v "$cmd" >/dev/null 2>&1; then
      echo "[error] Required tool '$cmd' is not installed." >&2
      errors=$((errors + 1))
    fi
  done

  # Check Docker Compose availability
  if command -v docker >/dev/null 2>&1; then
    if ! docker compose version >/dev/null 2>&1 && ! command -v docker-compose >/dev/null 2>&1; then
      echo "[error] Docker Compose is required but neither 'docker compose' nor 'docker-compose' is available." >&2
      errors=$((errors + 1))
    fi
  fi

  # Check port conflicts
  local all_ports=("$API_PORT" "$ORCHESTRATOR_PORT" "$FRONTEND_PORT" "$DEMO_PORT")
  local port_names=("API" "Orchestrator" "Frontend" "Demo Target")
  for i in "${!all_ports[@]}"; do
    local port="${all_ports[$i]}"
    local name="${port_names[$i]}"
    if is_port_listening "$port"; then
      # Only warn if it's not one of our own managed services
      local pid_name
      case "$name" in
        API) pid_name="api" ;;
        Orchestrator) pid_name="orchestrator" ;;
        Frontend) pid_name="frontend" ;;
        "Demo Target") pid_name="demo-target" ;;
      esac
      local pid_file="$PID_DIR/${pid_name}.pid"
      if [[ -f "$pid_file" ]] && kill -0 "$(cat "$pid_file" 2>/dev/null || true)" 2>/dev/null; then
        : # Our own process — fine
      else
        echo "[warn] Port :$port ($name) is already in use by another process." >&2
        echo "        Run 'lsof -i :$port' to identify it, or use PENTRA_${pid_name^^}_PORT to change the port." >&2
      fi
    fi
  done

  # Check dev auth env consistency
  local api_env_file="$ROOT_DIR/pentra_core/services/api-gateway/.env"
  local expected_tenant="22222222-2222-2222-2222-222222222222"
  local expected_user="11111111-1111-1111-1111-111111111111"

  if [[ -f "$api_env_file" ]]; then
    local env_tenant
    env_tenant="$(grep -E '^DEV_AUTH_TENANT_ID=' "$api_env_file" 2>/dev/null | head -1 | cut -d= -f2- | tr -d '"' | tr -d "'" || true)"
    if [[ -n "$env_tenant" && "$env_tenant" != "$expected_tenant" ]]; then
      echo "[warn] DEV_AUTH_TENANT_ID in .env ($env_tenant) does not match seed data default ($expected_tenant)." >&2
      echo "        This may cause 'asset not found' or RLS errors. Update .env or seed data to match." >&2
    fi

    local env_user
    env_user="$(grep -E '^DEV_AUTH_USER_ID=' "$api_env_file" 2>/dev/null | head -1 | cut -d= -f2- | tr -d '"' | tr -d "'" || true)"
    if [[ -n "$env_user" && "$env_user" != "$expected_user" ]]; then
      echo "[warn] DEV_AUTH_USER_ID in .env ($env_user) does not match seed data default ($expected_user)." >&2
      echo "        This may cause auth errors. Update .env or seed data to match." >&2
    fi
  fi

  if (( errors > 0 )); then
    echo "[error] $errors critical issue(s) found. Fix them before starting the stack." >&2
    exit 1
  fi

  echo "[validate] Configuration checks passed"
}

ensure_local_infra() {
  require_cmd docker "Docker is required to run the Pentra local stack."
  require_cmd ss "ss is required to check local service ports."

  local missing_services=()

  ensure_named_container_running "pentra-postgres-local" "PostgreSQL" || missing_services+=("postgres")
  ensure_named_container_running "pentra-redis-local" "Redis" || missing_services+=("redis")

  if (( ${#missing_services[@]} > 0 )); then
    echo "[infra] Starting missing local infra services: ${missing_services[*]}"
    compose_cmd up -d "${missing_services[@]}"
  fi

  wait_for_container_health "pentra-postgres-local" "PostgreSQL"
  wait_for_container_health "pentra-redis-local" "Redis"
  wait_for_port "$POSTGRES_PORT" "PostgreSQL"
  wait_for_port "$REDIS_PORT" "Redis"
}

run_migrations_and_seed() {
  echo "[setup] Applying migrations and seeding dev data"
  "$ROOT_DIR/pentra_core/scripts/local/migrate_and_seed.sh"
}

start_stack() {
  require_cmd python3 "python3 is required to run the Pentra local stack."
  require_cmd pnpm "pnpm is required to run the Pentra frontend."
  require_cmd ss "ss is required to check local service ports."

  validate_config
  ensure_backend_env
  ensure_local_infra
  run_migrations_and_seed

  start_port_process \
    "demo-target" \
    "$DEMO_PORT" \
    env "PENTRA_PHASE3_DEMO_PORT=$DEMO_PORT" \
    "$ROOT_DIR/pentra_core/scripts/local/run_phase3_demo_target.sh"

  start_port_process \
    "api" \
    "$API_PORT" \
    env \
    "ALLOWED_ORIGINS=$ALLOWED_ORIGINS" \
    "PENTRA_API_PORT=$API_PORT" \
    "$ROOT_DIR/pentra_core/scripts/local/run_api.sh"

  start_port_process \
    "orchestrator" \
    "$ORCHESTRATOR_PORT" \
    env \
    "PENTRA_DISABLE_AUTONOMY=${PENTRA_DISABLE_AUTONOMY:-false}" \
    "PENTRA_ORCHESTRATOR_PORT=$ORCHESTRATOR_PORT" \
    "$ROOT_DIR/pentra_core/scripts/local/run_orchestrator.sh"

  for family in "${WORKER_FAMILIES[@]}"; do
    local worker_health_port_value
    worker_health_port_value="$(worker_health_port "$family")"
    start_port_process \
      "worker-$family" \
      "$worker_health_port_value" \
      env \
      "WORKER_LIVE_TOOLS=$WORKER_LIVE_TOOLS" \
      "WORKER_EXECUTION_MODE=${WORKER_EXECUTION_MODE:-controlled_live_local}" \
      "WORKER_LIVE_TARGET_POLICY=${WORKER_LIVE_TARGET_POLICY:-local_only}" \
      "WORKER_HEALTH_HOST=${WORKER_HEALTH_HOST:-127.0.0.1}" \
      "WORKER_HEALTH_PORT=$worker_health_port_value" \
      "WORKER_PREWARM_IMAGES=${WORKER_PREWARM_IMAGES:-true}" \
      "$ROOT_DIR/pentra_core/scripts/local/run_worker.sh" \
      "$family"
  done

  start_port_process \
    "frontend" \
    "$FRONTEND_PORT" \
    env "PENTRA_FRONTEND_PORT=$FRONTEND_PORT" \
    "$ROOT_DIR/pentra_core/scripts/local/run_frontend.sh"

  echo
  echo "Pentra local stack is up."
  echo "  Frontend:      http://localhost:$FRONTEND_PORT"
  echo "  API:           http://localhost:$API_PORT"
  echo "  Orchestrator:  http://localhost:$ORCHESTRATOR_PORT"
  echo "  Demo Target:   http://127.0.0.1:$DEMO_PORT"
  echo "  Logs:          $LOG_DIR"
  echo
  echo "Useful commands:"
  echo "  ./run_pentra_local.sh status"
  echo "  ./run_pentra_local.sh stop"
}

print_status() {
  echo "Pentra local status"
  echo "  PostgreSQL : $(is_port_listening "$POSTGRES_PORT" && echo "up :$POSTGRES_PORT" || echo "down")"
  echo "  Redis      : $(is_port_listening "$REDIS_PORT" && echo "up :$REDIS_PORT" || echo "down")"
  echo "  Demo Target: $(is_port_listening "$DEMO_PORT" && echo "up :$DEMO_PORT" || echo "down")"
  echo "  API        : $(is_port_listening "$API_PORT" && echo "up :$API_PORT" || echo "down")"
  echo "  Orchestrator: $(is_port_listening "$ORCHESTRATOR_PORT" && echo "up :$ORCHESTRATOR_PORT" || echo "down")"
  echo "  Frontend   : $(is_port_listening "$FRONTEND_PORT" && echo "up :$FRONTEND_PORT" || echo "down")"
  for family in "${WORKER_FAMILIES[@]}"; do
    local health_port
    health_port="$(worker_health_port "$family")"
    if is_port_listening "$health_port"; then
      echo "  Worker $family: up :$health_port"
    else
      echo "  Worker $family: down"
    fi
  done
  echo "  Logs       : $LOG_DIR"
}

stop_stack() {
  stop_pid_file_process "frontend"
  for family in "${WORKER_FAMILIES[@]}"; do
    stop_pid_file_process "worker-$family"
  done
  stop_pid_file_process "orchestrator"
  stop_pid_file_process "api"
  stop_pid_file_process "demo-target"

  if command -v docker >/dev/null 2>&1; then
    echo "[stop] PostgreSQL and Redis containers"
    compose_cmd stop postgres redis >/dev/null 2>&1 || true
  fi

  echo "Pentra local stack stopped."
}

print_help() {
  cat <<EOF
Usage: ./run_pentra_local.sh [start|status|stop|validate]

Commands:
  start   Start the full local Pentra stack
  status  Show local service status
  stop    Stop the services started by this script
  validate Run the canonical backend validation suites

Environment overrides:
  PENTRA_FRONTEND_PORT        Default: $FRONTEND_PORT
  PENTRA_API_PORT             Default: $API_PORT
  PENTRA_ORCHESTRATOR_PORT    Default: $ORCHESTRATOR_PORT
  PENTRA_PHASE3_DEMO_PORT     Default: $DEMO_PORT
  PENTRA_DISABLE_AUTONOMY     Default: false
  WORKER_EXECUTION_MODE       Default: controlled_live_local
  WORKER_LIVE_TARGET_POLICY   Default: local_only
  WORKER_LIVE_TOOLS           Default: $WORKER_LIVE_TOOLS
  WORKER_PREWARM_IMAGES       Default: true
EOF
}

case "${1:-start}" in
  start)
    start_stack
    ;;
  status)
    print_status
    ;;
  stop)
    stop_stack
    ;;
  validate)
    run_validation_suites
    ;;
  help|-h|--help)
    print_help
    ;;
  *)
    print_help
    exit 1
    ;;
esac
