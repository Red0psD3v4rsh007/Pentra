#!/usr/bin/env bash
set -euo pipefail

ACTION="${1:-ensure}"
TARGET_KEY="${2:-all}"

declare -A CONTAINER_NAMES=(
  [juice_shop_local]="pentra-benchmark-juice-shop"
  [dvwa_local]="pentra-benchmark-dvwa"
  [webgoat_local]="pentra-benchmark-webgoat"
)

declare -A IMAGES=(
  [juice_shop_local]="bkimminich/juice-shop@sha256:9d65de715135ec9ba7667335d02cf9c1b70f6cbe2ff1d454d1d1d3c22744c336"
  [dvwa_local]="vulnerables/web-dvwa@sha256:dae203fe11646a86937bf04db0079adef295f426da68a92b40e3b181f337daa7"
  [webgoat_local]="webgoat/webgoat@sha256:3101bd9e7bcfe122d7ef91e690ef3720de36cc4e86b3d06763a1ddf2e2751a4b"
)

declare -A PORT_MAPPINGS=(
  [juice_shop_local]="3001:3000"
  [dvwa_local]="3002:80"
  [webgoat_local]="3003:8080"
)

declare -A HEALTHCHECK_URLS=(
  [juice_shop_local]="http://127.0.0.1:3001/"
  [dvwa_local]="http://127.0.0.1:3002/"
  [webgoat_local]="http://127.0.0.1:3003/WebGoat"
)

declare -A HEALTH_TIMEOUTS=(
  [juice_shop_local]="120"
  [dvwa_local]="120"
  [webgoat_local]="180"
)

target_keys() {
  if [[ "$TARGET_KEY" == "all" ]]; then
    printf '%s\n' juice_shop_local dvwa_local webgoat_local
    return
  fi
  if [[ -z "${CONTAINER_NAMES[$TARGET_KEY]:-}" ]]; then
    echo "Unknown benchmark target: $TARGET_KEY" >&2
    exit 1
  fi
  printf '%s\n' "$TARGET_KEY"
}

container_exists() {
  local name="$1"
  docker inspect "$name" >/dev/null 2>&1
}

container_running() {
  local name="$1"
  local status
  status="$(docker inspect --format '{{.State.Status}}' "$name" 2>/dev/null || true)"
  [[ "$status" == "running" ]]
}

wait_for_http() {
  local url="$1"
  local timeout="$2"
  local attempt
  for attempt in $(seq 1 "$timeout"); do
    if curl -fsS -L --max-time 5 "$url" >/dev/null 2>&1; then
      return 0
    fi
    sleep 1
  done
  echo "Health check did not succeed for $url within ${timeout}s" >&2
  return 1
}

ensure_target() {
  local key="$1"
  local container="${CONTAINER_NAMES[$key]}"
  local image="${IMAGES[$key]}"
  local ports="${PORT_MAPPINGS[$key]}"
  local health_url="${HEALTHCHECK_URLS[$key]}"
  local timeout="${HEALTH_TIMEOUTS[$key]}"

  if ! docker image inspect "$image" >/dev/null 2>&1; then
    echo "[pull] $key -> $image"
    docker pull "$image" >/dev/null
  fi

  if container_exists "$container"; then
    if ! container_running "$container"; then
      echo "[start] $key container"
      docker start "$container" >/dev/null
    else
      echo "[skip] $key container already running"
    fi
  else
    echo "[run] $key -> $image"
    docker run -d \
      --name "$container" \
      --pull never \
      --restart unless-stopped \
      -p "$ports" \
      "$image" >/dev/null
  fi

  wait_for_http "$health_url" "$timeout"
  echo "[ok] $key reachable at $health_url"
}

status_target() {
  local key="$1"
  local container="${CONTAINER_NAMES[$key]}"
  if ! container_exists "$container"; then
    echo "$key: missing"
    return
  fi
  local status
  status="$(docker inspect --format '{{.State.Status}}' "$container" 2>/dev/null || true)"
  echo "$key: $status"
}

stop_target() {
  local key="$1"
  local container="${CONTAINER_NAMES[$key]}"
  if ! container_exists "$container"; then
    echo "[skip] $key container missing"
    return
  fi
  if container_running "$container"; then
    echo "[stop] $key"
    docker stop "$container" >/dev/null
  else
    echo "[skip] $key already stopped"
  fi
}

case "$ACTION" in
  ensure)
    while read -r key; do
      ensure_target "$key"
    done < <(target_keys)
    ;;
  status)
    while read -r key; do
      status_target "$key"
    done < <(target_keys)
    ;;
  stop)
    while read -r key; do
      stop_target "$key"
    done < <(target_keys)
    ;;
  *)
    echo "Unsupported action: $ACTION" >&2
    echo "Usage: $0 [ensure|status|stop] [target_key|all]" >&2
    exit 1
    ;;
esac
