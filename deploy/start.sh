#!/usr/bin/env bash
set -euo pipefail

data_dir="${POCKETBASE_DATA_DIR:-/data}"
mkdir -p "$data_dir"

# Easypanel/Docker volumes can replace the image's pre-owned /data directory
# with a root-owned mount. Repair it before starting the data-owning processes.
if [[ "$(id -u)" -eq 0 ]]; then
  chown -R bun:bun "$data_dir"
fi

if [[ -z "${POCKETBASE_SUPERUSER_EMAIL:-}" || -z "${POCKETBASE_SUPERUSER_PASSWORD:-}" ]]; then
  echo "POCKETBASE_SUPERUSER_EMAIL and POCKETBASE_SUPERUSER_PASSWORD are required." >&2
  exit 1
fi
if [[ -z "${POCKETBASE_WORKER_EMAIL:-}" || -z "${POCKETBASE_WORKER_PASSWORD:-}" ]]; then
  echo "POCKETBASE_WORKER_EMAIL and POCKETBASE_WORKER_PASSWORD are required." >&2
  exit 1
fi

status_file=/tmp/wellguard-startup-status.txt
error_file=/tmp/wellguard-startup-error.txt
printf 'starting\n' >"$status_file"
: >"$error_file"

pb_pid=''
agent_pid=''
nginx -c /etc/nginx/nginx.conf -g 'daemon off;' &
nginx_pid=$!

shutdown() {
  for pid in "$nginx_pid" "$agent_pid" "$pb_pid"; do
    [[ -n "$pid" ]] && kill -TERM "$pid" 2>/dev/null || true
  done
  wait 2>/dev/null || true
}
trap shutdown TERM INT EXIT

fail_startup() {
  local message="$1"
  printf 'error: %s\n' "$message" >"$status_file"
  echo "Wellguard startup failed: $message" >&2
  wait "$nginx_pid"
  exit 1
}

printf 'migrating PocketBase\n' >"$status_file"
if ! gosu bun /usr/local/bin/pocketbase superuser upsert "$POCKETBASE_SUPERUSER_EMAIL" "$POCKETBASE_SUPERUSER_PASSWORD" \
  --dir="$data_dir" --migrationsDir=/app/pb_migrations --dev=false >/dev/null \
  2> >(tee -a "$error_file" >&2); then
  fail_startup 'PocketBase migration or superuser setup failed'
fi

gosu bun /usr/local/bin/pocketbase serve --http=127.0.0.1:8090 --origins="${PUBLIC_ORIGIN:-*}" \
  --dir="$data_dir" --migrationsDir=/app/pb_migrations --dev=false \
  2> >(tee -a "$error_file" >&2) &
pb_pid=$!

printf 'waiting for PocketBase\n' >"$status_file"
pb_ready=false
for _ in {1..30}; do
  if curl --silent --fail http://127.0.0.1:8090/api/health >/dev/null; then break; fi
  sleep 1
done

if curl --silent --fail http://127.0.0.1:8090/api/health >/dev/null; then
  pb_ready=true
fi

if [[ "$pb_ready" != true ]]; then
  fail_startup 'PocketBase did not become healthy within 30 seconds'
fi

printf 'provisioning the observer identity\n' >"$status_file"
if ! gosu bun env POCKETBASE_URL=http://127.0.0.1:8090 bun run /app/scripts/seed-worker.ts >/dev/null \
  2> >(tee -a "$error_file" >&2); then
  fail_startup 'least-privilege observer provisioning failed'
fi

if [[ -n "${WELLGUARD_ADMIN_EMAIL:-}" && -n "${WELLGUARD_ADMIN_PASSWORD:-}" ]]; then
  printf 'seeding the initial workspace\n' >"$status_file"
  if ! gosu bun env POCKETBASE_URL=http://127.0.0.1:8090 bun run /app/scripts/seed.ts >/dev/null \
    2> >(tee -a "$error_file" >&2); then
    fail_startup 'initial workspace seed failed'
  fi
fi

printf 'starting the observer\n' >"$status_file"
gosu bun env -u POCKETBASE_SUPERUSER_EMAIL -u POCKETBASE_SUPERUSER_PASSWORD bun run /app/agent/index.ts &
agent_pid=$!
sleep 1
if ! kill -0 "$agent_pid" 2>/dev/null; then
  fail_startup 'observer worker exited during startup'
fi

printf 'ready\n' >"$status_file"

wait -n "$nginx_pid" "$agent_pid" "$pb_pid"
exit 1
