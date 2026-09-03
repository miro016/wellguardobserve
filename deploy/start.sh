#!/usr/bin/env bash
set -euo pipefail

data_dir="${POCKETBASE_DATA_DIR:-/data}"
mkdir -p "$data_dir"

if [[ -z "${POCKETBASE_SUPERUSER_EMAIL:-}" || -z "${POCKETBASE_SUPERUSER_PASSWORD:-}" ]]; then
  echo "POCKETBASE_SUPERUSER_EMAIL and POCKETBASE_SUPERUSER_PASSWORD are required." >&2
  exit 1
fi

/usr/local/bin/pocketbase superuser upsert "$POCKETBASE_SUPERUSER_EMAIL" "$POCKETBASE_SUPERUSER_PASSWORD" \
  --dir="$data_dir" --migrationsDir=/app/pb_migrations --dev=false >/dev/null

/usr/local/bin/pocketbase serve --http=127.0.0.1:8090 --origins="${PUBLIC_ORIGIN:-*}" \
  --dir="$data_dir" --migrationsDir=/app/pb_migrations --dev=false &
pb_pid=$!

for _ in {1..30}; do
  if curl --silent --fail http://127.0.0.1:8090/api/health >/dev/null; then break; fi
  sleep 1
done

if [[ -n "${WELLGUARD_ADMIN_EMAIL:-}" && -n "${WELLGUARD_ADMIN_PASSWORD:-}" ]]; then
  POCKETBASE_URL=http://127.0.0.1:8090 bun run /app/scripts/seed.ts >/dev/null
fi

bun run /app/agent/index.ts &
agent_pid=$!
nginx -c /etc/nginx/nginx.conf -g 'daemon off;' &
nginx_pid=$!

shutdown() {
  kill -TERM "$nginx_pid" "$agent_pid" "$pb_pid" 2>/dev/null || true
  wait "$nginx_pid" "$agent_pid" "$pb_pid" 2>/dev/null || true
}
trap shutdown TERM INT EXIT

wait -n "$nginx_pid" "$agent_pid" "$pb_pid"
exit 1
