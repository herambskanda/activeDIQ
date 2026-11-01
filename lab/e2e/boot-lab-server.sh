#!/usr/bin/env bash
# Boots a REAL, lab-built activeDIQ server for the console end-to-end suites (T-0855).
#
#   lab/e2e/boot-lab-server.sh up   [DIR]   build, start PostgreSQL + the server, write DIR/env
#   lab/e2e/boot-lab-server.sh down [DIR]   stop the server and remove the PostgreSQL container
#
# DIR defaults to a fresh mktemp directory (printed). `up` writes DIR/env: source it, then run
#   ADIQ_BASE_URL=... npm --prefix web run e2e -- webauthn-sign-in
# Nothing here is a secret worth keeping: the database and the KEK passphrase are random per boot,
# live under DIR (mode 0700) and in the container, and die with `down`.
# Needs: go, node/npm (web/node_modules installed), docker, openssl, curl.
set -euo pipefail

cmd="${1:-}"; dir="${2:-}"
root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
PG_IMAGE="${ADIQ_E2E_PG_IMAGE:-postgres:16-alpine}"

die() { echo "boot-lab-server: $*" >&2; exit 1; }

case "$cmd" in
up)
  [ -n "$dir" ] || dir="$(mktemp -d)"
  mkdir -p "$dir"; chmod 700 "$dir"; dir="$(cd "$dir" && pwd)"
  # 1. The console is embedded in the server binary (ADR-0001 tier W): build it unless the caller already did.
  if [ -z "$(find "$root/internal/webui/dist" -mindepth 1 ! -name .gitkeep -print -quit)" ]; then
    (cd "$root" && make web-embed)
  fi
  # 2. The lab build: the only build that has `account add-passkey` (labpasskey_lab.go).
  (cd "$root" && go build -tags lab -o "$dir/server" ./cmd/server)
  # 3. PostgreSQL with the install's roles; migrations applied as the owner role, like the installer.
  pgpass="$(openssl rand -hex 16)"; apppass="$(openssl rand -hex 16)"; ownpass="$(openssl rand -hex 16)"
  cid="$(docker run -d --rm -e POSTGRES_PASSWORD="$pgpass" -p 127.0.0.1::5432 "$PG_IMAGE")"
  echo "$cid" > "$dir/pg.cid"
  for _ in $(seq 1 60); do docker exec "$cid" pg_isready -U postgres -q 2>/dev/null && break; sleep 1; done
  docker exec "$cid" pg_isready -U postgres -q || die "PostgreSQL did not come up"
  psql_() { docker exec -i "$cid" psql -v ON_ERROR_STOP=1 -q -U postgres "$@"; }
  psql_ -d postgres <<SQL
CREATE ROLE activediq_owner LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOBYPASSRLS PASSWORD '$ownpass';
CREATE ROLE activediq_app   LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOBYPASSRLS PASSWORD '$apppass';
CREATE ROLE activediq_catrust NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOBYPASSRLS;
GRANT activediq_catrust TO activediq_owner;
CREATE DATABASE activediq OWNER activediq_owner;
SQL
  for f in $(ls "$root"/migrations/*.sql | sort); do
    docker exec -i "$cid" psql -v ON_ERROR_STOP=1 -q -U activediq_owner -d activediq < "$f" >/dev/null || die "migration $(basename "$f") failed"
  done
  port="$(docker port "$cid" 5432/tcp | head -1 | sed 's/.*://')"
  # 4. The installation KEK (passphrase provider) and the server settings.
  mkdir -p "$dir/kek" "$dir/tls"; chmod 700 "$dir/kek" "$dir/tls"
  openssl rand -hex 24 > "$dir/kek.pass"; chmod 600 "$dir/kek.pass"
  apiport="$(node -e 'const s=require("net").createServer().listen(0,"127.0.0.1",()=>{console.log(s.address().port);s.close()})')"
  cat > "$dir/env" <<ENV
export ACTIVEDIQ_DATABASE_DSN='postgres://activediq_app:$apppass@127.0.0.1:$port/activediq?sslmode=disable'
export ACTIVEDIQ_KEK_PROVIDER=passphrase
export ACTIVEDIQ_KEK_DIR='$dir/kek'
export ACTIVEDIQ_KEK_PASSPHRASE_FILE='$dir/kek.pass'
export ACTIVEDIQ_API_ADDR=127.0.0.1:$apiport
export ACTIVEDIQ_API_TLS_DIR='$dir/tls'
export ACTIVEDIQ_PUBLIC_URL=https://localhost:$apiport
export ADIQ_BASE_URL=https://localhost:$apiport
export ADIQ_E2E_SERVER_BIN='$dir/server'
export ADIQ_E2E_CA='$dir/tls/api-cert.pem'
ENV
  chmod 600 "$dir/env"
  # shellcheck disable=SC1090,SC1091
  . "$dir/env"
  "$dir/server" kek init
  # 5. Start it; wait for the readiness probe (this is process start-up, not test synchronisation).
  "$dir/server" > "$dir/server.log" 2>&1 &
  echo $! > "$dir/server.pid"
  for _ in $(seq 1 60); do
    ls "$dir"/tls/*.pem >/dev/null 2>&1 && curl -sf --cacert "$(ls "$dir"/tls/*.pem | head -1)" "https://localhost:$apiport/health/ready" >/dev/null 2>&1 && break
    kill -0 "$(cat "$dir/server.pid")" 2>/dev/null || { cat "$dir/server.log" >&2; die "the server exited"; }
    sleep 1
  done
  ls "$dir"/tls/ >&2
  echo "up: source $dir/env" >&2
  echo "$dir"
  ;;
down)
  [ -n "$dir" ] || die "usage: down DIR"
  [ ! -f "$dir/server.pid" ] || kill "$(cat "$dir/server.pid")" 2>/dev/null || true
  [ ! -f "$dir/pg.cid" ] || docker stop "$(cat "$dir/pg.cid")" >/dev/null 2>&1 || true
  ;;
*) die "usage: $0 up [DIR] | down DIR" ;;
esac
