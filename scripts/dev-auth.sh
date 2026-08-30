#!/usr/bin/env bash
# Local authenticated dev rig — a real API on :8080 backed by a real Postgres,
# so auth-gated pages (/clusters, /dashboard, /admin) can be looked at in a
# browser instead of only asserted against in happy-dom.
#
# Why this exists: `make frontend-dev-live` proxies to production and is
# therefore signed-out and read-only, which leaves a third of the app
# unverifiable. This rig is the opposite trade: entirely local, so writes are
# safe, and it serves THIS branch's API rather than the deployed one.
#
# No containers. postgresql and nats-server are native binaries in the Flox
# environment; everything below runs out of .dev/ (gitignored).
#
# The GitHub OAuth vars are set to placeholders only because the API validates
# their presence at startup. The /auth routes are never exercised here — the
# rig authenticates by API key — so no OAuth app exists and none is needed.
#
# Auth uses no bypass and no new code path. internal/api/middleware.go already
# accepts `Authorization: Bearer <api-key>` as equivalent to a session cookie,
# so the rig mints keys for five seeded personas (see PERSONAS below) and the
# dev vite config injects one. GitHub OAuth is never involved; its config vars
# stay empty.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DEV="$ROOT/.dev"
PGDATA="$DEV/pgdata"
PGPORT=5433
NATS_PORT=4222
API_PORT=8080
ENVFILE="$DEV/dev-auth.env"

export PGHOST=127.0.0.1
export PGPORT
export PGUSER=ocidex
export PGDATABASE=ocidex

log() { printf '\033[36m▸\033[0m %s\n' "$*"; }
die() { printf '\033[31m✗\033[0m %s\n' "$*" >&2; exit 1; }

# ── Postgres ────────────────────────────────────────────────────────────────
pg_running() { pg_ctl -D "$PGDATA" status >/dev/null 2>&1; }

start_pg() {
    if [ ! -d "$PGDATA" ]; then
        log "initdb $PGDATA"
        # trust auth: the socket is bound to loopback on a non-default port and
        # holds nothing but throwaway fixture data.
        initdb -D "$PGDATA" -U ocidex --auth=trust >"$DEV/initdb.log" 2>&1 \
            || { cat "$DEV/initdb.log"; die "initdb failed"; }
    fi
    if pg_running; then
        log "postgres already running on :$PGPORT"
    else
        log "starting postgres on :$PGPORT"
        pg_ctl -D "$PGDATA" -l "$DEV/postgres.log" \
            -o "-p $PGPORT -k $DEV -h 127.0.0.1" -w start \
            || { tail -20 "$DEV/postgres.log"; die "postgres failed to start"; }
    fi
    createdb ocidex 2>/dev/null && log "created database ocidex" || true
}

# ── NATS ────────────────────────────────────────────────────────────────────
start_nats() {
    if [ -f "$DEV/nats.pid" ] && kill -0 "$(cat "$DEV/nats.pid")" 2>/dev/null; then
        log "nats already running on :$NATS_PORT"
        return
    fi
    log "starting nats-server on :$NATS_PORT"
    nats-server -p "$NATS_PORT" -js -sd "$DEV/nats" >"$DEV/nats.log" 2>&1 &
    echo $! > "$DEV/nats.pid"
    sleep 1
    kill -0 "$(cat "$DEV/nats.pid")" 2>/dev/null || { tail -20 "$DEV/nats.log"; die "nats failed to start"; }
}

# ── Schema + fixtures ───────────────────────────────────────────────────────
DB_URL="postgres://ocidex@127.0.0.1:$PGPORT/ocidex?sslmode=disable"

migrate() {
    log "applying migrations"
    (cd "$ROOT" && DATABASE_URL="$DB_URL" go run ./cmd/ocidex migrate up) \
        || die "migrations failed"
}

# ── Personas ────────────────────────────────────────────────────────────────
# Five principals, one on each side of every authorization boundary the app
# draws today: a global admin, a namespace owner, a member who owns nothing, a
# global viewer, and a member who owns a *different* namespace. The last is the
# one that makes cross-tenant denial observable — without a second tenant,
# "denied" and "nothing there" render identically.
#
# Fields: username:github_id:global_role:owned_namespace
PERSONAS=(
    "devadmin:1:admin:"
    "devowner:2:member:local"
    "devsecurity:3:member:"
    "devviewer:4:viewer:"
    "devoutsider:5:member:outsider-lab"
)

# Every capability the server knows (internal/authz/capability.go), as a
# Postgres array literal. "Everything" is spelled out rather than left empty
# because api_key.capabilities defaults to '{}', which means a key that can do
# nothing at all.
ALL_CAPABILITIES="{read_private,ingest,trigger_scan,push_inventory,delete_artifact,manage_source,manage_cluster,read_secret,manage_member,delete_namespace}"

# Mints the five personas, each with a fully-capable and a read-only API key. Keys
# are hashed exactly as internal/service/auth.go does it — hex(SHA-256(plaintext)),
# prefix = first 8 chars — so they validate through the ordinary ValidateAPIKey
# path. No bypass, no fixture-only code.
mint_key() { openssl rand -base64 32 | tr '+/' '-_' | tr -d '=\n' | sed 's/^/ocidex_/'; }

seed_auth() {
    if [ -f "$ENVFILE" ] && psql -tAc "SELECT 1 FROM api_key LIMIT 1" | grep -q 1; then
        log "reusing existing dev credentials ($ENVFILE)"
        return
    fi

    local sql env_body persona user gid role ns scope key hash prefix var
    sql=""
    env_body=""

    for persona in "${PERSONAS[@]}"; do
        IFS=: read -r user gid role ns <<<"$persona"
        sql+="
INSERT INTO ocidex_user (github_id, github_username, role)
VALUES ($gid, '$user', '$role')
ON CONFLICT (github_id) DO UPDATE SET github_username = EXCLUDED.github_username, role = EXCLUDED.role;
"
        # Two keys per persona, spanning the ceiling (ADR-046): one holding
        # every capability, which resolves to whatever the persona's roles
        # allow, and one holding read_private alone. The _RW/_RO variable names
        # survive the retirement of the read / read-write scopes because that
        # is still what the pair is for.
        for variant in full read; do
            key="$(mint_key)"
            hash="$(printf '%s' "$key" | shasum -a 256 | cut -d' ' -f1)"
            prefix="${key:0:8}"
            if [ "$variant" = full ]; then
                caps="$ALL_CAPABILITIES"
            else
                caps="{read_private}"
            fi
            sql+="
INSERT INTO api_key (user_id, name, key_hash, prefix, capabilities)
SELECT id, '$user $variant', '$hash', '$prefix', '$caps'
FROM ocidex_user WHERE github_id = $gid;
"
            var="OCIDEX_DEV_KEY_$(printf '%s' "$user" | tr '[:lower:]' '[:upper:]')"
            [ "$variant" = full ] && var="${var}_RW" || var="${var}_RO"
            env_body+="$var=$key
"
            # The vite dev config and scripts/dev-fixtures.py both predate the
            # persona roster; devadmin's full key keeps the old name so neither
            # has to know about personas to keep working.
            [ "$user" = "devadmin" ] && [ "$variant" = full ] && \
                env_body+="OCIDEX_DEV_API_KEY=$key
"
        done
        if [ -n "$ns" ]; then
            sql+="
INSERT INTO namespace (name, visibility) VALUES ('$ns', 'private')
ON CONFLICT (name) DO NOTHING;
INSERT INTO namespace_member (namespace_id, user_id, role)
SELECT n.id, u.id, 'owner' FROM namespace n, ocidex_user u
WHERE n.name = '$ns' AND u.github_id = $gid
ON CONFLICT (namespace_id, user_id) DO NOTHING;
"
        fi
    done

    log "seeding ${#PERSONAS[@]} personas, $(( ${#PERSONAS[@]} * 2 )) API keys"
    psql -v ON_ERROR_STOP=1 -q <<SQL
$sql
SQL
    cat > "$ENVFILE" <<ENV
# Generated by scripts/dev-auth.sh — local only, never a real credential.
# One fully-capable (_RW) and one read-only (_RO) key per persona; see PERSONAS.
$env_body
DATABASE_URL=$DB_URL
ENV
    log "credentials written to $ENVFILE"
}

# Prints who exists and what they own. The roster is the whole point of the rig
# — a reviewer has to know which key is which before switching personas.
#
# "Owns" is now a membership row (ADR-046), not a namespace column: the owner is
# the single `namespace_member` with role 'owner'.
roster() {
    psql -tA -F' ' <<'SQL' 2>/dev/null || echo "  (database not reachable)"
SELECT '  ' || rpad(u.github_username, 12) || rpad(u.role, 7)
       || rpad((SELECT count(*) FROM api_key k WHERE k.user_id = u.id) || ' keys', 8)
       || 'owns: ' || coalesce(string_agg(n.name || ' (' || n.visibility || ')', ', '), '-')
FROM ocidex_user u
LEFT JOIN namespace_member m ON m.user_id = u.id AND m.role = 'owner'
LEFT JOIN namespace n ON n.id = m.namespace_id
GROUP BY u.id, u.github_username, u.role
ORDER BY u.github_id;
SQL
}

# ── API ─────────────────────────────────────────────────────────────────────
start_api() {
    if [ -f "$DEV/api.pid" ] && kill -0 "$(cat "$DEV/api.pid")" 2>/dev/null; then
        log "api already running on :$API_PORT"
        return
    fi
    log "starting api on :$API_PORT"
    (
        cd "$ROOT"
        DATABASE_URL="$DB_URL" \
        NATS_URL="nats://127.0.0.1:$NATS_PORT" \
        PORT="$API_PORT" \
        ENVIRONMENT=development \
        LOG_LEVEL=info \
        SESSION_SECRET="$(openssl rand -hex 32)" \
        GITHUB_CLIENT_ID=dev-unused \
        GITHUB_CLIENT_SECRET=dev-unused \
        FRONTEND_URL="http://localhost:3200" \
        CORS_ALLOWED_ORIGINS="http://localhost:3200" \
        nohup go run ./cmd/ocidex >"$DEV/api.log" 2>&1 &
        echo $! > "$DEV/api.pid"
    )
    for _ in $(seq 1 60); do
        if curl -sf "http://127.0.0.1:$API_PORT/ready" >/dev/null 2>&1; then
            log "api ready"
            return
        fi
        sleep 1
    done
    tail -30 "$DEV/api.log"
    die "api did not become ready"
}

# The fixtures are a separate script and a separate step on purpose: `up` has to
# stay runnable against an already-seeded rig, and a corpus is the part most
# likely to need re-running on its own while iterating on a page.
seed_fixtures() {
    (cd "$ROOT" && python3 scripts/dev-fixtures.py)
}

stop_all() {
    for svc in api nats; do
        if [ -f "$DEV/$svc.pid" ]; then
            # go run spawns the real binary as a child; kill the group.
            pkill -P "$(cat "$DEV/$svc.pid")" 2>/dev/null || true
            kill "$(cat "$DEV/$svc.pid")" 2>/dev/null || true
            rm -f "$DEV/$svc.pid"
            log "stopped $svc"
        fi
    done
    pkill -f 'ocidex/exe/ocidex' 2>/dev/null || true
    if pg_running; then
        pg_ctl -D "$PGDATA" -m fast stop >/dev/null && log "stopped postgres"
    fi
}

case "${1:-up}" in
    up)
        mkdir -p "$DEV"
        start_pg
        start_nats
        migrate
        seed_auth
        start_api
        seed_fixtures
        printf '\n\033[32m✓\033[0m rig up — api :%s, postgres :%s, nats :%s\n' \
            "$API_PORT" "$PGPORT" "$NATS_PORT"
        printf '  next: \033[1mmake frontend-dev-auth\033[0m  (:3200, signed out — pick a persona in the switcher)\n'
        printf '\n  personas (\033[1mmake dev-auth-status\033[0m to re-print):\n'
        roster
        ;;
    fixtures) seed_fixtures ;;
    down)   stop_all ;;
    status)
        pg_running && echo "postgres: up" || echo "postgres: down"
        [ -f "$DEV/nats.pid" ] && kill -0 "$(cat "$DEV/nats.pid")" 2>/dev/null \
            && echo "nats: up" || echo "nats: down"
        curl -sf "http://127.0.0.1:$API_PORT/ready" >/dev/null 2>&1 \
            && echo "api: up" || echo "api: down"
        if pg_running; then
            echo "personas:"
            roster
        fi
        ;;
    # `key` alone is devadmin's fully-capable key (what the vite config injects);
    # `key devviewer ro` picks any persona/scope out of the roster.
    key)
        if [ -z "${2:-}" ]; then
            grep '^OCIDEX_DEV_API_KEY=' "$ENVFILE" | cut -d= -f2
        else
            var="OCIDEX_DEV_KEY_$(printf '%s' "$2" | tr '[:lower:]' '[:upper:]')"
            var="${var}_$(printf '%s' "${3:-rw}" | tr '[:lower:]' '[:upper:]')"
            grep "^$var=" "$ENVFILE" | cut -d= -f2 \
                || die "no key $var in $ENVFILE"
        fi
        ;;
    reset)
        stop_all
        rm -rf "$DEV"
        log "removed $DEV — next 'up' starts from an empty database"
        ;;
    *) die "usage: dev-auth.sh [up|down|status|key [persona [rw|ro]]|fixtures|reset]" ;;
esac
