#!/bin/sh
# Pulsar Hub container entrypoint. The first argument selects the role:
#   web     wait for the database, migrate, create the cache table, then serve with gunicorn.
#           The web container is the only one that migrates (migrate-before-traffic).
#   worker  wait until web has finished migrating, then run the django-q2 cluster.
#   relay   run the remote-console relay (python -m relay). It has no database and waits for web itself.
#   other   run the given command as-is, e.g. `docker compose run --rm web python manage.py shell`.
set -eu

log() { echo "[entrypoint] $*"; }

# Bounded wait: WAIT_TRIES attempts, 2 seconds apart (default 60 tries = 2 minutes).
WAIT_TRIES="${ENTRYPOINT_WAIT_TRIES:-60}"

wait_for_db() {
    log "waiting for the database..."
    i=0
    until python - <<'PY' >/dev/null 2>&1
import os, psycopg
# The owning role exists from the start; the application role only after the first grant.
url = os.environ.get("DATABASE_OWNER_URL") or os.environ["DATABASE_URL"]
psycopg.connect(url, connect_timeout=3).close()
PY
    do
        i=$((i + 1))
        if [ "$i" -ge "$WAIT_TRIES" ]; then
            log "ERROR: database not reachable after $WAIT_TRIES attempts; giving up." >&2
            exit 1
        fi
        sleep 2
    done
    log "database is reachable."
}

wait_for_migrations() {
    log "waiting for web to finish migrating..."
    i=0
    until python manage.py migrate --check >/dev/null 2>&1; do
        i=$((i + 1))
        if [ "$i" -ge "$WAIT_TRIES" ]; then
            log "ERROR: migrations still unapplied after $WAIT_TRIES attempts; is the web service healthy?" >&2
            exit 1
        fi
        sleep 2
    done
    log "migrations are applied."
}

role="${1:-web}"

case "$role" in
    web)
        wait_for_db
        # Migrations, the cache table, schedules and role grants run as the owning database role
        # when one is configured. The service itself then starts as the application role, and
        # the owner's credentials are removed from its environment first.
        if [ -n "${DATABASE_OWNER_URL:-}" ]; then
            export HUB_DATABASE_AS_OWNER=1
        else
            log "WARNING: DATABASE_OWNER_URL is not set; the service runs as the role that owns the tables."
        fi
        log "running migrations..."
        python manage.py migrate --noinput
        # The shared database cache (rate limits, login throttles) needs its table; idempotent.
        log "ensuring cache table..."
        python manage.py createcachetable
        log "ensuring housekeeping schedules..."
        python manage.py setup_schedules
        if [ -n "${DATABASE_OWNER_URL:-}" ]; then
            log "setting the application role's rights..."
            python manage.py grant_app_role
        fi
        unset HUB_DATABASE_AS_OWNER DATABASE_OWNER_URL POSTGRES_PASSWORD
        # The root filesystem is read-only: worker heartbeat files go to the /tmp tmpfs, and the
        # control socket (which gunicorn would put in the home directory) is off. There is no
        # gunicorn access log: the hub writes its own, with secrets in addresses redacted.
        log "starting gunicorn..."
        exec gunicorn hub.wsgi:application \
            --bind 0.0.0.0:8000 \
            --workers "${GUNICORN_WORKERS:-2}" \
            --timeout "${GUNICORN_TIMEOUT:-30}" \
            --worker-tmp-dir /tmp \
            --no-control-socket
        ;;
    worker)
        wait_for_migrations
        unset DATABASE_OWNER_URL POSTGRES_PASSWORD
        log "starting django-q2 cluster..."
        exec python manage.py qcluster
        ;;
    relay)
        # No database, no Django. It announces itself to web and retries until web answers.
        unset DATABASE_URL DATABASE_OWNER_URL POSTGRES_PASSWORD DJANGO_SECRET_KEY OIDC_RSA_PRIVATE_KEY
        log "starting the remote-console relay..."
        exec python -m relay
        ;;
    *)
        # One-off commands (`docker compose run --rm web python manage.py ...`). Add
        # HUB_DATABASE_AS_OWNER=1 for the few that change the schema.
        exec "$@"
        ;;
esac
