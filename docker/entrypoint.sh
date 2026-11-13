#!/bin/sh
# Pulsar Hub container entrypoint. The first argument selects the role:
#   web     wait for the database, migrate, create the cache table, then serve with gunicorn.
#           The web container is the only one that migrates (migrate-before-traffic).
#   worker  wait until web has finished migrating, then run the django-q2 cluster.
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
psycopg.connect(os.environ["DATABASE_URL"], connect_timeout=3).close()
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
        log "running migrations..."
        python manage.py migrate --noinput
        # The shared database cache (rate limits, login throttles) needs its table; idempotent.
        log "ensuring cache table..."
        python manage.py createcachetable
        # The root filesystem is read-only: worker heartbeat files go to the /tmp tmpfs, and the
        # control socket (which gunicorn would put in the home directory) is off.
        log "starting gunicorn..."
        exec gunicorn hub.wsgi:application \
            --bind 0.0.0.0:8000 \
            --workers "${GUNICORN_WORKERS:-2}" \
            --timeout "${GUNICORN_TIMEOUT:-30}" \
            --worker-tmp-dir /tmp \
            --no-control-socket \
            --access-logfile -
        ;;
    worker)
        wait_for_migrations
        log "starting django-q2 cluster..."
        exec python manage.py qcluster
        ;;
    *)
        exec "$@"
        ;;
esac
