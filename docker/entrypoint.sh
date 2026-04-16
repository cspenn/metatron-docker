#!/bin/bash
set -e

echo "[entrypoint] Waiting for MariaDB to be ready..."

MAX_TRIES=30
COUNT=0

until mariadb -h"${DB_HOST:-mariadb}" \
              -u"${DB_USER:-metatron}" \
              -p"${DB_PASSWORD:-metatron123}" \
              "${DB_NAME:-metatron}" \
              -e "SELECT 1" >/dev/null 2>&1; do
    COUNT=$((COUNT + 1))
    if [ "$COUNT" -ge "$MAX_TRIES" ]; then
        echo "[entrypoint] ERROR: MariaDB did not become ready after ${MAX_TRIES} attempts. Exiting."
        exit 1
    fi
    echo "[entrypoint] Attempt ${COUNT}/${MAX_TRIES} -- MariaDB not ready yet, waiting 2s..."
    sleep 2
done

echo "[entrypoint] MariaDB is ready. Starting Metatron..."
exec "$@"
