#!/bin/sh
# Container entry point: bring the database schema up to date, then run the command (uvicorn).
# Set RUN_MIGRATIONS=0 to skip the migration step, e.g. when it is run separately.
set -e

if [ "${RUN_MIGRATIONS:-1}" = "1" ]; then
    python scripts/migrate.py
fi

exec "$@"
