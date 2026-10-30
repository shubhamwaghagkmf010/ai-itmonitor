#!/usr/bin/env bash
# Stops the development services started by start_all.sh - only those, found through their pid files.
exec "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/scripts/dev_services.sh" stop
