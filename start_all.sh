#!/usr/bin/env bash
# Starts the development services (API, local agent, Vite dev server). See scripts/dev_services.sh.
exec "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/scripts/dev_services.sh" start
