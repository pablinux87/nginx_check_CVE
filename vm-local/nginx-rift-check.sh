#!/usr/bin/env bash
# Atajo al informe completo
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
exec "$DIR/nginx-rift-report.sh" "$@"
