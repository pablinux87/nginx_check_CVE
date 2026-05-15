#!/usr/bin/env bash
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
echo "=== Verificación post-parche ==="
exec "$DIR/nginx-rift-report.sh" "$@"
