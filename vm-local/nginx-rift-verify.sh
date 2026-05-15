#!/usr/bin/env bash
# Verificación post-parche — ejecutar en VM/KUDU
set -uo pipefail

echo "=== Verificación post-parche CVE-2026-42945 ==="
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
"$DIR/nginx-rift-check.sh"
RC=$?

for log in /var/log/nginx/error.log /var/log/nginx/access.log; do
  [[ -r "$log" ]] || continue
  echo "--- $log (SIGSEGV / signal 11) ---"
  grep -E "exited on signal|SIGSEGV" "$log" 2>/dev/null | tail -5 || echo "(sin coincidencias recientes)"
done

echo "Smoke test manual: home, login, APIs."
exit "$RC"
