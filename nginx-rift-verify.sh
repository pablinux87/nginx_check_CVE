#!/usr/bin/env bash
# Verificación post-parche + logs históricos SIGSEGV
# Uso: ./nginx-rift-verify.sh [-f hosts.txt] [-u USER] [-i KEY] [-c reporte-post.csv]
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SCAN="$SCRIPT_DIR/nginx-rift-scan.sh"
CSV_OUT="reporte-rift-post.csv"
EXTRA=()

while [[ $# -gt 0 ]]; do
  case "$1" in
    -f|-u|-i) EXTRA+=("$1" "$2"); shift 2 ;;
    -c) CSV_OUT="$2"; shift 2 ;;
    *) echo "Uso: $0 [-f hosts.txt] [-u USER] [-i KEY] [-c reporte-post.csv]" >&2; exit 1 ;;
  esac
done

[[ -x "$SCAN" ]] || chmod +x "$SCAN" 2>/dev/null || true
"$SCAN" "${EXTRA[@]}" -c "$CSV_OUT"
SCAN_RC=$?

echo
echo "=== Revisión logs (localhost / requiere ejecución en cada VM) ==="
for log in /var/log/nginx/error.log /var/log/nginx/access.log; do
  [[ -r "$log" ]] || continue
  echo "--- $log ---"
  grep -E "exited on signal|SIGSEGV" "$log" 2>/dev/null | tail -5 || echo "  (sin coincidencias recientes)"
  awk '{print $7}' "$log" 2>/dev/null | awk 'length($0)>500' | sort -u | head -5 | sed 's/^/  URI larga: /' || true
done

echo
echo "Smoke test manual por sitio: home, login, APIs, uploads."
echo "CSV post-parche: $CSV_OUT"
exit "$SCAN_RC"
