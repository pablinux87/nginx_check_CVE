#!/usr/bin/env bash
# Comprobaciones DESPUÉS del upgrade en VM de producción
# Uso: sudo ./nginx-rift-postflight-vm.sh [ruta_backup]
set -uo pipefail

BK="${1:-}"

echo "================================================================================"
echo " POSTFLIGHT VM — $(hostname -f 2>/dev/null || hostname)"
echo "================================================================================"
echo ""

echo "Versión: $(nginx -v 2>&1)"
echo ""

echo "=== nginx -t ==="
if ! nginx -t 2>&1 | sed 's/^/   /'; then
  echo ""
  echo "FALLO nginx -t. Si faltan módulos (brotli), ver LEEME-VM-PRODUCCION.txt"
  [[ -n "$BK" ]] && echo "Rollback rápido config: sudo cp $BK/nginx.conf /etc/nginx/nginx.conf"
  exit 1
fi
echo ""

echo "=== Vhosts cargados (nginx -T) ==="
nginx -T 2>/dev/null | grep -E '^# configuration file /etc/nginx/sites-' | sed 's/^# configuration file /   /;s/:$//' | sort -u
echo ""

echo "=== server_name activos ==="
nginx -T 2>/dev/null | grep -E '^\s+server_name ' | sed 's/^/   /' | head -40
echo ""

echo "=== Prueba HTTP local (puerto 80, Host header) ==="
while IFS= read -r name; do
  [[ -z "$name" || "$name" == "_" ]] && continue
  code="$(curl -sS -o /dev/null -w '%{http_code}' --connect-timeout 3 -H "Host: $name" "http://127.0.0.1/" 2>/dev/null || echo "ERR")"
  echo "   Host: $name → HTTP $code"
done < <(nginx -T 2>/dev/null | grep -E '^\s+server_name ' | sed 's/.*server_name//;s/;//' | tr ' ' '\n' | grep -v '^$' | sort -u | head -25)

echo ""
echo "Revisar en navegador los dominios críticos y HTTPS (certificados no se prueban aquí)."
echo "Informe CVE: ./nginx-rift-report.sh -o /home/nginx-rift-reporte-post.txt"
