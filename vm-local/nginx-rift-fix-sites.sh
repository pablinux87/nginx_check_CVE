#!/usr/bin/env bash
# Recuperar sitios tras upgrade nginx.org (Welcome to nginx)
# Uso: sudo ./nginx-rift-fix-sites.sh [ruta_backup] 
# Ejemplo: sudo ./nginx-rift-fix-sites.sh /etc/nginx.backup.20260515160205
set -uo pipefail

[[ "$(id -u)" -eq 0 ]] || { echo "Ejecutar con sudo." >&2; exit 1; }

BK="${1:-}"
NGX="/etc/nginx/nginx.conf"

echo "=== Diagnóstico ==="
echo "Sitios en sites-enabled:"
ls -la /etc/nginx/sites-enabled/ 2>/dev/null || echo "(vacío)"
echo ""
echo "Includes en nginx.conf:"
grep -n include "$NGX" || true
echo ""
echo "Config activa (server_name):"
nginx -T 2>/dev/null | grep -E 'server_name|root ' | head -20 || true

if [[ -n "$BK" && -f "$BK/nginx.conf" ]]; then
  echo ""
  echo "=== Diff nginx.conf (backup vs actual) ==="
  diff -u "$BK/nginx.conf" "$NGX" | head -40 || true
fi

echo ""
echo "=== Aplicar fix ==="

if [[ -d /etc/nginx/sites-enabled ]] && ! grep -q 'sites-enabled' "$NGX"; then
  if grep -q 'include /etc/nginx/conf.d/\*\.conf;' "$NGX"; then
    sed -i '/include \/etc\/nginx\/conf.d\/\*\.conf;/a\    include /etc/nginx/sites-enabled/*;' "$NGX"
    echo "OK: include sites-enabled añadido"
  else
    echo "Editar manualmente $NGX dentro del bloque http { }:"
    echo "    include /etc/nginx/sites-enabled/*;"
  fi
fi

for f in /etc/nginx/conf.d/default.conf; do
  if [[ -f "$f" ]]; then
    mv "$f" "${f}.disabled" && echo "OK: desactivado $f"
  fi
done

if nginx -t; then
  systemctl reload nginx
  echo "NGINX recargado."
  if ls /var/run/php/php*-fpm.sock &>/dev/null && grep -qE '^\s*user\s+nginx\s*;' "$NGX" 2>/dev/null; then
    echo ""
    echo "AVISO: user=nginx pero PHP-FPM usa socket www-data → suele dar 502."
    echo "Ejecutar: sudo ./nginx-rift-fix-502.sh ${BK:-}"
  else
    echo "Probar el sitio en el navegador."
  fi
fi
