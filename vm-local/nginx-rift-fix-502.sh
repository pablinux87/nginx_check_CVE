#!/usr/bin/env bash
# 502 Bad Gateway tras upgrade nginx.org en Ubuntu/Debian + PHP-FPM
# Causa habitual: user nginx vs socket www-data en /var/run/php/*.sock
# Uso: sudo ./nginx-rift-fix-502.sh [ruta_backup_nginx]
set -uo pipefail

[[ "$(id -u)" -eq 0 ]] || { echo "Ejecutar con sudo." >&2; exit 1; }

BK="${1:-}"
NGX="/etc/nginx/nginx.conf"
ERRLOG="/var/log/nginx/error.log"
FIXED=0

echo "=== 502 — diagnóstico PHP-FPM ==="
echo ""

echo "1) Servicios"
systemctl is-active nginx php8.1-fpm php8.2-fpm php-fpm 2>/dev/null | paste - - - - || true
echo ""

echo "2) Usuario NGINX (nginx.conf)"
grep -E '^\s*user\s' "$NGX" || echo "(sin directiva user)"
NGX_USER="$(grep -E '^\s*user\s' "$NGX" | awk '{print $2}' | tr -d ';' | head -1)"
echo "   Proceso master: $(ps -o user= -C nginx 2>/dev/null | head -1 | xargs)"
echo ""

echo "3) Sockets PHP-FPM"
ls -la /var/run/php/*.sock 2>/dev/null || ls -la /run/php/*.sock 2>/dev/null || echo "   No hay sockets en /var/run/php ni /run/php"
echo ""

echo "4) Últimos errores NGINX (connect() to unix:...)"
if [[ -f "$ERRLOG" ]]; then
  tail -n 15 "$ERRLOG" | grep -E 'connect\(\)|Permission denied|No such file|upstream' || tail -n 8 "$ERRLOG"
else
  echo "   Sin $ERRLOG"
fi
echo ""

echo "5) fastcgi en star_it / sites-enabled"
grep -R "fastcgi_pass\|fastcgi-php" /etc/nginx/sites-enabled/ 2>/dev/null | head -10 || true
echo ""

if [[ -n "$BK" && -f "$BK/nginx.conf" ]]; then
  echo "6) user en backup vs actual"
  grep -E '^\s*user\s' "$BK/nginx.conf" "$NGX" || true
  echo ""
fi

echo "=== Aplicar correcciones ==="

# A) user www-data (estándar Ubuntu + socket FPM)
if [[ -f "$NGX" ]] && grep -qE '^\s*user\s+nginx\s*;' "$NGX"; then
  if ls /var/run/php/php*-fpm.sock /run/php/php*-fpm.sock &>/dev/null; then
    sed -i 's/^\s*user\s\+nginx\s*;/user www-data;/' "$NGX"
    echo "OK: user nginx → www-data en $NGX"
    FIXED=1
  fi
fi

# B) snippets fastcgi (Ubuntu) si el backup los tenía distintos
if [[ -n "$BK" && -f "$BK/snippets/fastcgi-php.conf" ]]; then
  if ! cmp -s "$BK/snippets/fastcgi-php.conf" /etc/nginx/snippets/fastcgi-php.conf 2>/dev/null; then
    cp -a "$BK/snippets/fastcgi-php.conf" /etc/nginx/snippets/fastcgi-php.conf
    echo "OK: restaurado snippets/fastcgi-php.conf desde backup"
    FIXED=1
  fi
fi

# C) PHP-FPM arriba
for svc in php8.1-fpm php8.2-fpm php-fpm; do
  if systemctl list-unit-files "$svc.service" &>/dev/null; then
    systemctl start "$svc" 2>/dev/null || true
    systemctl is-active --quiet "$svc" && echo "OK: $svc activo"
  fi
done

echo ""
if nginx -t; then
  systemctl restart nginx
  echo "NGINX reiniciado. Probar el sitio."
  echo ""
  echo "Si sigue 502, pegar salida de:"
  echo "  tail -20 $ERRLOG"
  echo "  ls -la /var/run/php/"
  echo "  grep fastcgi_pass /etc/nginx/sites-enabled/*"
else
  echo "nginx -t falló — revisar $NGX" >&2
  exit 1
fi
