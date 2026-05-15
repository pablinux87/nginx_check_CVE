#!/usr/bin/env bash
# Comprobaciones ANTES de parchear NGINX en VM de producción (multi-sitio / SSL)
# Uso: sudo ./nginx-rift-preflight-vm.sh
set -uo pipefail

[[ "$(id -u)" -eq 0 ]] || { echo "Ejecutar con sudo." >&2; exit 1; }

FAIL=0
WARN=0

version_ge() {
  [[ "$(printf '%s\n%s\n' "$2" "$1" | sort -V | tail -n1)" == "$1" ]]
}

echo "================================================================================"
echo " PREFLIGHT VM — CVE NGINX Rift ($(hostname -f 2>/dev/null || hostname))"
echo " $(date -u '+%Y-%m-%d %H:%M:%S UTC')"
echo "================================================================================"
echo ""

VER="$(nginx -v 2>&1 | awk -F/ '{print $2}' | awk '{print $1}')"
echo "1. Versión actual: $VER"
if version_ge "$VER" "1.30.1"; then
  echo "   OK: ya parcheado para el CVE."
else
  echo "   PENDIENTE: hace falta >= 1.30.1"
  WARN=$((WARN+1))
fi
echo ""

echo "2. nginx -t (obligatorio antes de tocar nada)"
if nginx -t 2>&1 | sed 's/^/   /'; then
  echo "   OK"
else
  echo "   FALLO: no actualizar hasta corregir la config actual."
  FAIL=$((FAIL+1))
fi
echo ""

echo "3. Sitios habilitados (sites-enabled)"
if [[ -d /etc/nginx/sites-enabled ]]; then
  ls -la /etc/nginx/sites-enabled/ | sed 's/^/   /'
  ENABLED_COUNT="$(find /etc/nginx/sites-enabled -maxdepth 1 -type l -o -type f 2>/dev/null | wc -l)"
  echo "   Total entradas: $ENABLED_COUNT"
  echo ""
  echo "   server_name por vhost:"
  grep -Rh '^\s*server_name' /etc/nginx/sites-enabled/ 2>/dev/null | sed 's/^/     /' || true
else
  echo "   AVISO: no hay sites-enabled (layout distinto)."
  WARN=$((WARN+1))
fi
echo ""

echo "4. includes en nginx.conf"
grep -nE 'include.*/(sites-enabled|conf\.d|modules-enabled)' /etc/nginx/nginx.conf 2>/dev/null | sed 's/^/   /' || echo "   (revisar nginx.conf a mano)"
if ! grep -q 'sites-enabled' /etc/nginx/nginx.conf 2>/dev/null; then
  echo "   AVISO: nginx.conf no incluye sites-enabled"
  WARN=$((WARN+1))
fi
echo ""

echo "5. Módulos dinámicos Ubuntu (CRÍTICO para nginx.org)"
if [[ -d /etc/nginx/modules-enabled ]]; then
  ls -la /etc/nginx/modules-enabled/ | sed 's/^/   /'
  echo ""
  for f in /etc/nginx/modules-enabled/*.conf; do
    [[ -f "$f" ]] || continue
    so="$(grep -E 'load_module' "$f" 2>/dev/null | awk '{print $2}' | tr -d ';')"
    if [[ -n "$so" ]]; then
      if [[ -f "$so" ]]; then
        echo "   OK load_module: $so"
      else
        echo "   ROTO: $f → no existe $so"
        FAIL=$((FAIL+1))
      fi
    fi
  done
  if dpkg -l 'libnginx-mod-*' 'nginx-common' 2>/dev/null | grep -q '^ii'; then
    echo ""
    echo "   Paquetes Ubuntu NGINX instalados:"
    dpkg -l 'libnginx-mod-*' 'nginx-common' 2>/dev/null | awk '/^ii/{print "     "$2" "$3}' || true
    echo ""
    echo "   *** ADVERTENCIA ***"
    echo "   El script nginx-rift-upgrade-vm.sh instala nginx OFICIAL (nginx.org)."
    echo "   Eso ELIMINA libnginx-mod-* (brotli, geoip, stream, etc.)."
    echo "   Tras el upgrade, nginx -t puede fallar si los vhosts usan brotli."
    echo "   En star.it se arregló restaurando nginx.conf del backup;"
    echo "   en hosts CON brotli hace falta plan (ver LEEME-VM-PRODUCCION.txt)."
    WARN=$((WARN+1))
  fi
else
  echo "   Sin modules-enabled (menor riesgo con nginx.org)."
fi
echo ""

echo "6. Certificados referenciados en vhosts activos"
missing=0
while IFS= read -r cert; do
  [[ -n "$cert" && -f "$cert" ]] || { echo "   FALTA: $cert"; missing=$((missing+1)); }
done < <(grep -Rh 'ssl_certificate ' /etc/nginx/sites-enabled/ 2>/dev/null \
  | grep -v '#' | awk '{print $2}' | tr -d ';' | sort -u)
if [[ $missing -eq 0 ]]; then
  echo "   OK: rutas ssl_certificate en sites-enabled existen en disco."
else
  echo "   $missing certificado(s) no encontrado(s) — revisar Let's Encrypt / rutas."
  WARN=$((WARN+1))
fi
echo ""

echo "7. PHP-FPM (si aplica)"
if ls /var/run/php/php*-fpm.sock /run/php/php*-fpm.sock &>/dev/null; then
  ls -la /var/run/php/*.sock /run/php/*.sock 2>/dev/null | sed 's/^/   /'
  NGX_USER="$(grep -E '^\s*user\s' /etc/nginx/nginx.conf | awk '{print $2}' | tr -d ';' | head -1)"
  echo "   user nginx.conf: ${NGX_USER:-?(sin directiva)}"
  echo "   Tras nginx.org suele hacer falta user www-data; (star_it lo resolvió con backup nginx.conf)."
else
  echo "   Sin sockets PHP visibles (puede ser solo proxy estático)."
fi
echo ""

echo "8. Espacio para backup"
df -h /etc /var | sed 's/^/   /'
echo ""

echo "================================================================================"
if [[ $FAIL -gt 0 ]]; then
  echo " RESULTADO=PREFLIGHT_FALLO — corregir antes de upgrade."
  exit 1
elif [[ $WARN -gt 0 ]]; then
  echo " RESULTADO=PREFLIGHT_AVISO — se puede planificar upgrade en ventana;"
  echo " leer LEEME-VM-PRODUCCION.txt y ejecutar upgrade con --safe."
  exit 2
else
  echo " RESULTADO=PREFLIGHT_OK"
  exit 0
fi
