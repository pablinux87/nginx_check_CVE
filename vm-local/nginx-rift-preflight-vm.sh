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

nginx_modules_path() {
  local p
  p="$(nginx -V 2>&1 | tr ' ' '\n' | sed -n 's/^--modules-path=//p' | head -1)"
  [[ -n "$p" ]] && echo "$p" && return
  for p in /usr/lib/nginx/modules /usr/share/nginx/modules; do
    [[ -d "$p" ]] && echo "$p" && return
  done
  echo "/usr/lib/nginx/modules"
}

resolve_module_so() {
  local so="$1" moddir="$2"
  [[ -f "$so" ]] && echo "$so" && return 0
  if [[ "$so" == modules/* ]]; then
    [[ -f "$moddir/${so#modules/}" ]] && echo "$moddir/${so#modules/}" && return 0
  fi
  local base="${so##*/}"
  [[ -f "$moddir/$base" ]] && echo "$moddir/$base" && return 0
  return 1
}

echo "================================================================================"
echo " PREFLIGHT VM — CVE NGINX Rift ($(hostname -f 2>/dev/null || hostname))"
echo " $(date -u '+%Y-%m-%d %H:%M:%S UTC')"
echo "================================================================================"
echo ""

VER="$(nginx -v 2>&1 | awk -F/ '{print $2}' | awk '{print $1}')"
NGX_DEB="$(dpkg -l nginx 2>/dev/null | awk '/^ii/{print $3}' || true)"
echo "1. Versión actual: $VER"
[[ -n "$NGX_DEB" ]] && echo "   Paquete nginx: $NGX_DEB"
if echo "$NGX_DEB" | grep -qi sury; then
  echo "   Origen: PPA Ondřej Surý (deb.sury.org) — NO usar nginx.org sin plan."
  echo "   Preferir: apt upgrade nginx cuando Sury publique >= 1.30.1"
  echo "   Comprobar: apt-cache policy nginx | head -8"
  WARN=$((WARN+1))
fi
if version_ge "$VER" "1.30.1"; then
  echo "   OK: ya parcheado para el CVE."
else
  echo "   PENDIENTE: hace falta >= 1.30.1"
  WARN=$((WARN+1))
fi
echo ""

echo "2. nginx -t (autoridad: si OK, los módulos cargan)"
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
  echo ""
  echo "   server_name por vhost:"
  grep -Rh '^\s*server_name' /etc/nginx/sites-enabled/ 2>/dev/null | sed 's/^/     /' || true
else
  echo "   AVISO: no hay sites-enabled."
  WARN=$((WARN+1))
fi
echo ""

echo "4. includes en nginx.conf"
grep -nE 'include.*/(sites-enabled|conf\.d|modules-enabled)' /etc/nginx/nginx.conf 2>/dev/null | sed 's/^/   /' || true
echo ""

MODDIR="$(nginx_modules_path)"
echo "5. Módulos dinámicos (modules-path: $MODDIR)"
if [[ -d /etc/nginx/modules-enabled ]]; then
  mod_broken=0
  for f in /etc/nginx/modules-enabled/*.conf; do
    [[ -f "$f" ]] || continue
    [[ "$f" == *.removed ]] && continue
    while IFS= read -r line; do
      so="$(echo "$line" | awk '{print $2}' | tr -d ';')"
      [[ -z "$so" ]] && continue
      if resolved="$(resolve_module_so "$so" "$MODDIR")"; then
        echo "   OK $f → $(basename "$resolved")"
      else
        echo "   ROTO $f → $so (no en $MODDIR)"
        mod_broken=$((mod_broken+1))
      fi
    done < <(grep -E '^\s*load_module' "$f" 2>/dev/null || true)
  done
  if [[ $mod_broken -gt 0 ]] && nginx -t &>/dev/null; then
    echo "   NOTA: nginx -t OK pero rutas relativas no resueltas en preflight (falso positivo corregido)."
    mod_broken=0
  elif [[ $mod_broken -gt 0 ]]; then
    FAIL=$((FAIL+1))
  fi
  if dpkg -l 'libnginx-mod-*' 2>/dev/null | grep -q '^ii'; then
    echo ""
    echo "   Paquetes libnginx-mod-* (Sury/Ubuntu):"
    dpkg -l 'libnginx-mod-*' 'nginx-common' 2>/dev/null | awk '/^ii/{print "     "$2" "$3}' || true
    echo ""
    echo "   *** Si usás nginx-rift-upgrade-vm.sh (nginx.org) ***"
    echo "   Se eliminan estos paquetes y puede romper brotli/geoip."
    echo "   En multiplica: mejor apt desde Sury cuando haya 1.30.1+."
    WARN=$((WARN+1))
  fi
else
  echo "   Sin modules-enabled."
fi
echo ""

echo "6. Certificados (ssl_certificate en sites-enabled)"
missing=0
while IFS= read -r cert; do
  [[ -n "$cert" && -f "$cert" ]] || { echo "   FALTA: $cert"; missing=$((missing+1)); }
done < <(grep -Rh 'ssl_certificate ' /etc/nginx/sites-enabled/ 2>/dev/null \
  | grep -v '#' | awk '{print $2}' | tr -d ';' | sort -u)
[[ $missing -eq 0 ]] && echo "   OK: certificados referenciados existen." || WARN=$((WARN+1))
echo ""

echo "7. PHP-FPM"
if ls /var/run/php/php*-fpm.sock /run/php/php*-fpm.sock &>/dev/null; then
  ls -la /var/run/php/*.sock /run/php/*.sock 2>/dev/null | sed 's/^/   /'
  NGX_USER="$(grep -E '^\s*user\s' /etc/nginx/nginx.conf | awk '{print $2}' | tr -d ';' | head -1)"
  SOCK_USER="$(stat -c '%U' /run/php/php8.0-fpm.sock 2>/dev/null || stat -c '%U' /var/run/php/php-fpm.sock 2>/dev/null || echo '?')"
  echo "   user nginx.conf: ${NGX_USER:-?}"
  echo "   dueño socket FPM: $SOCK_USER"
  if [[ -n "${NGX_USER:-}" && "$NGX_USER" != "$SOCK_USER" && "$SOCK_USER" != "?" ]]; then
    echo "   AVISO: user NGINX y socket FPM distintos → 502 si se cambia a www-data."
    WARN=$((WARN+1))
  else
    echo "   OK: mantener user=$NGX_USER tras cualquier upgrade (no usar www-data a ciegas)."
  fi
else
  echo "   Sin sockets PHP (puede ser solo estático/proxy)."
fi
echo ""

echo "8. Espacio disco"
df -h / | tail -1 | sed 's/^/   /'
echo ""

echo "9. Versión disponible en apt (sin instalar)"
if command -v apt-cache &>/dev/null; then
  apt-get update -qq 2>/dev/null || true
  echo "   Candidatos nginx:"
  apt-cache policy nginx 2>/dev/null | sed 's/^/   /' | head -12 || true
  CAND="$(apt-cache policy nginx 2>/dev/null | awk '/Candidate:/{print $2}')"
  if [[ -n "$CAND" && "$CAND" != "(none)" ]] && version_ge "$CAND" "1.30.1"; then
    echo "   >>> APT tiene >= 1.30.1: usar upgrade Sury/Ubuntu (ver nginx-rift-upgrade-apt.sh)"
  elif echo "$NGX_DEB" | grep -qi sury; then
    echo "   >>> Sury aún no ofrece >= 1.30.1 en Candidate; valorar nginx.org o esperar PPA."
    WARN=$((WARN+1))
  fi
fi
echo ""

echo "================================================================================"
if [[ $FAIL -gt 0 ]]; then
  echo " RESULTADO=PREFLIGHT_FALLO — corregir nginx -t / módulos antes de upgrade."
  exit 1
elif [[ $WARN -gt 0 ]]; then
  echo " RESULTADO=PREFLIGHT_AVISO — listo para planificar (snapshot + ventana)."
  echo " Leer LEEME-VM-PRODUCCION.txt (Sury vs nginx.org)."
  exit 2
else
  echo " RESULTADO=PREFLIGHT_OK"
  exit 0
fi
