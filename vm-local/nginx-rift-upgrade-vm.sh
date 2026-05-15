#!/usr/bin/env bash
# Upgrade NGINX en VM propia (Debian/Ubuntu) hacia >= 1.30.1 — CVE-2026-42945
# Uso: sudo ./nginx-rift-upgrade-vm.sh [--dry-run]
set -uo pipefail

MIN_FIXED="1.30.1"
DRY=0
[[ "${1:-}" == "--dry-run" ]] && DRY=1

[[ "$(id -u)" -eq 0 ]] || { echo "Ejecutar con sudo." >&2; exit 1; }

CUR="$(nginx -v 2>&1 | awk -F/ '{print $2}' | awk '{print $1}')"
echo "Versión actual: $CUR"

version_ge() {
  [[ "$(printf '%s\n%s\n' "$2" "$1" | sort -V | tail -n1)" == "$1" ]]
}

if version_ge "$CUR" "$MIN_FIXED"; then
  echo "Ya >= $MIN_FIXED. Nada que hacer."
  exit 0
fi

echo "=== Backup /etc/nginx ==="
BK="/etc/nginx.backup.$(date +%Y%m%d%H%M%S)"
if [[ $DRY -eq 1 ]]; then
  echo "[dry-run] cp -a /etc/nginx $BK"
else
  cp -a /etc/nginx "$BK"
  echo "Backup en: $BK"
fi

if [[ ! -f /etc/os-release ]]; then
  echo "SO no soportado por este script." >&2
  exit 1
fi
# shellcheck source=/dev/null
. /etc/os-release

install_nginx_org_debian() {
  apt-get update -qq
  apt-get install -y curl gnupg2 ca-certificates lsb-release debian-archive-keyring

  curl -fsSL https://nginx.org/keys/nginx_signing.key | gpg --dearmor -o /usr/share/keyrings/nginx-archive-keyring.gpg

  CODENAME="${VERSION_CODENAME:-bookworm}"
  echo "deb [signed-by=/usr/share/keyrings/nginx-archive-keyring.gpg] https://nginx.org/packages/debian ${CODENAME} nginx" \
    > /etc/apt/sources.list.d/nginx.list

  apt-get update -qq
  apt-get install -y --only-upgrade nginx
}

install_nginx_org_ubuntu() {
  apt-get update -qq
  apt-get install -y curl gnupg2 ca-certificates lsb-release ubuntu-keyring

  curl -fsSL https://nginx.org/keys/nginx_signing.key | gpg --dearmor -o /usr/share/keyrings/nginx-archive-keyring.gpg

  CODENAME="${VERSION_CODENAME:-jammy}"
  echo "deb [signed-by=/usr/share/keyrings/nginx-archive-keyring.gpg] https://nginx.org/packages/ubuntu ${CODENAME} nginx" \
    > /etc/apt/sources.list.d/nginx.list

  apt-get update -qq
  apt-get install -y --only-upgrade nginx
}

if [[ $DRY -eq 1 ]]; then
  echo "[dry-run] Instalaría repo nginx.org para $ID y upgrade nginx"
  exit 0
fi

case "${ID:-}" in
  debian) install_nginx_org_debian ;;
  ubuntu) install_nginx_org_ubuntu ;;
  *)
    echo "SO: $ID — usar manual: https://nginx.org/en/linux_packages.html" >&2
    exit 1
    ;;
esac

NEW="$(nginx -v 2>&1 | awk -F/ '{print $2}' | awk '{print $1}')"
echo "Versión nueva: $NEW"

if ! version_ge "$NEW" "$MIN_FIXED"; then
  echo "ADVERTENCIA: sigue por debajo de $MIN_FIXED. Revisar repo." >&2
  exit 1
fi

echo "=== Restaurar includes de sitios (nginx.org no usa sites-enabled por defecto) ==="
NGX_CONF="/etc/nginx/nginx.conf"
if [[ -d /etc/nginx/sites-enabled ]] && ! grep -q 'sites-enabled' "$NGX_CONF" 2>/dev/null; then
  if grep -q 'include /etc/nginx/conf.d/\*\.conf;' "$NGX_CONF"; then
    sed -i '/include \/etc\/nginx\/conf.d\/\*\.conf;/a\    include /etc/nginx/sites-enabled/*;' "$NGX_CONF"
    echo "Añadido: include /etc/nginx/sites-enabled/*;"
  else
    echo "AVISO: editar $NGX_CONF y añadir: include /etc/nginx/sites-enabled/*;"
  fi
fi
if [[ -f /etc/nginx/conf.d/default.conf ]]; then
  mv /etc/nginx/conf.d/default.conf /etc/nginx/conf.d/default.conf.disabled-by-rift-upgrade 2>/dev/null || true
  echo "Desactivado conf.d/default.conf (página Welcome to nginx)."
fi

# nginx.org usa user nginx; PHP-FPM en Ubuntu expone el socket como www-data → 502
if [[ "${ID:-}" == "ubuntu" || "${ID:-}" == "debian" ]]; then
  if ls /var/run/php/php*-fpm.sock /run/php/php*-fpm.sock &>/dev/null; then
    if grep -qE '^\s*user\s+nginx\s*;' "$NGX_CONF" 2>/dev/null; then
      sed -i 's/^\s*user\s\+nginx\s*;/user www-data;/' "$NGX_CONF"
      echo "user nginx → www-data (acceso al socket PHP-FPM)."
    fi
  fi
  if [[ -d "$BK/snippets" ]] && [[ -f "$BK/snippets/fastcgi-php.conf" ]]; then
    cp -a "$BK/snippets/fastcgi-php.conf" /etc/nginx/snippets/fastcgi-php.conf 2>/dev/null || true
  fi
fi

echo "=== nginx -t ==="
nginx -t

echo "=== restart nginx ==="
systemctl restart nginx
systemctl is-active --quiet nginx && echo "nginx activo."

echo "Verificar: nginx -T | grep configuration.file"
echo "Ejecutar: ./nginx-rift-report.sh para verificar CVE."
