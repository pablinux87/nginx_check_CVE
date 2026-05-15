#!/usr/bin/env bash
# Upgrade NGINX en VM propia (Debian/Ubuntu) hacia >= 1.30.1 — CVE-2026-42945
#
# Uso recomendado producción (multi-sitio / SSL):
#   sudo ./nginx-rift-preflight-vm.sh
#   sudo ./nginx-rift-upgrade-vm.sh --safe
#   sudo ./nginx-rift-postflight-vm.sh /etc/nginx.backup.TIMESTAMP
#
# Opciones:
#   --dry-run          Solo muestra acciones
#   --safe             Restaura nginx.conf + snippets del backup tras apt (RECOMENDADO)
#   --ack-module-risk  Permite upgrade aunque haya libnginx-mod-* (brotli puede romper nginx -t)
set -uo pipefail

MIN_FIXED="1.30.1"
DRY=0
SAFE=0
ACK_MODULES=0

for arg in "$@"; do
  case "$arg" in
    --dry-run) DRY=1 ;;
    --safe) SAFE=1 ;;
    --ack-module-risk) ACK_MODULES=1 ;;
    -h|--help)
      echo "Uso: sudo $0 [--dry-run] [--safe] [--ack-module-risk]"
      echo "Ver LEEME-VM-PRODUCCION.txt"
      exit 0
      ;;
    *) echo "Opción desconocida: $arg" >&2; exit 1 ;;
  esac
done

[[ "$(id -u)" -eq 0 ]] || { echo "Ejecutar con sudo." >&2; exit 1; }

version_ge() {
  [[ "$(printf '%s\n%s\n' "$2" "$1" | sort -V | tail -n1)" == "$1" ]]
}

CUR="$(nginx -v 2>&1 | awk -F/ '{print $2}' | awk '{print $1}')"
echo "Versión actual: $CUR"

if version_ge "$CUR" "$MIN_FIXED"; then
  echo "Ya >= $MIN_FIXED. Nada que hacer."
  exit 0
fi

if ! nginx -t &>/dev/null; then
  echo "ERROR: nginx -t falla AHORA. Corregir antes del upgrade." >&2
  nginx -t 2>&1 | sed 's/^/  /' >&2
  exit 1
fi

HAS_UBUNTU_MODS=0
if dpkg -l 'libnginx-mod-*' 2>/dev/null | grep -q '^ii'; then
  HAS_UBUNTU_MODS=1
  echo "Detectados paquetes libnginx-mod-* (brotli, geoip, etc.)."
  if [[ $ACK_MODULES -eq 0 && $DRY -eq 0 ]]; then
    echo "ERROR: en producción con módulos Ubuntu usar:" >&2
    echo "  sudo $0 --safe --ack-module-risk" >&2
    echo "  y leer LEEME-VM-PRODUCCION.txt (plan brotli)." >&2
    exit 1
  fi
fi

BK="/etc/nginx.backup.$(date +%Y%m%d%H%M%S)"
echo "=== Backup /etc/nginx ==="
if [[ $DRY -eq 1 ]]; then
  echo "[dry-run] cp -a /etc/nginx $BK"
else
  cp -a /etc/nginx "$BK"
  echo "Backup en: $BK"
  echo "$BK" > /root/.nginx-rift-last-backup 2>/dev/null || true
fi

if [[ ! -f /etc/os-release ]]; then
  echo "SO no soportado." >&2
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
  echo "[dry-run] Instalaría nginx.org; --safe restauraría nginx.conf y snippets/ desde $BK"
  [[ $HAS_UBUNTU_MODS -eq 1 ]] && echo "[dry-run] AVISO: se eliminarían libnginx-mod-*"
  exit 0
fi

case "${ID:-}" in
  debian) install_nginx_org_debian ;;
  ubuntu) install_nginx_org_ubuntu ;;
  *)
    echo "SO: $ID — https://nginx.org/en/linux_packages.html" >&2
    exit 1
    ;;
esac

NEW="$(nginx -v 2>&1 | awk -F/ '{print $2}' | awk '{print $1}')"
echo "Versión nueva: $NEW"

if ! version_ge "$NEW" "$MIN_FIXED"; then
  echo "ADVERTENCIA: sigue por debajo de $MIN_FIXED." >&2
  exit 1
fi

NGX_CONF="/etc/nginx/nginx.conf"

restore_tree() {
  local src="$1"
  echo "=== Restaurar desde backup ($src) ==="
  cp -a "$src/nginx.conf" "$NGX_CONF"
  echo "OK: nginx.conf"
  if [[ -d "$src/snippets" ]]; then
    cp -a "$src/snippets/." /etc/nginx/snippets/
    echo "OK: snippets/"
  fi
  # sites-available/enabled no los toca apt; no sobrescribir salvo emergencia
}

if [[ $SAFE -eq 1 ]]; then
  restore_tree "$BK"
else
  echo "=== Ajuste mínimo sin --safe (menos recomendado en producción) ==="
  if [[ -d /etc/nginx/sites-enabled ]] && ! grep -q 'sites-enabled' "$NGX_CONF" 2>/dev/null; then
    if grep -q 'include /etc/nginx/conf.d/\*\.conf;' "$NGX_CONF"; then
      sed -i '/include \/etc\/nginx\/conf.d\/\*\.conf;/a\    include /etc/nginx/sites-enabled/*;' "$NGX_CONF"
      echo "Añadido include sites-enabled"
    fi
  fi
  if grep -qE '^\s*user\s+nginx\s*;' "$NGX_CONF" 2>/dev/null; then
    sed -i 's/^\s*user\s\+nginx\s*;/user www-data;/' "$NGX_CONF"
    echo "user → www-data"
  fi
fi

if [[ -f /etc/nginx/conf.d/default.conf ]]; then
  mv /etc/nginx/conf.d/default.conf /etc/nginx/conf.d/default.conf.disabled-by-rift-upgrade 2>/dev/null || true
  echo "Desactivado conf.d/default.conf"
fi

# Módulos Ubuntu: tras nginx.org los .so desaparecen
if [[ $HAS_UBUNTU_MODS -eq 1 ]]; then
  MOD_BK="/etc/nginx/modules-enabled.backup-rift"
  if [[ -d /etc/nginx/modules-enabled ]]; then
    cp -a /etc/nginx/modules-enabled "$MOD_BK" 2>/dev/null || true
    broken=0
    for f in /etc/nginx/modules-enabled/*.conf; do
      [[ -f "$f" ]] || continue
      so="$(grep -E 'load_module' "$f" 2>/dev/null | awk '{print $2}' | tr -d ';')"
      [[ -n "$so" && ! -f "$so" ]] && broken=1
    done
    if [[ $broken -eq 1 ]]; then
      echo "AVISO: módulos Ubuntu rotos tras upgrade. Copia en $MOD_BK"
      echo "      Si nginx -t falla por brotli: ver LEEME-VM-PRODUCCION.txt"
    fi
  fi
fi

echo "=== nginx -t ==="
if nginx -t; then
  echo "=== reload nginx ==="
  systemctl restart nginx
  systemctl is-active --quiet nginx && echo "nginx activo."
else
  echo ""
  echo "FALLO nginx -t. Rollback de config recomendado:" >&2
  echo "  sudo cp $BK/nginx.conf $NGX_CONF" >&2
  echo "  sudo nginx -t && sudo systemctl reload nginx" >&2
  if [[ $HAS_UBUNTU_MODS -eq 1 ]]; then
    echo "  Si el error es 'brotli': deshabilitar /etc/nginx/modules-enabled/*brotli*" >&2
  fi
  exit 1
fi

echo ""
echo "Backup: $BK"
echo "Postflight: sudo ./nginx-rift-postflight-vm.sh $BK"
echo "Informe:    ./nginx-rift-report.sh -o /home/nginx-rift-reporte.txt"
