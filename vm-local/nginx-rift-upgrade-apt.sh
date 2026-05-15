#!/usr/bin/env bash
# Upgrade NGINX vía APT (Sury / Ubuntu) — mantiene brotli y módulos libnginx-mod-*
# Usar en multiplica ANTES que nginx.org si apt ofrece >= 1.30.1
# Uso: sudo ./nginx-rift-upgrade-apt.sh [--dry-run]
set -uo pipefail

MIN_FIXED="1.30.1"
DRY=0
[[ "${1:-}" == "--dry-run" ]] && DRY=1

[[ "$(id -u)" -eq 0 ]] || { echo "Ejecutar con sudo." >&2; exit 1; }

version_ge() {
  [[ "$(printf '%s\n%s\n' "$2" "$1" | sort -V | tail -n1)" == "$1" ]]
}

CUR="$(nginx -v 2>&1 | awk -F/ '{print $2}' | awk '{print $1}')"
echo "Versión actual: $CUR"

if version_ge "$CUR" "$MIN_FIXED"; then
  echo "Ya >= $MIN_FIXED."
  exit 0
fi

if ! nginx -t &>/dev/null; then
  echo "ERROR: nginx -t falla." >&2
  exit 1
fi

apt-get update -qq
CAND="$(apt-cache policy nginx 2>/dev/null | awk '/Candidate:/{print $2}')"
echo "Candidato apt nginx: ${CAND:-desconocido}"

if [[ -z "$CAND" || "$CAND" == "(none)" ]] || ! version_ge "$CAND" "$MIN_FIXED"; then
  echo "ERROR: apt no ofrece nginx >= $MIN_FIXED todavía." >&2
  echo "Opciones: esperar PPA Sury, o nginx-rift-upgrade-vm.sh --safe (pierde módulos)." >&2
  apt-cache policy nginx | head -15
  exit 1
fi

BK="/etc/nginx.backup.$(date +%Y%m%d%H%M%S)"
if [[ $DRY -eq 1 ]]; then
  echo "[dry-run] cp -a /etc/nginx $BK"
  echo "[dry-run] apt-get install --only-upgrade nginx libnginx-mod-*"
  exit 0
fi

cp -a /etc/nginx "$BK"
echo "Backup: $BK"

DEBIAN_FRONTEND=noninteractive apt-get install -y --only-upgrade nginx libnginx-mod-brotli \
  libnginx-mod-http-geoip libnginx-mod-http-image-filter libnginx-mod-http-xslt-filter \
  libnginx-mod-mail libnginx-mod-ssl-ct libnginx-mod-stream libnginx-mod-stream-geoip 2>/dev/null \
  || apt-get install -y --only-upgrade nginx 'libnginx-mod-*'

NEW="$(nginx -v 2>&1 | awk -F/ '{print $2}' | awk '{print $1}')"
echo "Versión nueva: $NEW"

if ! version_ge "$NEW" "$MIN_FIXED"; then
  echo "ERROR: tras apt sigue < $MIN_FIXED" >&2
  exit 1
fi

nginx -t && systemctl reload nginx
echo "OK. Postflight: ./nginx-rift-postflight-vm.sh $BK"
