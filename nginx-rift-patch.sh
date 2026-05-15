#!/usr/bin/env bash
# Parcheo NGINX a 1.30.1+ / 1.31.0+ — ejecutar en cada VM Linux (staging → prod)
# Uso: sudo ./nginx-rift-patch.sh [--dry-run]
set -uo pipefail

DRY_RUN=0
[[ "${1:-}" == "--dry-run" ]] && DRY_RUN=1

MIN_FIXED="1.30.1"

version_ge() {
  printf '%s\n%s\n' "$1" "$2" | sort -V | tail -n1 | grep -qxF "$2"
}

if ! command -v nginx >/dev/null 2>&1; then
  echo "NGINX no encontrado en PATH." >&2
  exit 1
fi

CUR="$(nginx -v 2>&1 | awk -F/ '{print $2}' | awk '{print $1}')"
echo "Versión actual: $CUR"

if version_ge "$CUR" "$MIN_FIXED"; then
  echo "Ya está en $CUR (>= $MIN_FIXED). Solo verificar restart si el binario cambió recientemente."
  exit 0
fi

if [[ $DRY_RUN -eq 1 ]]; then
  echo "[dry-run] Se actualizaría nginx y se haría systemctl restart nginx"
  exit 0
fi

if command -v apt-get >/dev/null 2>&1; then
  apt-get update -qq
  apt-get install -y --only-upgrade nginx
elif command -v dnf >/dev/null 2>&1; then
  dnf update -y nginx
elif command -v yum >/dev/null 2>&1; then
  yum update -y nginx
else
  echo "Gestor de paquetes no soportado. Instalar manualmente desde https://nginx.org/en/linux_packages.html" >&2
  exit 1
fi

NEW="$(nginx -v 2>&1 | awk -F/ '{print $2}' | awk '{print $1}')"
echo "Versión tras update: $NEW"

if ! version_ge "$NEW" "$MIN_FIXED"; then
  echo "ADVERTENCIA: repositorio del SO aún no ofrece >= $MIN_FIXED. Usar repo oficial nginx.org." >&2
  exit 1
fi

nginx -t
systemctl restart nginx
systemctl is-active --quiet nginx && echo "nginx activo tras restart." || { echo "nginx no activo" >&2; exit 1; }
