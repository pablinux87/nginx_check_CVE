#!/usr/bin/env bash
# Parcheo local NGINX >= 1.30.1 — requiere sudo en VM tradicional
set -uo pipefail

MIN_FIXED="1.30.1"
DRY_RUN=0
[[ "${1:-}" == "--dry-run" ]] && DRY_RUN=1

version_ge() {
  [[ "$(printf '%s\n%s\n' "$2" "$1" | sort -V | tail -n1)" == "$1" ]]
}

if ! command -v nginx >/dev/null 2>&1; then
  echo "NGINX no encontrado. En App Service el parche lo gestiona Azure/platform."
  exit 1
fi

CUR="$(nginx -v 2>&1 | awk -F/ '{print $2}' | awk '{print $1}')"
echo "Versión actual: $CUR"

if version_ge "$CUR" "$MIN_FIXED"; then
  echo "Ya >= $MIN_FIXED. Si actualizaste recientemente, reinicia nginx."
  exit 0
fi

if [[ $DRY_RUN -eq 1 ]]; then
  echo "[dry-run] apt/dnf upgrade nginx + systemctl restart nginx"
  exit 0
fi

if ! command -v sudo >/dev/null 2>&1; then
  echo "Sin sudo: no se puede parchear desde KUDU. Abrir ticket a infra con versión $CUR"
  exit 1
fi

if command -v apt-get >/dev/null 2>&1; then
  sudo apt-get update -qq && sudo apt-get install -y --only-upgrade nginx
elif command -v dnf >/dev/null 2>&1; then
  sudo dnf update -y nginx
else
  echo "Gestor no soportado. Ver https://nginx.org/en/linux_packages.html"
  exit 1
fi

NEW="$(nginx -v 2>&1 | awk -F/ '{print $2}' | awk '{print $1}')"
echo "Versión nueva: $NEW"
sudo nginx -t && sudo systemctl restart nginx
echo "Listo. Ejecutar ./nginx-rift-verify.sh"
