#!/usr/bin/env bash
# Orquestador simplificado — sin SSH batch
set -uo pipefail
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$DIR"

phase="${1:-help}"

case "$phase" in
  external)
    if command -v docker >/dev/null 2>&1 && [[ -f docker-compose.yml ]]; then
      echo "[*] Escaneo externo vía Docker..."
      docker compose run --rm scanner
    else
      echo "[*] Escaneo externo local..."
      chmod +x nginx-rift-scan-external.sh 2>/dev/null || true
      ./nginx-rift-scan-external.sh -f domains.txt -c reporte-externo.csv
    fi
    ;;
  help-vm|vm)
    cat "$DIR/vm-local/LEEME-KUDU.txt"
    ;;
  help|*)
    cat <<EOF
Uso: $0 [external|help-vm]

  external  — Escanear domains.txt → reporte-externo.csv
  help-vm   — Instrucciones para pruebas dentro de la VM (KUDU)

Flujo: external → filtrar CSV → vm-local/ en KUDU
EOF
    ;;
esac
