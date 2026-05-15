#!/usr/bin/env bash
# Mitigación local — ejecutar en VM/KUDU
set -uo pipefail

APPLY_ASLR=0
[[ "${1:-}" == "--apply-aslr" ]] && APPLY_ASLR=1

echo "=== Mitigación CVE-2026-42945 (local) ==="

if [[ -r /proc/sys/kernel/randomize_va_space ]]; then
  aslr="$(cat /proc/sys/kernel/randomize_va_space)"
  echo "ASLR actual: $aslr"
  if [[ "$aslr" == "0" ]]; then
    if [[ "$APPLY_ASLR" -eq 1 ]] && command -v sudo >/dev/null 2>&1; then
      sudo sysctl -w kernel.randomize_va_space=2 2>/dev/null && echo "ASLR=2 aplicado"
      echo 'kernel.randomize_va_space = 2' | sudo tee /etc/sysctl.d/99-aslr.conf >/dev/null 2>&1 || true
    else
      echo "Recomendado: sudo sysctl -w kernel.randomize_va_space=2"
      echo "O ejecutar: $0 --apply-aslr"
    fi
  fi
else
  echo "ASLR: no disponible en este entorno"
fi

NGX=""
command -v nginx >/dev/null 2>&1 && NGX=nginx
[[ -z "$NGX" ]] && { echo "NGINX no en PATH."; exit 1; }

dump="$("$NGX" -T 2>/dev/null)" || dump="$(sudo -n "$NGX" -T 2>/dev/null)" || dump=""
if [[ -n "$dump" ]]; then
  n="$(echo "$dump" | grep -cE '^[[:space:]]*rewrite[[:space:]]+.*\$[0-9].*\?' || echo 0)"
  echo "Rewrites sospechosos: $n"
  echo "$dump" | grep -nE '^[[:space:]]*rewrite[[:space:]]+.*\$[0-9].*\?' | head -20
  echo ""
  echo "Migrar a capturas nombradas, ejemplo:"
  echo "  rewrite ^/x/(?<id>[0-9]+)/\$ /app?id=\$id&tab=1 last;"
  "$NGX" -t 2>/dev/null || sudo -n "$NGX" -t 2>/dev/null || echo "nginx -t: requiere permisos"
else
  echo "No se pudo leer nginx -T"
fi
echo "Tras editar config: nginx -t && nginx -s reload (o sudo)"
