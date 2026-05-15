#!/usr/bin/env bash
# Mitigación inmediata CVE-2026-42945: ASLR + revisión config
# Uso: ./nginx-rift-mitigate.sh [-f hosts.txt] [-u USER] [-i KEY] [--apply-aslr]
set -uo pipefail

SSH_USER="" SSH_KEY="" HOSTS=() HOSTS_FILE="" APPLY_ASLR=0
SSH_OPTS=("-o" "ConnectTimeout=5" "-o" "BatchMode=yes" "-o" "StrictHostKeyChecking=accept-new")

while [[ $# -gt 0 ]]; do
  case "$1" in
    -f) HOSTS_FILE="$2"; shift 2 ;;
    -u) SSH_USER="$2"; shift 2 ;;
    -i) SSH_KEY="$2"; shift 2 ;;
    --apply-aslr) APPLY_ASLR=1; shift ;;
    -h) HOSTS+=("$2"); shift 2 ;;
    *) echo "Uso: $0 [-f hosts.txt] [-u USER] [-i KEY] [--apply-aslr]" >&2; exit 1 ;;
  esac
done

if [[ -n "$HOSTS_FILE" ]]; then
  while IFS= read -r line; do
    line="${line%%#*}"; line="$(echo -n "$line" | tr -d '[:space:]')"
    [[ -n "$line" ]] && HOSTS+=("$line")
  done < "$HOSTS_FILE"
fi
[[ ${#HOSTS[@]} -eq 0 ]] && HOSTS=("localhost")

run_on_host() {
  local host="$1" script="$2"
  if [[ "$host" == "localhost" || "$host" == "127.0.0.1" ]]; then
    APPLY_ASLR="$APPLY_ASLR" bash -c "$script"
  else
    local target="$host"
    [[ -n "$SSH_USER" ]] && target="${SSH_USER}@${host}"
    local -a s=("ssh" "${SSH_OPTS[@]}")
    [[ -n "$SSH_KEY" ]] && s+=("-i" "$SSH_KEY")
    "${s[@]}" "$target" "APPLY_ASLR=$APPLY_ASLR bash -s" <<< "$script"
  fi
}

read -r -d '' MIT_SCRIPT <<'EOSCRIPT' || true
set -uo pipefail
if [[ -r /proc/sys/kernel/randomize_va_space ]]; then
  aslr="$(cat /proc/sys/kernel/randomize_va_space)"
  echo "  ASLR actual: $aslr"
  if [[ "$aslr" == "0" && "${APPLY_ASLR:-0}" == "1" ]] && command -v sudo >/dev/null 2>&1; then
    sudo sysctl -w kernel.randomize_va_space=2 && echo "  ASLR aplicado en runtime"
    echo 'kernel.randomize_va_space = 2' | sudo tee /etc/sysctl.d/99-aslr.conf >/dev/null 2>&1 && \
      echo "  Persistido en /etc/sysctl.d/99-aslr.conf" || true
  elif [[ "$aslr" == "0" ]]; then
    echo "  ACCIÓN: ejecutar con --apply-aslr o: sudo sysctl -w kernel.randomize_va_space=2"
  fi
else
  echo "  ASLR: N/A (no Linux /proc)"
fi
if command -v nginx >/dev/null 2>&1; then
  dump="$(nginx -T 2>/dev/null)" || dump="$(sudo -n nginx -T 2>/dev/null)" || dump=""
  if [[ -n "$dump" ]]; then
    echo "$dump" | grep -nE '^[[:space:]]*rewrite[[:space:]]+.*\$[0-9].*\?' | head -20 | sed 's/^/  rewrite sospechoso: /'
    nginx -t 2>/dev/null || sudo -n nginx -t 2>/dev/null || echo "  nginx -t: no ejecutable sin permisos"
  else
    echo "  No se pudo volcar nginx -T"
  fi
else
  echo "  NGINX no instalado"
fi
EOSCRIPT

for host in "${HOSTS[@]}"; do
  echo "=== Mitigación: $host ==="
  run_on_host "$host" "$MIT_SCRIPT"
  echo
done
echo "Parchear a 1.30.1+ y usar capturas nombradas en rewrite sigue siendo obligatorio."
