#!/usr/bin/env bash
# Orquestador: ejecutar desde máquina con SSH a las VMs Linux
# Uso:
#   sed -i 's/\r$//' *.sh && chmod +x *.sh
#   ./run-on-vms.sh -f hosts.txt -u sysadmin -i ~/.ssh/id_rsa [scan|mitigate|patch|verify|all]
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

PHASE="${1:-scan}"
shift || true
SSH_ARGS=()
while [[ $# -gt 0 ]]; do
  case "$1" in
    scan|mitigate|patch|verify|all) PHASE="$1"; shift ;;
    *) SSH_ARGS+=("$1"); shift ;;
  esac
done

for f in nginx-rift-scan.sh nginx-rift-mitigate.sh nginx-rift-patch.sh nginx-rift-verify.sh; do
  [[ -f "$f" ]] && sed -i 's/\r$//' "$f" 2>/dev/null || true
  chmod +x "$f" 2>/dev/null || true
done

case "$PHASE" in
  scan)
    ./nginx-rift-scan.sh "${SSH_ARGS[@]}" -c reporte-rift-pre.csv
    ;;
  mitigate)
    ./nginx-rift-mitigate.sh "${SSH_ARGS[@]}" --apply-aslr
    echo "Revisar rewrite-mitigation-example.conf y aplicar capturas nombradas en cada host CRITICAL/HIGH."
    ;;
  patch)
    echo "Parcheo: copiar nginx-rift-patch.sh a cada VM y ejecutar con sudo, o:"
    echo "  ssh user@host 'bash -s' < nginx-rift-patch.sh"
    read -r -p "¿Ejecutar patch vía SSH en hosts de -f? [y/N] " ans
    [[ "${ans,,}" == "y" ]] || exit 0
    HOSTS_FILE="hosts.txt"
    for a in "${SSH_ARGS[@]}"; do [[ "$a" == "-f" ]] && HOSTS_FILE="${SSH_ARGS[$((${#SSH_ARGS[@]}+1))]}"; done
    while IFS= read -r h; do
      h="${h%%#*}"; h="$(echo -n "$h" | tr -d '[:space:]')"
      [[ -z "$h" || "$h" == "localhost" ]] && continue
      echo "=== patch $h ==="
      # shellcheck disable=SC2086
      ssh "${SSH_ARGS[@]/#-f/-X}" "$h" 'bash -s' < nginx-rift-patch.sh || echo "Fallo en $h"
    done < "${HOSTS_FILE:-hosts.txt}"
    ;;
  verify)
    ./nginx-rift-verify.sh "${SSH_ARGS[@]}" -c reporte-rift-post.csv
    ;;
  all)
    "$0" scan "${SSH_ARGS[@]}"
    "$0" mitigate "${SSH_ARGS[@]}"
    echo "Ejecutar patch en ventana de mantenimiento (staging → prod), luego:"
    "$0" verify "${SSH_ARGS[@]}"
    ;;
  *)
    echo "Uso: $0 [scan|mitigate|patch|verify|all] [-f hosts.txt] [-u USER] [-i KEY]"
    exit 1
    ;;
esac
