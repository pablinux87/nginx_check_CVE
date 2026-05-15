#!/usr/bin/env bash
# NGINX dentro de contenedores Docker en el host actual
# Uso: ./nginx-rift-docker-scan.sh [-c reporte-docker.csv]
set -uo pipefail

CSV_OUT=""
[[ "${1:-}" == "-c" && -n "${2:-}" ]] && CSV_OUT="$2"

command -v docker >/dev/null 2>&1 || { echo "docker no encontrado" >&2; exit 1; }

[[ -n "$CSV_OUT" ]] && echo "container,nginx_version,vuln_range,pattern_matches,aslr,risk" > "$CSV_OUT"

VULN_MIN="0.6.27"
VULN_MAX="1.30.0"

version_in_range() {
  local v="$1"
  local lower upper
  lower="$(printf '%s\n%s\n' "$VULN_MIN" "$v" | sort -V | head -n1)"
  [[ "$lower" != "$VULN_MIN" ]] && return 1
  upper="$(printf '%s\n%s\n' "$v" "$VULN_MAX" | sort -V | tail -n1)"
  [[ "$upper" != "$VULN_MAX" ]] && return 1
}

while read -r cid name; do
  [[ -z "$cid" ]] && continue
  if ! docker exec "$cid" sh -c 'command -v nginx >/dev/null 2>&1' 2>/dev/null; then
    continue
  fi
  ver="$(docker exec "$cid" nginx -v 2>&1 | awk -F/ '{print $2}' | awk '{print $1}')"
  matches="$(docker exec "$cid" sh -c 'nginx -T 2>/dev/null' | grep -cE '^[[:space:]]*rewrite[[:space:]]+.*\$[0-9].*\?' || echo 0)"
  vr="no"
  version_in_range "$ver" 2>/dev/null && vr="yes" || true
  risk="LOW"
  [[ "$vr" == "yes" && "$matches" -gt 0 ]] && risk="HIGH"
  [[ "$vr" == "yes" && "$matches" -eq 0 ]] && risk="MEDIUM"
  echo "--- $name ($cid) ---"
  echo "  version: $ver | vuln: $vr | pattern: $matches | risk: $risk"
  [[ -n "$CSV_OUT" ]] && echo "$name,$ver,$vr,$matches,unknown,$risk" >> "$CSV_OUT"
done < <(docker ps --format '{{.ID}} {{.Names}}')
