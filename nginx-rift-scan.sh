#!/usr/bin/env bash
# nginx-rift-scan.sh — Detector CVE-2026-42945 (NGINX Rift)
set -uo pipefail

FIXED_STABLE="1.30.1"
FIXED_MAINLINE="1.31.0"
VULN_MIN="0.6.27"
VULN_MAX="1.30.0"
SSH_USER=""
SSH_KEY=""
SSH_OPTS=("-o" "ConnectTimeout=5" "-o" "BatchMode=yes" "-o" "StrictHostKeyChecking=accept-new")
HOSTS=()
HOSTS_FILE=""
CSV_OUT=""

if [[ -t 1 ]]; then
  RED=$'\e[31m'; YEL=$'\e[33m'; GRN=$'\e[32m'; BLD=$'\e[1m'; RST=$'\e[0m'
else
  RED=""; YEL=""; GRN=""; BLD=""; RST=""
fi

usage() {
  cat <<EOF
nginx-rift-scan.sh — CVE-2026-42945
  $0 [-h HOST]... [-f HOSTS_FILE] [-u USER] [-i KEY] [-c CSV_OUT]
EOF
  exit 1
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    -h) HOSTS+=("$2"); shift 2 ;;
    -f) HOSTS_FILE="$2"; shift 2 ;;
    -u) SSH_USER="$2"; shift 2 ;;
    -i) SSH_KEY="$2"; shift 2 ;;
    -c) CSV_OUT="$2"; shift 2 ;;
    --help|-\?) usage ;;
    *) echo "Argumento desconocido: $1" >&2; usage ;;
  esac
done

if [[ -n "$HOSTS_FILE" ]]; then
  [[ -r "$HOSTS_FILE" ]] || { echo "No puedo leer $HOSTS_FILE" >&2; exit 1; }
  while IFS= read -r line; do
    line="${line%%#*}"
    line="$(echo -n "$line" | tr -d '[:space:]')"
    [[ -n "$line" ]] && HOSTS+=("$line")
  done < "$HOSTS_FILE"
fi
[[ ${#HOSTS[@]} -eq 0 ]] && HOSTS=("localhost")

version_in_vuln_range() {
  local v="$1"
  [[ -z "$v" || "$v" == "unknown" ]] && return 2
  local lower upper
  lower="$(printf '%s\n%s\n' "$VULN_MIN" "$v" | sort -V | head -n1)"
  [[ "$lower" != "$VULN_MIN" ]] && return 1
  upper="$(printf '%s\n%s\n' "$v" "$VULN_MAX" | sort -V | tail -n1)"
  [[ "$upper" != "$VULN_MAX" ]] && return 1
  return 0
}

build_ssh_cmd() {
  local host="$1" -a cmd=("ssh")
  [[ -n "$SSH_KEY" ]] && cmd+=("-i" "$SSH_KEY")
  cmd+=("${SSH_OPTS[@]}")
  [[ -n "$SSH_USER" ]] && cmd+=("${SSH_USER}@${host}") || cmd+=("$host")
  printf '%s\n' "${cmd[@]}"
}

run_on_host() {
  local host="$1" script="$2"
  if [[ "$host" == "localhost" || "$host" == "127.0.0.1" ]]; then
    bash -c "$script"
  else
    local -a ssh_cmd
    mapfile -t ssh_cmd < <(build_ssh_cmd "$host")
    "${ssh_cmd[@]}" "bash -s" <<< "$script"
  fi
}

read -r -d '' REMOTE_SCRIPT <<'EOSCRIPT' || true
set -uo pipefail
NGX_VERSION="unknown"
command -v nginx >/dev/null 2>&1 && NGX_VERSION="$(nginx -v 2>&1 | awk -F/ '{print $2}' | awk '{print $1}')"
CFG_DUMP=""
if command -v nginx >/dev/null 2>&1; then
  if out="$(nginx -T 2>/dev/null)" && [[ -n "$out" ]]; then CFG_DUMP="$out"
  elif command -v sudo >/dev/null 2>&1 && out="$(sudo -n nginx -T 2>/dev/null)" && [[ -n "$out" ]]; then CFG_DUMP="$out"
  fi
fi
VULN_MATCHES=0
VULN_LINES=""
if [[ -n "$CFG_DUMP" ]]; then
  while IFS= read -r line; do
    [[ -z "$line" ]] && continue
    VULN_MATCHES=$((VULN_MATCHES+1))
    VULN_LINES+="${line}"$'\n'
  done < <(echo "$CFG_DUMP" | grep -nE '^[[:space:]]*rewrite[[:space:]]+.*\$[0-9].*\?')
fi
ASLR="unknown"
[[ -r /proc/sys/kernel/randomize_va_space ]] && ASLR="$(cat /proc/sys/kernel/randomize_va_space)"
echo "VERSION|${NGX_VERSION}"
echo "CFG_LOADED|$([[ -n "$CFG_DUMP" ]] && echo yes || echo no)"
echo "VULN_MATCHES|${VULN_MATCHES}"
echo "ASLR|${ASLR}"
[[ -n "$VULN_LINES" ]] && { echo "VULN_LINES_BEGIN"; echo "$VULN_LINES"; echo "VULN_LINES_END"; }
EOSCRIPT

echo
echo "${BLD}=== Scanner CVE-2026-42945 (NGINX Rift) ===${RST}"
echo "Corregido: stable ${FIXED_STABLE}, mainline ${FIXED_MAINLINE} | Vulnerable: ${VULN_MIN} – ${VULN_MAX}"
echo "Hosts: ${#HOSTS[@]}"
echo
[[ -n "$CSV_OUT" ]] && echo "host,nginx_version,vuln_range,config_loaded,pattern_matches,aslr,risk" > "$CSV_OUT"

TOTAL_AT_RISK=0 TOTAL_PATCHED=0 TOTAL_NOT_INSTALLED=0 TOTAL_UNREACHABLE=0

for host in "${HOSTS[@]}"; do
  echo "${BLD}--- ${host} ---${RST}"
  OUT="$(run_on_host "$host" "$REMOTE_SCRIPT" 2>&1)"; RC=$?
  if [[ $RC -ne 0 && -z "$OUT" ]]; then
    echo "  ${RED}[ERROR] No alcanzable.${RST}"
    TOTAL_UNREACHABLE=$((TOTAL_UNREACHABLE+1))
    [[ -n "$CSV_OUT" ]] && echo "$host,unreachable,unknown,unknown,unknown,unknown,UNKNOWN" >> "$CSV_OUT"
    echo; continue
  fi
  VERSION="$(echo "$OUT" | awk -F'|' '/^VERSION\|/{print $2; exit}')"
  CFG_LOADED="$(echo "$OUT" | awk -F'|' '/^CFG_LOADED\|/{print $2; exit}')"
  MATCHES="$(echo "$OUT" | awk -F'|' '/^VULN_MATCHES\|/{print $2; exit}')"
  ASLR="$(echo "$OUT" | awk -F'|' '/^ASLR\|/{print $2; exit}')"
  VULN_LINES="$(echo "$OUT" | sed -n '/^VULN_LINES_BEGIN$/,/^VULN_LINES_END$/p' | sed '1d;$d')"
  MATCHES="${MATCHES:-0}"
  VULN_RANGE="no"
  if [[ -z "$VERSION" || "$VERSION" == "unknown" ]]; then VULN_RANGE="unknown"
  elif version_in_vuln_range "$VERSION"; then VULN_RANGE="yes"; fi
  RISK="LOW"
  if [[ "$VULN_RANGE" == "yes" && "$MATCHES" -gt 0 ]]; then
    [[ "$ASLR" == "0" ]] && RISK="CRITICAL" || RISK="HIGH"
  elif [[ "$VULN_RANGE" == "yes" ]]; then RISK="MEDIUM"
  elif [[ "$VULN_RANGE" == "unknown" ]]; then RISK="UNKNOWN"; fi
  echo "  NGINX version : ${VERSION:-unknown}"
  case "$VULN_RANGE" in
    yes) echo "  En rango vuln : ${RED}SÍ${RST}"; TOTAL_AT_RISK=$((TOTAL_AT_RISK+1)) ;;
    no)
      if [[ "$VERSION" == "unknown" ]]; then
        echo "  En rango vuln : ${YEL}N/A${RST}"; TOTAL_NOT_INSTALLED=$((TOTAL_NOT_INSTALLED+1))
      else echo "  En rango vuln : ${GRN}NO${RST}"; TOTAL_PATCHED=$((TOTAL_PATCHED+1)); fi ;;
    *) echo "  En rango vuln : ${YEL}DESCONOCIDO${RST}" ;;
  esac
  echo "  Config cargada: ${CFG_LOADED:-no}"
  if [[ "$MATCHES" -gt 0 ]]; then
    echo "  Patrón rewrite: ${RED}${MATCHES} línea(s)${RST}"
    echo "${VULN_LINES}" | sed 's/^/      /'
  else echo "  Patrón rewrite: ${GRN}0${RST}"; fi
  case "$ASLR" in
    2) echo "  ASLR: ${GRN}2${RST}" ;; 1) echo "  ASLR: ${YEL}1${RST}" ;;
    0) echo "  ASLR: ${RED}0${RST}" ;; *) echo "  ASLR: ${YEL}desconocido${RST}" ;;
  esac
  case "$RISK" in
    CRITICAL) echo "  Riesgo: ${RED}${BLD}CRÍTICO${RST}" ;;
    HIGH) echo "  Riesgo: ${RED}ALTO${RST}" ;;
    MEDIUM) echo "  Riesgo: ${YEL}MEDIO${RST}" ;;
    LOW) echo "  Riesgo: ${GRN}BAJO${RST}" ;;
    *) echo "  Riesgo: ${YEL}DESCONOCIDO${RST}" ;;
  esac
  [[ -n "$CSV_OUT" ]] && echo "$host,${VERSION:-unknown},$VULN_RANGE,${CFG_LOADED:-no},$MATCHES,${ASLR:-unknown},$RISK" >> "$CSV_OUT"
  echo
done

echo "${BLD}=== Resumen ===${RST}"
echo "  En riesgo: ${TOTAL_AT_RISK} | Parcheados: ${TOTAL_PATCHED} | Sin NGINX: ${TOTAL_NOT_INSTALLED} | Inalcanzables: ${TOTAL_UNREACHABLE}"
[[ -n "$CSV_OUT" ]] && echo "  CSV: ${CSV_OUT}"
[[ $TOTAL_AT_RISK -gt 0 ]] && { echo "${YEL}Actualizar a ${FIXED_STABLE} o ${FIXED_MAINLINE} y restart nginx.${RST}"; exit 2; }
exit 0
