#!/usr/bin/env bash
# Escaneo externo CVE-2026-42945 — solo pasivo, por dominio público
# Uso: ./nginx-rift-scan-external.sh -f domains.txt -c reporte-externo.csv [--poc-dir /opt/poc]
set -uo pipefail

VULN_MIN="0.6.27"
VULN_MAX="1.30.0"
MIN_FIXED="1.30.1"
DOMAINS_FILE=""
CSV_OUT="reporte-externo.csv"
POC_DIR="${POC_DIR:-}"
CURL_OPTS=(-sI -k --max-time 15 -L)

while [[ $# -gt 0 ]]; do
  case "$1" in
    -f) DOMAINS_FILE="$2"; shift 2 ;;
    -c) CSV_OUT="$2"; shift 2 ;;
    --poc-dir) POC_DIR="$2"; shift 2 ;;
    --help|-h)
      echo "Uso: $0 -f domains.txt [-c reporte-externo.csv] [--poc-dir /opt/poc]"
      exit 0 ;;
    *) echo "Argumento desconocido: $1" >&2; exit 1 ;;
  esac
done

[[ -n "$DOMAINS_FILE" && -r "$DOMAINS_FILE" ]] || { echo "Falta -f domains.txt legible" >&2; exit 1; }

if [[ -t 1 ]]; then
  RED=$'\e[31m'; YEL=$'\e[33m'; GRN=$'\e[32m'; BLD=$'\e[1m'; RST=$'\e[0m'
else
  RED=""; YEL=""; GRN=""; BLD=""; RST=""
fi

version_in_vuln_range() {
  local v="$1"
  [[ -z "$v" ]] && return 2
  local lower upper
  lower="$(printf '%s\n%s\n' "$VULN_MIN" "$v" | sort -V | head -n1)"
  [[ "$lower" != "$VULN_MIN" ]] && return 1
  upper="$(printf '%s\n%s\n' "$v" "$VULN_MAX" | sort -V | tail -n1)"
  [[ "$upper" != "$VULN_MAX" ]] && return 1
  return 0
}

version_ge_fixed() {
  local v="$1"
  [[ -z "$v" ]] && return 1
  [[ "$(printf '%s\n%s\n' "$MIN_FIXED" "$v" | sort -V | tail -n1)" == "$v" ]]
}

parse_url() {
  local input="$1"
  local u="${input%%#*}"
  u="$(echo -n "$u" | tr -d '[:space:]')"
  SCHEME="https"
  HOST=""
  PORT=""
  if [[ "$u" =~ ^https?:// ]]; then
    SCHEME="${u%%://*}"
    u="${u#*://}"
  fi
  u="${u%%/*}"
  u="${u%%\?*}"
  if [[ "$u" == *:* ]]; then
    HOST="${u%%:*}"
    PORT="${u##*:}"
  else
    HOST="$u"
    [[ "$SCHEME" == "https" ]] && PORT=443 || PORT=80
  fi
}

is_cdn_only() {
  local s="${1:-}" v="${2:-}"
  echo "$s" | grep -qi nginx && return 1
  echo "$s $v" | grep -qiE 'cloudflare|akamai|fastly|gcdn|bunny|amazons3' && return 0
  return 1
}

run_check_only() {
  local host="$1" port="$2"
  local poc="${POC_DIR}/nginx_rift_htb.py"
  [[ -f "$poc" ]] || return 2
  local out rc=0
  out="$(python3 "$poc" --target "$host" --port "$port" --check-only 2>&1)" || rc=$?
  CHECK_ONLY_RAW="$out"
  if echo "$out" | grep -qiE 'vulnerable|/api/.*detect|appears vulnerable|endpoint.*detect'; then
    return 0
  fi
  if echo "$out" | grep -qi 'not vulnerable\|Check complete'; then
    return 1
  fi
  return 2
}

DOMAINS=()
while IFS= read -r line; do
  line="${line%%#*}"
  line="$(echo -n "$line" | tr -d '[:space:]')"
  [[ -n "$line" ]] && DOMAINS+=("$line")
done < "$DOMAINS_FILE"

[[ ${#DOMAINS[@]} -gt 0 ]] || { echo "domains.txt vacío" >&2; exit 1; }

echo "${BLD}=== Escaneo externo CVE-2026-42945 (NGINX Rift) ===${RST}"
echo "Dominios: ${#DOMAINS[@]} | CSV: ${CSV_OUT}"
echo "domain,nginx_detected,version,http_code,server_header,via_header,check_only,veredicto,mensaje" > "$CSV_OUT"

N_PUEDE=0 N_NO=0 N_REVISAR=0 N_INDET=0

for domain in "${DOMAINS[@]}"; do
  echo
  echo "${BLD}--- ${domain} ---${RST}"
  parse_url "$domain"
  URL_FETCH="${SCHEME}://${HOST}"
  [[ "$PORT" != "443" && "$PORT" != "80" ]] && URL_FETCH="${URL_FETCH}:${PORT}"

  HEADERS="$(curl "${CURL_OPTS[@]}" "$URL_FETCH" 2>/dev/null || true)"
  HTTP_CODE="$(echo "$HEADERS" | awk 'toupper($1) ~ /^HTTP/ {print $2; exit}')"
  SERVER_HDR="$(echo "$HEADERS" | awk -F': ' 'tolower($1)=="server" {print $2; exit}' | tr -d '\r')"
  VIA_HDR="$(echo "$HEADERS" | awk -F': ' 'tolower($1)=="via" {print $2; exit}' | tr -d '\r')"

  NGINX_DETECTED="no"
  VERSION=""
  [[ "$SERVER_HDR" =~ [Nn][Gg][Ii][Nn][Xx] ]] && NGINX_DETECTED="yes"
  if [[ "$SERVER_HDR" =~ [Nn][Gg][Ii][Nn][Xx]/([0-9]+\.[0-9]+\.[0-9]+) ]]; then
    VERSION="${BASH_REMATCH[1]}"
  elif [[ "$SERVER_HDR" =~ [Nn][Gg][Ii][Nn][Xx]/([0-9]+\.[0-9]+) ]]; then
    VERSION="${BASH_REMATCH[1]}.0"
  fi

  CHECK_ONLY="skip"
  CHECK_ONLY_RAW=""
  if [[ -n "$POC_DIR" && -f "${POC_DIR}/nginx_rift_htb.py" ]]; then
    set +e
    run_check_only "$HOST" "$PORT"
    poc_rc=$?
    set +u
    set -uo pipefail
    if [[ $poc_rc -eq 0 ]]; then CHECK_ONLY="positivo"
    elif [[ $poc_rc -eq 1 ]]; then CHECK_ONLY="negativo"
    else CHECK_ONLY="error"
    fi
  fi

  VEREDICTO="INDETERMINADO"
  MENSAJE="No se pudo determinar con certeza; validar en la VM (KUDU)."

  if is_cdn_only "$SERVER_HDR" "$VIA_HDR" && [[ "$NGINX_DETECTED" == "no" ]]; then
    VEREDICTO="INDETERMINADO"
    MENSAJE="CDN/proxy delante sin NGINX visible; revisar origen en la VM si aplica."
    N_INDET=$((N_INDET+1))
  elif [[ -n "$VERSION" ]] && version_ge_fixed "$VERSION"; then
    VEREDICTO="NO_PARECE_VULNERABLE"
    MENSAJE="Según headers públicos, versión ${VERSION} >= ${MIN_FIXED}; no parece afectado por este CVE."
    N_NO=$((N_NO+1))
  elif [[ -n "$VERSION" ]] && version_in_vuln_range "$VERSION"; then
    VEREDICTO="PUEDE_SER_VULNERABLE"
    MENSAJE="Versión ${VERSION} en rango afectado (${VULN_MIN}–${VULN_MAX}). Controlar desde dentro (KUDU)."
    N_PUEDE=$((N_PUEDE+1))
  elif [[ "$CHECK_ONLY" == "positivo" ]]; then
    VEREDICTO="PUEDE_SER_VULNERABLE"
    MENSAJE="PoC --check-only reportó señales de exposición; validar config en la VM."
    N_PUEDE=$((N_PUEDE+1))
  elif [[ "$NGINX_DETECTED" == "yes" && -z "$VERSION" ]]; then
    VEREDICTO="REVISAR_DESDE_DENTRO"
    MENSAJE="NGINX detectado pero sin versión en header; ejecutar vm-local/nginx-rift-check.sh en la VM."
    N_REVISAR=$((N_REVISAR+1))
  elif [[ "$NGINX_DETECTED" == "no" ]]; then
    VEREDICTO="NO_PARECE_VULNERABLE"
    MENSAJE="No se detectó NGINX en Server; este CVE aplica al módulo rewrite de NGINX."
    N_NO=$((N_NO+1))
  else
    VEREDICTO="REVISAR_DESDE_DENTRO"
    MENSAJE="Resultado ambiguo; validar nginx -v y nginx -T dentro de la VM."
    N_REVISAR=$((N_REVISAR+1))
  fi

  echo "  HTTP: ${HTTP_CODE:-?} | Server: ${SERVER_HDR:-—}"
  [[ -n "$VERSION" ]] && echo "  Versión NGINX: $VERSION"
  echo "  check-only: $CHECK_ONLY"
  case "$VEREDICTO" in
    PUEDE_SER_VULNERABLE) echo "  ${RED}${BLD}VEREDICTO: ${VEREDICTO}${RST}" ;;
    NO_PARECE_VULNERABLE) echo "  ${GRN}${BLD}VEREDICTO: ${VEREDICTO}${RST}" ;;
    *) echo "  ${YEL}${BLD}VEREDICTO: ${VEREDICTO}${RST}" ;;
  esac
  echo "  → $MENSAJE"

  esc() { echo "$1" | tr ',' ';'; }
  echo "$(esc "$domain"),$NGINX_DETECTED,$(esc "${VERSION:-}"),${HTTP_CODE:-},$(esc "${SERVER_HDR:-}"),$(esc "${VIA_HDR:-}"),$CHECK_ONLY,$VEREDICTO,$(esc "$MENSAJE")" >> "$CSV_OUT"
done

echo
echo "${BLD}=== Resumen ===${RST}"
echo "  PUEDE_SER_VULNERABLE:    $N_PUEDE"
echo "  REVISAR_DESDE_DENTRO:  $N_REVISAR"
echo "  NO_PARECE_VULNERABLE:    $N_NO"
echo "  INDETERMINADO:           $N_INDET"
echo "  Reporte: ${CSV_OUT}"
echo
if [[ $N_PUEDE -gt 0 || $N_REVISAR -gt 0 ]]; then
  echo "${YEL}Siguiente paso:${RST} subir vm-local/ a KUDU y ejecutar ./nginx-rift-check.sh en cada sitio marcado."
fi
exit 0
