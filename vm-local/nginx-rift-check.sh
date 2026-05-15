#!/usr/bin/env bash
# Diagnóstico local CVE-2026-42945 — ejecutar DENTRO de la VM (KUDU bash)
set -uo pipefail

VULN_MIN="0.6.27"
VULN_MAX="1.30.0"
MIN_FIXED="1.30.1"

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

version_ge_fixed() {
  local v="$1"
  [[ -z "$v" ]] && return 1
  [[ "$(printf '%s\n%s\n' "$MIN_FIXED" "$v" | sort -V | tail -n1)" == "$v" ]]
}

echo "=== CVE-2026-42945 — chequeo local (VM / KUDU) ==="
echo

NGX_PATH=""
for p in nginx /usr/sbin/nginx /usr/local/nginx/sbin/nginx; do
  command -v "$p" >/dev/null 2>&1 && NGX_PATH="$p" && break
done

if [[ -z "$NGX_PATH" ]]; then
  echo "NGINX no encontrado en PATH de esta instancia."
  echo ""
  echo "VEREDICTO_LOCAL=REVISAR"
  echo "En Azure App Service el frontal NGINX suele ser capa de plataforma."
  echo "Escalar a platform/infra o validar si la app usa otro servidor web."
  exit 2
fi

VERSION="$("$NGX_PATH" -v 2>&1 | awk -F/ '{print $2}' | awk '{print $1}')"
echo "Binario: $NGX_PATH"
echo "Versión: $VERSION"

CFG_DUMP=""
if out="$("$NGX_PATH" -T 2>/dev/null)" && [[ -n "$out" ]]; then
  CFG_DUMP="$out"
elif command -v sudo >/dev/null 2>&1 && out="$(sudo -n "$NGX_PATH" -T 2>/dev/null)" && [[ -n "$out" ]]; then
  CFG_DUMP="$out"
fi

MATCHES=0
if [[ -n "$CFG_DUMP" ]]; then
  MATCHES="$(echo "$CFG_DUMP" | grep -cE '^[[:space:]]*rewrite[[:space:]]+.*\$[0-9].*\?' || echo 0)"
  echo "Config cargada: sí"
  echo "Líneas rewrite sospechosas (\$N + ?): $MATCHES"
  if [[ "$MATCHES" -gt 0 ]]; then
    echo "--- revisar manualmente ---"
    echo "$CFG_DUMP" | grep -nE '^[[:space:]]*rewrite[[:space:]]+.*\$[0-9].*\?' | head -15
  fi
else
  echo "Config cargada: no (ejecutar con permisos para nginx -T)"
fi

ASLR="unknown"
[[ -r /proc/sys/kernel/randomize_va_space ]] && ASLR="$(cat /proc/sys/kernel/randomize_va_space)"
echo "ASLR (randomize_va_space): $ASLR"

VEREDICTO="REVISAR"
MSG="Revisar manualmente."

if version_ge_fixed "$VERSION"; then
  if [[ "$MATCHES" -eq 0 ]]; then
    VEREDICTO="NO_VULNERABLE"
    MSG="Versión >= $MIN_FIXED y sin patrón rewrite detectado en config accesible."
  else
    VEREDICTO="REVISAR"
    MSG="Versión parcheada pero hay rewrites sospechosos; corregir capturas nombradas."
  fi
elif version_in_vuln_range "$VERSION"; then
  if [[ "$MATCHES" -gt 0 ]]; then
    [[ "$ASLR" == "0" ]] && VEREDICTO="VULNERABLE" MSG="Versión afectada + patrón rewrite + ASLR=0. Parchear y mitigar YA."
    [[ "$ASLR" != "0" ]] && VEREDICTO="VULNERABLE" MSG="Versión afectada + patrón rewrite. Parchear a $MIN_FIXED+ y usar capturas ?<nombre>."
  else
    VEREDICTO="VULNERABLE"
    MSG="Versión en rango vulnerable; parchear aunque no se detectó patrón (heurística incompleta)."
  fi
else
  VEREDICTO="REVISAR"
  MSG="Versión no clasificada; confirmar con nginx -v y parchear si < $MIN_FIXED."
fi

echo ""
echo "=========================================="
echo "VEREDICTO_LOCAL=$VEREDICTO"
echo "$MSG"
echo "=========================================="

case "$VEREDICTO" in
  VULNERABLE) echo "Siguiente: ./nginx-rift-mitigate.sh → editar config → ./nginx-rift-patch.sh"; exit 2 ;;
  NO_VULNERABLE) exit 0 ;;
  *) exit 1 ;;
esac
