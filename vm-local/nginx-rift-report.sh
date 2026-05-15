#!/usr/bin/env bash
# Informe CVE-2026-42945 — ejecutar en KUDU: ./nginx-rift-report.sh
# Guardar copia: ./nginx-rift-report.sh -o /home/nginx-rift-reporte.txt
set -uo pipefail

CVE="CVE-2026-42945"
VULN_MIN="0.6.27"
VULN_MAX="1.30.0"
MIN_FIXED="1.30.1"
OUT_FILE=""
VEREDICTO="REVISAR"

while [[ $# -gt 0 ]]; do
  case "$1" in
    -o) OUT_FILE="$2"; shift 2 ;;
    -h|--help)
      echo "Uso: $0 [-o archivo.txt]"
      exit 0 ;;
    *) echo "Opción desconocida: $1" >&2; exit 1 ;;
  esac
done

TMP="$(mktemp /tmp/nginx-rift-report.XXXXXX 2>/dev/null || mktemp)"

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

count_rewrites() {
  echo "$1" | grep -cE '^[[:space:]]*rewrite[[:space:]]+.*\$[0-9].*\?' 2>/dev/null || true
}

HOST_LABEL="${WEBSITE_HOSTNAME:-${WEBSITE_SITE_NAME:-$(hostname 2>/dev/null || echo 'desconocido')}}"
FECHA="$(date -u '+%Y-%m-%d %H:%M:%S UTC' 2>/dev/null || date '+%Y-%m-%d %H:%M:%S')"

{
  echo "================================================================================"
  echo " INFORME $CVE (NGINX Rift) — $HOST_LABEL"
  echo " Fecha: $FECHA"
  echo "================================================================================"
  echo ""

  NGX_PATH=""
  for p in nginx /usr/sbin/nginx /usr/local/nginx/sbin/nginx; do
    command -v "$p" >/dev/null 2>&1 && NGX_PATH="$p" && break
  done

  if [[ -z "$NGX_PATH" ]]; then
    echo "1. VERSIÓN NGINX"
    echo "   Estado: NO DETECTADO en PATH"
    echo "   ¿Actualizar?: NO APLICA en esta shell — frontal probablemente de plataforma"
    echo "   Acción: Usar header Server del scan externo y ticket a platform"
    echo ""
    echo "VEREDICTO_FINAL=REVISAR"
    exit 0
  fi

  VERSION="$("$NGX_PATH" -v 2>&1 | awk -F/ '{print $2}' | awk '{print $1}')"
  NEED_UPDATE="SÍ"
  UPDATE_MSG="Actualizar NGINX a >= $MIN_FIXED (o 1.31.0 mainline)."
  if version_ge_fixed "$VERSION"; then
    NEED_UPDATE="NO"
    UPDATE_MSG="No requiere upgrade por este CVE."
  elif ! version_in_vuln_range "$VERSION" 2>/dev/null; then
    NEED_UPDATE="REVISAR"
    UPDATE_MSG="Versión $VERSION: confirmar en https://nginx.org/en/security_advisories.html"
  fi

  echo "1. VERSIÓN NGINX"
  echo "   Binario:              $NGX_PATH"
  echo "   Versión actual:       $VERSION"
  echo "   CVE afecta versiones: $VULN_MIN – $VULN_MAX"
  echo "   Versión mínima segura: $MIN_FIXED+"
  echo "   ¿Hay que actualizar?:  $NEED_UPDATE"
  echo "   Detalle:              $UPDATE_MSG"
  if [[ -n "${WEBSITE_SITE_NAME:-}" ]]; then
    echo "   App Service:          el parche del binario lo aplica platform/Microsoft;"
    echo "                         no suele poder hacerse con apt desde KUDU."
  fi
  echo ""

  ASLR="unknown"
  [[ -r /proc/sys/kernel/randomize_va_space ]] && ASLR="$(cat /proc/sys/kernel/randomize_va_space)"
  ASLR_OK="DESCONOCIDO"
  ASLR_ACCION="No se pudo leer /proc."
  case "$ASLR" in
    2) ASLR_OK="OK"; ASLR_ACCION="Ninguna (ASLR completo)." ;;
    1) ASLR_OK="PARCIAL"; ASLR_ACCION="Subir a 2: sysctl kernel.randomize_va_space=2 (platform/root)." ;;
    0) ASLR_OK="MAL"; ASLR_ACCION="Habilitar ASLR=2 cuanto antes (reduce riesgo de RCE)." ;;
  esac

  echo "2. ASLR (Address Space Layout Randomization)"
  echo "   Qué es: el sistema operativo coloca programas y librerías en direcciones de"
  echo "   memoria distintas en cada arranque. Si alguien explota un fallo en NGINX,"
  echo "   le cuesta mucho más ejecutar código malicioso (RCE). NO reemplaza el parche."
  echo "   Valor (randomize_va_space): $ASLR  →  Estado: $ASLR_OK"
  echo "   Acción: $ASLR_ACCION"
  echo ""

  CFG_DUMP=""
  if out="$("$NGX_PATH" -T 2>/dev/null)" && [[ -n "$out" ]]; then CFG_DUMP="$out"
  elif command -v sudo >/dev/null 2>&1 && out="$(sudo -n "$NGX_PATH" -T 2>/dev/null)" && [[ -n "$out" ]]; then CFG_DUMP="$out"
  fi

  MATCHES=0
  REWRITE_OK="NO REVISADO"
  REWRITE_ACCION="Conseguir permisos para nginx -T."

  if [[ -n "$CFG_DUMP" ]]; then
    MATCHES=$(count_rewrites "$CFG_DUMP")
    MATCHES="${MATCHES//[^0-9]/}"
    MATCHES="${MATCHES:-0}"
    if [[ "$MATCHES" -eq 0 ]]; then
      REWRITE_OK="CORRECTA"
      REWRITE_ACCION="Sin patrón rewrite peligroso detectado en la config cargada."
    else
      REWRITE_OK="CORREGIR"
      REWRITE_ACCION="Sustituir \$1,\$2 por capturas nombradas (?<id>). Ver rewrite-mitigation-example.conf"
    fi
  else
    # nginx -T falló o sin permisos: revisar archivos .conf legibles a mano
    manual_hits=0
    if [[ -d /etc/nginx ]]; then
      while IFS= read -r line; do
        [[ -n "$line" ]] && manual_hits=$((manual_hits+1))
      done < <(grep -rnE '^[[:space:]]*rewrite[[:space:]]+.*\$[0-9].*\?' /etc/nginx/ 2>/dev/null | grep -v '^#' || true)
    fi
    MATCHES=$manual_hits
    if [[ "$manual_hits" -eq 0 ]]; then
      REWRITE_OK="REVISAR_MANUAL"
      REWRITE_ACCION="nginx -T no disponible; grep manual en /etc/nginx sin coincidencias del patrón CVE (confirmar tras arreglar nginx -t)."
    else
      REWRITE_OK="CORREGIR"
      REWRITE_ACCION="Patrón CVE detectado por grep en archivos bajo /etc/nginx (sin nginx -T completo)."
    fi
  fi

  echo "3. CONFIGURACIÓN REWRITE"
  echo "   Riesgo CVE: rewrite con \$1/\$2/... y signo ? en el destino del rewrite"
  echo "   Estado:     $REWRITE_OK"
  echo "   Coincidencias: $MATCHES"
  echo "   Acción:     $REWRITE_ACCION"
  if [[ -n "$CFG_DUMP" ]]; then
    echo ""
    echo "   Archivos a revisar (los que carga nginx):"
    echo "$CFG_DUMP" | grep -E '^# configuration file' | sed 's/^# configuration file /     /;s/:$//' | sort -u
    if [[ "$MATCHES" -gt 0 ]]; then
      echo ""
      echo "   Líneas a corregir:"
      echo "$CFG_DUMP" | grep -nE '^[[:space:]]*rewrite[[:space:]]+.*\$[0-9].*\?' | head -25 | sed 's/^/     /'
    fi
  fi
  echo ""

  echo "4. LOGS NGINX"
  LOG_FOUND=0
  for log in /var/log/nginx/error.log /home/LogFiles/nginx/error.log; do
    [[ -r "$log" ]] || continue
    LOG_FOUND=1
    hits=$(grep -cE 'exited on signal|SIGSEGV' "$log" 2>/dev/null || true)
    hits="${hits//[^0-9]/}"
    hits="${hits:-0}"
    echo "   $log → eventos signal/SIGSEGV: $hits"
    [[ "$hits" -gt 0 ]] && grep -E 'exited on signal|SIGSEGV' "$log" 2>/dev/null | tail -3 | sed 's/^/     /'
  done
  [[ $LOG_FOUND -eq 0 ]] && echo "   (logs no accesibles desde KUDU — normal)"
  echo ""

  echo "5. nginx -t"
  NGINX_T_OK="no"
  if "$NGX_PATH" -t 2>&1 | sed 's/^/   /'; then
    echo "   Sintaxis: OK"
    NGINX_T_OK="yes"
  else
    echo "   Sintaxis: FALLO — la config no es válida o falta un módulo (ej. brotli)."
    echo "   Mientras falle nginx -t, nginx -T no vuelca toda la config para el chequeo CVE."
  fi
  echo ""

  echo "6. ACCIONES PARA TICKET PLATFORM"
  step=1
  if [[ "$NEED_UPDATE" == "SÍ" ]]; then
    echo "   $step) Parchear frontal NGINX $VERSION → >= $MIN_FIXED (host: $HOST_LABEL)"
    step=$((step+1))
  fi
  if [[ "$REWRITE_OK" == "CORREGIR" ]]; then
    echo "   $step) Corregir rewrites en archivos de sección 3 y recargar nginx"
    step=$((step+1))
  fi
  if [[ "$NGINX_T_OK" == "no" ]]; then
    echo "   $step) Corregir error nginx -t (revisar /etc/nginx/conf.d/*.conf, ej. directiva brotli sin módulo)"
    step=$((step+1))
  fi
  if [[ "$REWRITE_OK" == "REVISAR_MANUAL" || "$REWRITE_OK" == "NO REVISADO" ]]; then
    echo "   $step) Tras arreglar nginx -t, volver a ejecutar ./nginx-rift-report.sh"
    step=$((step+1))
  fi
  if [[ "$ASLR_OK" == "MAL" || "$ASLR_OK" == "PARCIAL" ]]; then
    echo "   $step) Ajustar ASLR a 2 en el SO"
    step=$((step+1))
  fi
  if [[ "$NEED_UPDATE" == "NO" && "$REWRITE_OK" == "CORRECTA" && "$ASLR_OK" == "OK" ]]; then
    echo "   $step) Sin hallazgos críticos en esta instancia"
    step=$((step+1))
  fi
  echo ""

  if [[ "$NEED_UPDATE" == "NO" && "$REWRITE_OK" == "CORRECTA" && "$ASLR_OK" == "OK" && "$NGINX_T_OK" == "yes" ]]; then
    VEREDICTO="OK"
  elif [[ "$NEED_UPDATE" == "SÍ" && "$MATCHES" -gt 0 ]]; then
    VEREDICTO="URGENTE"
  elif [[ "$NGINX_T_OK" == "no" || "$REWRITE_OK" == "NO REVISADO" || "$REWRITE_OK" == "REVISAR_MANUAL" ]]; then
    VEREDICTO="REVISAR"
  elif [[ "$NEED_UPDATE" == "SÍ" ]]; then
    VEREDICTO="PARCHE_PLATAFORMA"
  else
    VEREDICTO="REVISAR"
  fi

  echo "================================================================================"
  echo " VEREDICTO_FINAL=$VEREDICTO"
  case "$VEREDICTO" in
    OK) echo " Todo controlado en esta instancia para CVE-2026-42945." ;;
    PARCHE_PLATAFORMA) echo " Config revisada OK; falta actualizar versión NGINX (platform/Azure)." ;;
    URGENTE) echo " Versión vulnerable + rewrites a corregir." ;;
    REVISAR) echo " Config NO cerrada: arreglar nginx -t y/o re-ejecutar informe." ;;
    *) echo " Revisar secciones anteriores." ;;
  esac
  echo "================================================================================"

} > "$TMP"

VEREDICTO="$(grep 'VEREDICTO_FINAL=' "$TMP" | tail -1 | sed 's/.*VEREDICTO_FINAL=//;s/ .*//')"
cat "$TMP"
[[ -n "$OUT_FILE" ]] && cp "$TMP" "$OUT_FILE" && echo "" && echo "Guardado en: $OUT_FILE"
rm -f "$TMP"

case "$VEREDICTO" in
  OK) exit 0 ;;
  PARCHE_PLATAFORMA) exit 2 ;;
  URGENTE) exit 3 ;;
  *) exit 1 ;;
esac