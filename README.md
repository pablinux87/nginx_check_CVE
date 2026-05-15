# nginx_check_CVE — CVE-2026-42945 (NGINX Rift)

Kit de comprobación y mitigación para **CVE-2026-42945**.

## Escaneo rápido desde tu PC

```bash
# Editar domains.txt con tus URLs
docker compose run --rm scanner
# o: ./nginx-rift-scan-external.sh -f domains.txt -c reporte-externo.csv
```

Ver `reporte-externo.csv` → columnas `veredicto` / `mensaje`.

## Pruebas dentro de la VM (KUDU / Azure App Service)

Usar la carpeta **`vm-local/`**:

```bash
chmod +x nginx-rift-*.sh
./nginx-rift-check.sh
```

Detalle: [vm-local/LEEME-KUDU.txt](vm-local/LEEME-KUDU.txt)

## Referencias

- [F5 K000161019](https://my.f5.com/manage/s/article/K000161019)
- [nginx security advisories](https://nginx.org/en/security_advisories.html)
