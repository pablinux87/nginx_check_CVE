# nginx_check_CVE — CVE-2026-42945

## KUDU (informe para platform)

```bash
apt-get update -qq && apt-get install -y git
cd /home && git clone https://github.com/pablinux87/nginx_check_CVE.git
cd /home/nginx_check_CVE && git pull && cd vm-local
chmod +x nginx-rift-*.sh
./nginx-rift-report.sh -o /home/nginx-rift-reporte.txt
```

## Scan externo (PC)

```bash
docker compose run --rm scanner
```

Ver [vm-local/LEEME-KUDU.txt](vm-local/LEEME-KUDU.txt)
