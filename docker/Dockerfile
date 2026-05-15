FROM python:3.12-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    curl bash ca-certificates git \
    && rm -rf /var/lib/apt/lists/*

RUN git clone --depth 1 https://github.com/cipherspy/CVE-2026-42945-POC.git /opt/poc

WORKDIR /data
COPY nginx-rift-scan-external.sh /usr/local/bin/nginx-rift-scan-external.sh
RUN sed -i 's/\r$//' /usr/local/bin/nginx-rift-scan-external.sh \
    && chmod +x /usr/local/bin/nginx-rift-scan-external.sh

ENV POC_DIR=/opt/poc
ENTRYPOINT ["nginx-rift-scan-external.sh"]
CMD ["-f", "/data/domains.txt", "-c", "/data/reporte-externo.csv", "--poc-dir", "/opt/poc"]
