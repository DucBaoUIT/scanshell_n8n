FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

RUN apt-get update \
    && apt-get install -y --no-install-recommends bash mariadb-client ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY scanner-api.py /app/scanner-api.py
COPY scan-source.sh /opt/security-scanner/scan-source.sh
COPY scan-database.sh /opt/security-scanner/scan-database.sh

RUN useradd --create-home --uid 10001 scanner \
    && chown -R scanner:scanner /opt/security-scanner \
    && chmod 750 /opt/security-scanner/*.sh

USER scanner

EXPOSE 8080

CMD ["uvicorn", "scanner-api:app", "--host", "0.0.0.0", "--port", "8080", "--workers", "2"]
