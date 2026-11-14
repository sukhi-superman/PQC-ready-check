# PQC-ready-check backend
# Debian 13 "trixie" ships OpenSSL 3.5.x, which supports the ML-KEM hybrid TLS 1.3 groups
# (X25519MLKEM768, SecP256r1MLKEM768, SecP384r1MLKEM1024) out of the box. The python:*-trixie
# images build Python's ssl module against that same OpenSSL.
FROM python:3.13-slim-trixie

ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PIP_NO_CACHE_DIR=1

RUN apt-get update \
 && apt-get install -y --no-install-recommends openssl ca-certificates \
 && rm -rf /var/lib/apt/lists/*

# Fail the build early if this OpenSSL cannot negotiate the NIST ML-KEM hybrid groups.
RUN openssl version \
 && openssl list -tls-groups | tr ':' '\n' | grep -qx X25519MLKEM768 \
 && openssl list -tls-groups | tr ':' '\n' | grep -qx SecP256r1MLKEM768 \
 && openssl list -tls-groups | tr ':' '\n' | grep -qx SecP384r1MLKEM1024 \
 && python -c "import ssl; print(ssl.OPENSSL_VERSION)"

WORKDIR /app
COPY requirements.txt .
RUN pip install -r requirements.txt
COPY main.py .

RUN useradd --system --uid 10001 --no-create-home app
USER app

ENV PORT=8000
EXPOSE 8000
HEALTHCHECK --interval=60s --timeout=5s CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:%s/api/health' % __import__('os').environ.get('PORT','8000')).status==200 else 1)"
# --proxy-headers off: client IPs for rate limiting come from TRUSTED_PROXY_HOPS instead.
CMD ["sh", "-c", "exec uvicorn main:app --host 0.0.0.0 --port ${PORT} --no-proxy-headers --workers 1"]
