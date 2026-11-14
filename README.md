# PQC-ready-check — Is your website quantum-safe?

Scan any domain's **live TLS handshake** and see whether it uses post-quantum key exchange.

**Site:** https://sukhi-superman.github.io/PQC-ready-check/

| Folder | What it is |
|---|---|
| `frontend/` | React + Tailwind + Lucide single-page app, built with Vite and published to GitHub Pages by `.github/workflows/pages.yml` |
| `backend/` | FastAPI service that performs the TLS inspection with OpenSSL 3.5+ (`main.py`, `Dockerfile`, tests) |

> **Current status:** the site is live with **labelled sample reports** only. Real scanning switches on once the
> backend is deployed and the site is pointed at it (see *Go live* below). Turnstile uses Cloudflare's **test keys**
> until real keys are created.

## How a scan works

1. **Rate limit** per client IP (default 5/minute, 30/hour, in memory).
2. **Input sanitising:** scheme, credentials, path, query and port are stripped. The port is always 443. IP literals and numeric hosts are rejected.
3. **Cloudflare Turnstile** token verified with `siteverify`. This is the first outbound call; nothing touches the target before it passes.
4. **DNS + SSRF guard:** every A/AAAA answer must be globally routable. Private, loopback, link-local, CGNAT, reserved, multicast, IPv4-mapped, 6to4 and Teredo addresses are refused. Probes connect to the **pinned IP**, with SNI set to the hostname, so a DNS re-bind can't redirect them.
5. **Probes:**
   - `openssl s_client` offers `X25519MLKEM768:SecP256r1MLKEM768:SecP384r1MLKEM1024:X25519:P-256:P-384`. It records the negotiated group (`Negotiated TLS1.3 group:` / `Peer Temp Key:`), protocol, cipher, ALPN, OCSP stapling, peer signature type and certificate chain.
   - A Python `ssl` handshake measures TCP and TLS latency and cross-checks version, cipher and ALPN.
   - One TLS 1.3 handshake per NIST hybrid group shows which post-quantum groups the server accepts.
6. Progress streams to the browser as NDJSON. Nothing is written to disk.

### Verdicts

| Tier | Rule |
|---|---|
| **Quantum-safe** (Hybrid PQC Protected) | TLS 1.3 **and** an ML-KEM hybrid group (`X25519MLKEM768`, `SecP256r1MLKEM768`, `SecP384r1MLKEM1024`; FIPS 203, RFC 10024) |
| **Classical modern** (HNDL risk) | TLS 1.3 with ECDHE/DHE and an AEAD cipher, without ML-KEM |
| **Legacy / at risk** | Anything else: TLS 1.2 or older, static RSA key transport, CBC or weak ciphers |

**Score (0–100):**

- key exchange 50 (ML-KEM hybrid 50 · ECDHE 15 · DHE 8 · RSA 0)
- protocol 15
- symmetric cipher 15 (256-bit AEAD 15 · 128-bit AEAD 10 · CBC 3)
- certificate key 15 (ML-DSA/SLH-DSA 15 · RSA ≥3072 / P-384 9 · RSA-2048 / P-256 7)
- chain verification 3 + OCSP stapling 2

The site never offers CSV, JSON or PDF export.

## Run locally

### Backend (needs OpenSSL ≥ 3.5)

With Docker (recommended):

```bash
cd backend
docker build -t pqc-backend .      # the build fails if OpenSSL lacks the ML-KEM hybrid groups
docker run --rm -p 8000:8000 \
  -e TURNSTILE_SECRET=1x0000000000000000000000000000000AA \
  -e ALLOWED_ORIGINS=http://localhost:5173 \
  pqc-backend
curl http://localhost:8000/api/health
```

`1x0000000000000000000000000000000AA` is Cloudflare's always-pass **test** secret, for local use only.

Without Docker, you need an `openssl` binary ≥ 3.5 (`openssl version`):

```bash
cd backend
python -m venv .venv && . .venv/bin/activate && pip install -r requirements.txt pytest
OPENSSL_BIN=$(which openssl) python -m pytest -q          # 66 tests; live-handshake tests skip without OpenSSL 3.5
TURNSTILE_SECRET=1x0000000000000000000000000000000AA uvicorn main:app --reload --port 8000
```

### Frontend

```bash
cd frontend
npm ci
VITE_API_URL=http://localhost:8000 npm run dev    # http://localhost:5173/PQC-ready-check/
npm run dev                                       # without VITE_API_URL: sample-report mode
```

## Backend configuration (environment variables)

| Variable | Default | Purpose |
|---|---|---|
| `TURNSTILE_SECRET` | *(required)* | Turnstile secret key. Without it, scans are refused (503). |
| `TURNSTILE_HOSTNAMES` | *(off)* | Optional: only accept tokens issued for these hostnames, e.g. `sukhi-superman.github.io` |
| `ALLOWED_ORIGINS` | `https://sukhi-superman.github.io,http://localhost:5173` | CORS allow-list |
| `TRUSTED_PROXY_HOPS` | `0` | Reverse proxies that append `X-Forwarded-For` (Render / Cloud Run: `1`) |
| `RATE_LIMIT_PER_MINUTE` / `RATE_LIMIT_PER_HOUR` | `5` / `30` | Per-IP limits |
| `MAX_CONCURRENT_SCANS` | `4` | Global concurrency |
| `PROBE_TIMEOUT_SECONDS` | `8` | Per-handshake timeout |
| `OPENSSL_BIN` | `openssl` | OpenSSL 3.5+ binary |

Run a **single worker**. Rate-limit state lives in memory; for several instances, move it to Redis.

## Go live

1. **Deploy the backend** from `backend/Dockerfile` to any container host with outbound TCP 443, such as Render, Cloud Run or Fly.io. Then set:
   - `TURNSTILE_SECRET`
   - `TURNSTILE_HOSTNAMES=sukhi-superman.github.io`
   - `TRUSTED_PROXY_HOPS=1`
2. **Create a Turnstile widget** in Cloudflare for hostname `sukhi-superman.github.io` and copy its site key and secret key.
3. In this repo, go to **Settings → Secrets and variables → Actions → Variables** and add:
   - `VITE_API_URL` = the backend URL
   - `VITE_TURNSTILE_SITE_KEY` = the site key
4. Re-run the **Deploy site to GitHub Pages** workflow. The page's Content-Security-Policy automatically allows the configured API origin.

## Standards referenced

- NIST FIPS 203 (ML-KEM) and FIPS 204 (ML-DSA), August 2024
- NIST IR 8547 (final, October 2026): quantum-vulnerable public-key algorithms are deprecated after 2030 and disallowed after 2035
- RFC 10024 (August 2026): PQ/T hybrid key agreement for TLS 1.3
- NSA CNSA 2.0: web browsers, servers and cloud services should prefer it by 2025 and use it exclusively by 2033
- CISA / NSA / NIST *Quantum-Readiness: Migration to Post-Quantum Cryptography*
- Cloudflare Radar post-quantum adoption data
