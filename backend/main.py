"""
PQC-ready-check — backend

Inspects a domain's live, public TLS handshake and rates its post-quantum readiness.

Request pipeline (in this order, so nothing touches the network before it is allowed to):
  1. per-IP rate limit (in memory)
  2. strict input sanitising -> a bare DNS hostname, port fixed to 443
  3. Cloudflare Turnstile token check via siteverify      <- first outbound call, to Cloudflare only
  4. DNS resolution + SSRF guard: every resolved address must be globally routable
  5. TLS probes against the *pinned* IP (SNI = hostname), so a DNS re-bind cannot redirect them:
       a. `openssl s_client` (OpenSSL 3.5+) offering ML-KEM hybrid groups first -> negotiated group,
          protocol, cipher, ALPN, OCSP stapling, peer signature type, certificate chain
       b. Python `ssl` handshake -> TCP / TLS latency, cross-check of version, cipher and ALPN
       c. one `s_client` per NIST hybrid group (TLS 1.3, that group only) -> which PQC groups the server accepts
Progress is streamed to the browser as NDJSON events; the last event carries the full result.
Nothing about a scan is written to disk or kept after the response.
"""

from __future__ import annotations

import asyncio
import ipaddress
import json
import logging
import os
import re
import socket
import ssl
import subprocess
import time
from collections import deque
from datetime import datetime, timezone
from typing import Any, AsyncIterator

import certifi
import httpx
import idna
from cryptography import x509
from cryptography.exceptions import UnsupportedAlgorithm
from cryptography.hazmat.primitives.asymmetric import dsa, ec, ed448, ed25519, rsa
from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, Field

log = logging.getLogger("pqc-ready-check")
logging.basicConfig(level=os.environ.get("LOG_LEVEL", "INFO"))

# --------------------------------------------------------------------------------------------- config
OPENSSL_BIN = os.environ.get("OPENSSL_BIN", "openssl")
TURNSTILE_SECRET = os.environ.get("TURNSTILE_SECRET", "").strip()
TURNSTILE_HOSTNAMES = {h.strip() for h in os.environ.get("TURNSTILE_HOSTNAMES", "").split(",") if h.strip()}
SITEVERIFY_URL = "https://challenges.cloudflare.com/turnstile/v0/siteverify"
ALLOWED_ORIGINS = [o.strip() for o in os.environ.get(
    "ALLOWED_ORIGINS", "https://sukhi-superman.github.io,http://localhost:5173").split(",") if o.strip()]
RATE_PER_MINUTE = int(os.environ.get("RATE_LIMIT_PER_MINUTE", "5"))
RATE_PER_HOUR = int(os.environ.get("RATE_LIMIT_PER_HOUR", "30"))
MAX_CONCURRENT_SCANS = int(os.environ.get("MAX_CONCURRENT_SCANS", "4"))
# Number of reverse proxies in front of the app that append to X-Forwarded-For (Render/Cloud Run: 1).
TRUSTED_PROXY_HOPS = int(os.environ.get("TRUSTED_PROXY_HOPS", "0"))
PROBE_TIMEOUT = float(os.environ.get("PROBE_TIMEOUT_SECONDS", "8"))
DNS_TIMEOUT = 5.0
TARGET_PORT = 443  # never user-controlled

# NIST FIPS 203 ML-KEM hybrids for TLS 1.3 (RFC 10024 codepoints)
PQC_GROUPS: dict[str, dict[str, str]] = {
    "X25519MLKEM768": {"classical": "X25519", "kem": "ML-KEM-768", "codepoint": "0x11EC", "nist_level": "3"},
    "SecP256r1MLKEM768": {"classical": "P-256", "kem": "ML-KEM-768", "codepoint": "0x11EB", "nist_level": "3"},
    "SecP384r1MLKEM1024": {"classical": "P-384", "kem": "ML-KEM-1024", "codepoint": "0x11ED", "nist_level": "5"},
}
# ClientHello offer: hybrids first (most preferred), then classical fallbacks a modern browser also offers
OFFERED_GROUPS = ["X25519MLKEM768", "SecP256r1MLKEM768", "SecP384r1MLKEM1024", "X25519", "P-256", "P-384"]
CLASSICAL_NAMES = {"x25519": "X25519", "x448": "X448", "prime256v1": "P-256", "secp256r1": "P-256", "p-256": "P-256",
                   "secp384r1": "P-384", "p-384": "P-384", "secp521r1": "P-521", "p-521": "P-521"}

# ------------------------------------------------------------------------------- input sanitising
LABEL_RE = re.compile(r"^(?!-)[a-z0-9-]{1,63}(?<!-)$")
TLD_RE = re.compile(r"^(xn--[a-z0-9-]{1,59}|[a-z]{2,63})$")


class InputError(ValueError):
    """User input that cannot be scanned (shown to the user as-is)."""


def sanitize_domain(raw: Any) -> str:
    """Reduce user input to a bare, lowercase, ASCII (punycode) DNS hostname.

    Strips scheme, credentials, path, query, fragment and port. Rejects IP literals, single-label
    names and numeric "domains" (e.g. 2130706433 or 0x7f.1) that resolvers may treat as IPs."""
    if not isinstance(raw, str):
        raise InputError("Enter a domain name such as example.com.")
    s = raw.strip()
    if not s or len(s) > 300:
        raise InputError("Enter a domain name such as example.com.")
    s = re.sub(r"^[a-zA-Z][a-zA-Z0-9+.\-]*://", "", s)       # scheme
    s = re.split(r"[/?#\\]", s, maxsplit=1)[0]                # path, query, fragment
    s = s.rsplit("@", 1)[-1]                                   # user:pass@
    if s.startswith("["):
        raise InputError("Enter a domain name, not an IP address.")
    s = s.split(":", 1)[0].rstrip(".").strip()                 # port, trailing dot
    if not s:
        raise InputError("Enter a domain name such as example.com.")
    try:
        ipaddress.ip_address(s)
        raise InputError("Enter a domain name, not an IP address.")
    except ValueError as e:
        if isinstance(e, InputError):
            raise
    try:
        s = idna.encode(s, uts46=True).decode("ascii")
    except idna.IDNAError:
        raise InputError("That doesn't look like a valid domain name.") from None
    s = s.lower()
    labels = s.split(".")
    if len(s) > 253 or len(labels) < 2 or not all(LABEL_RE.match(lb) for lb in labels) or not TLD_RE.match(labels[-1]):
        raise InputError("That doesn't look like a valid public domain name.")
    return s


# --------------------------------------------------------------------------------------- SSRF guard
def is_public_ip(value: str) -> bool:
    ip = ipaddress.ip_address(value)
    if isinstance(ip, ipaddress.IPv6Address):
        if ip.ipv4_mapped:
            return is_public_ip(str(ip.ipv4_mapped))
        if ip.sixtofour:
            return is_public_ip(str(ip.sixtofour))
        if ip.teredo:
            return is_public_ip(str(ip.teredo[1]))
    return ip.is_global and not ip.is_multicast and not ip.is_reserved and not ip.is_unspecified


class TargetError(Exception):
    """The target cannot be scanned (DNS failure, blocked address, no TLS)."""


async def resolve_target(host: str) -> list[str]:
    """Resolve A/AAAA records. Refuse the whole target if ANY address is not globally routable."""
    loop = asyncio.get_running_loop()
    try:
        infos = await asyncio.wait_for(loop.getaddrinfo(host, TARGET_PORT, type=socket.SOCK_STREAM), DNS_TIMEOUT)
    except (socket.gaierror, asyncio.TimeoutError):
        raise TargetError(f"Could not resolve {host}. Check the spelling, or the domain may not exist.") from None
    ips: list[str] = []
    for info in infos:
        ip = info[4][0].split("%", 1)[0]
        if ip not in ips:
            ips.append(ip)
    if not ips:
        raise TargetError(f"{host} has no address records.")
    if not all(is_public_ip(ip) for ip in ips):
        raise TargetError(f"{host} resolves to a private, loopback or reserved address, so it can't be scanned.")
    ips.sort(key=lambda a: ":" in a)  # prefer IPv4
    return ips


# ---------------------------------------------------------------------------------------- rate limit
class RateLimiter:
    """Sliding-window limits per client IP, held in memory only."""

    def __init__(self, per_minute: int, per_hour: int, max_clients: int = 50_000):
        self.per_minute, self.per_hour, self.max_clients = per_minute, per_hour, max_clients
        self.hits: dict[str, deque[float]] = {}

    def check(self, key: str, now: float | None = None) -> int | None:
        """Record a hit. Returns None if allowed, else seconds to wait."""
        now = time.monotonic() if now is None else now
        q = self.hits.setdefault(key, deque())
        while q and now - q[0] > 3600:
            q.popleft()
        last_minute = [t for t in q if now - t < 60]
        if len(last_minute) >= self.per_minute:
            return int(60 - (now - last_minute[0])) + 1
        if len(q) >= self.per_hour:
            return int(3600 - (now - q[0])) + 1
        q.append(now)
        if len(self.hits) > self.max_clients:  # drop idle clients
            for k in [k for k, v in self.hits.items() if not v or now - v[-1] > 3600]:
                del self.hits[k]
        return None


limiter = RateLimiter(RATE_PER_MINUTE, RATE_PER_HOUR)
scan_slots = asyncio.Semaphore(MAX_CONCURRENT_SCANS)


def client_ip(request: Request) -> str:
    if TRUSTED_PROXY_HOPS > 0:
        xff = [p.strip() for p in request.headers.get("x-forwarded-for", "").split(",") if p.strip()]
        if len(xff) >= TRUSTED_PROXY_HOPS:
            return xff[-TRUSTED_PROXY_HOPS]
    return request.client.host if request.client else "unknown"


# ----------------------------------------------------------------------------------------- Turnstile
async def verify_turnstile(token: str, remote_ip: str) -> None:
    if not TURNSTILE_SECRET:
        raise HTTPException(503, "Bot protection is not configured on this server, so scans are disabled.")
    if not token or len(token) > 2048:
        raise HTTPException(403, "Please complete the verification check.")
    try:
        async with httpx.AsyncClient(timeout=8) as client:
            r = await client.post(SITEVERIFY_URL, data={"secret": TURNSTILE_SECRET, "response": token, "remoteip": remote_ip})
        data = r.json()
    except (httpx.HTTPError, ValueError):
        raise HTTPException(503, "Could not reach the verification service. Please try again.") from None
    if not data.get("success"):
        raise HTTPException(403, "Verification failed or expired. Please complete the check again.")
    if TURNSTILE_HOSTNAMES and data.get("hostname") not in TURNSTILE_HOSTNAMES:
        raise HTTPException(403, "Verification was issued for a different site.")


# ------------------------------------------------------------------------------------------- probes
async def run_s_client(ip: str, host: str, groups: str, extra: list[str] | None = None, full: bool = True) -> dict:
    """Run `openssl s_client` against the pinned IP. Arguments are a list (no shell); host is pre-validated."""
    target = f"[{ip}]:{TARGET_PORT}" if ":" in ip else f"{ip}:{TARGET_PORT}"
    args = [OPENSSL_BIN, "s_client", "-connect", target, "-servername", host, "-groups", groups]
    if full:
        args += ["-alpn", "h2,http/1.1", "-status", "-showcerts", "-verify_hostname", host, "-CAfile", certifi.where()]
    args += extra or []
    t0 = time.perf_counter()
    try:
        proc = await asyncio.create_subprocess_exec(*args, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                                    stderr=subprocess.STDOUT)
    except OSError as e:
        return {"ok": False, "error": f"OpenSSL could not be started ({e.__class__.__name__})", "ms": 0}
    try:
        out, _ = await asyncio.wait_for(proc.communicate(), PROBE_TIMEOUT)
    except asyncio.TimeoutError:
        proc.kill()
        await proc.wait()
        return {"ok": False, "error": "timed out", "ms": round((time.perf_counter() - t0) * 1000)}
    parsed = parse_s_client(out[:512_000].decode("utf-8", "replace"))
    parsed["ms"] = round((time.perf_counter() - t0) * 1000)
    return parsed


def parse_s_client(text: str) -> dict:
    """Parse the human-readable output of OpenSSL 3.5 `s_client`."""
    def first(pattern: str, flags: int = re.M) -> str | None:
        m = re.search(pattern, text, flags)
        return m.group(1).strip() if m else None

    cipher = first(r"Cipher is (\S+)")
    protocol = first(r"^\s*Protocol\s*:\s*(\S+)")
    ok = "CONNECTED(" in text and bool(cipher) and cipher != "(NONE)" and bool(protocol)
    group = first(r"Negotiated TLS1\.3 group:\s*(\S+)")
    temp_key = None
    m = re.search(r"(?:Peer|Server) Temp Key:\s*([^,\n]+)(?:,\s*([^,\n]+))?(?:,\s*(\d+) bits)?", text)
    if m:
        kind, curve = m.group(1).strip(), (m.group(2) or "").strip()
        temp_key = {"type": kind, "curve": curve, "bits": int(m.group(3)) if m.group(3) else None}
        if not group:
            name = curve if kind.upper() == "ECDH" else kind
            group = CLASSICAL_NAMES.get(name.lower(), name)
    if group:
        group = CLASSICAL_NAMES.get(group.lower(), group)
    verify = re.search(r"Verify return code:\s*(\d+)\s*\(([^)]*)\)", text)
    stapled = bool(re.search(r"OCSP Response Status:\s*successful", text))
    cert_status = first(r"Cert Status:\s*(\S+)")
    return {
        "ok": ok,
        "protocol": protocol,
        "cipher": cipher if cipher != "(NONE)" else None,
        "group": group,
        "temp_key": temp_key,
        "alpn": first(r"ALPN protocol:\s*(\S+)"),
        "ocsp_stapled": stapled,
        "ocsp_cert_status": cert_status,
        "peer_signature_type": first(r"Peer signature type:\s*(\S+)"),
        "peer_signing_digest": first(r"Peer signing digest:\s*(\S+)"),
        "server_key_bits": int(first(r"Server public key is (\d+) bit") or 0) or None,
        "verify_code": int(verify.group(1)) if verify else None,
        "verify_message": verify.group(2) if verify else None,
        "certs_pem": re.findall(r"-----BEGIN CERTIFICATE-----.+?-----END CERTIFICATE-----", text, re.S),
        "error": None if ok else _s_client_error(text),
    }


def _s_client_error(text: str) -> str:
    for pat, msg in [(r"alert handshake failure|no shared cipher|no suitable", "the server rejected every option offered"),
                     (r"wrong version number|unsupported protocol|protocol version", "no protocol version in common"),
                     (r"Connection refused|connect:errno", "connection refused or blocked on port 443"),
                     (r"Name or service not known", "name resolution failed")]:
        if re.search(pat, text, re.I):
            return msg
    return "no TLS handshake completed"


def python_ssl_probe(ip: str, host: str) -> dict:
    """Second, independent handshake through Python's ssl module (linked to the same OpenSSL in the
    container): measures TCP connect and TLS handshake time and cross-checks version, cipher and ALPN."""
    def connect(ctx: ssl.SSLContext) -> dict:
        t0 = time.perf_counter()
        sock = socket.create_connection((ip, TARGET_PORT), timeout=PROBE_TIMEOUT)
        t1 = time.perf_counter()
        try:
            ss = ctx.wrap_socket(sock, server_hostname=host)
        except Exception:
            sock.close()
            raise
        t2 = time.perf_counter()
        with ss:
            group_fn = getattr(ss, "group", None)  # Python 3.15+ exposes the negotiated group
            return {"ok": True, "tcp_ms": round((t1 - t0) * 1000, 1), "tls_ms": round((t2 - t1) * 1000, 1),
                    "version": ss.version(), "cipher": (ss.cipher() or [None])[0], "alpn": ss.selected_alpn_protocol(),
                    "cert_der": ss.getpeercert(binary_form=True), "group": group_fn() if callable(group_fn) else None}

    ctx = ssl.create_default_context(cafile=certifi.where())
    ctx.set_alpn_protocols(["h2", "http/1.1"])
    try:
        res = connect(ctx)
        res["verified"], res["verify_error"] = True, None
        return res
    except ssl.SSLCertVerificationError as e:
        loose = ssl.create_default_context()
        loose.check_hostname, loose.verify_mode = False, ssl.CERT_NONE
        loose.set_alpn_protocols(["h2", "http/1.1"])
        try:
            res = connect(loose)
        except (OSError, ssl.SSLError) as e2:
            return {"ok": False, "error": e2.__class__.__name__}
        res["verified"], res["verify_error"] = False, (e.verify_message or "certificate verification failed")
        return res
    except (OSError, ssl.SSLError) as e:
        return {"ok": False, "error": e.__class__.__name__}


# ------------------------------------------------------------------------------------ certificate
PQ_SIG_OIDS = {
    "2.16.840.1.101.3.4.3.17": "ML-DSA-44", "2.16.840.1.101.3.4.3.18": "ML-DSA-65", "2.16.840.1.101.3.4.3.19": "ML-DSA-87",
    **{f"2.16.840.1.101.3.4.3.{n}": "SLH-DSA" for n in range(20, 32)},
}
CURVE_NAMES = {"secp256r1": "P-256", "secp384r1": "P-384", "secp521r1": "P-521"}


def _name_attr(name: x509.Name, oid) -> str | None:
    attrs = name.get_attributes_for_oid(oid)
    return str(attrs[0].value) if attrs else None


def describe_certificate(pems: list[str], der: bytes | None) -> dict | None:
    try:
        if pems:
            chain = [x509.load_pem_x509_certificate(p.encode()) for p in pems]
        elif der:
            chain = [x509.load_der_x509_certificate(der)]
        else:
            return None
    except ValueError:
        return None
    leaf = chain[0]
    key_type, key_bits, pq = "Unknown", None, False
    try:
        pk = leaf.public_key()
        if isinstance(pk, rsa.RSAPublicKey):
            key_type, key_bits = f"RSA-{pk.key_size}", pk.key_size
        elif isinstance(pk, ec.EllipticCurvePublicKey):
            key_type, key_bits = f"ECDSA {CURVE_NAMES.get(pk.curve.name, pk.curve.name)}", pk.curve.key_size
        elif isinstance(pk, ed25519.Ed25519PublicKey):
            key_type, key_bits = "Ed25519", 256
        elif isinstance(pk, ed448.Ed448PublicKey):
            key_type, key_bits = "Ed448", 456
        elif isinstance(pk, dsa.DSAPublicKey):
            key_type, key_bits = f"DSA-{pk.key_size}", pk.key_size
        else:
            key_type = type(pk).__name__.replace("PublicKey", "")
            pq = "MLDSA" in key_type.upper() or "SLHDSA" in key_type.upper()
    except (UnsupportedAlgorithm, ValueError):
        oid = getattr(getattr(leaf, "public_key_algorithm_oid", None), "dotted_string", "")
        key_type = PQ_SIG_OIDS.get(oid, f"Unrecognised ({oid or 'unknown OID'})")
        pq = oid in PQ_SIG_OIDS
    sig_oid = leaf.signature_algorithm_oid.dotted_string
    sig_name = PQ_SIG_OIDS.get(sig_oid) or getattr(leaf.signature_algorithm_oid, "_name", sig_oid)
    pq = pq or sig_oid in PQ_SIG_OIDS
    try:
        sans = leaf.extensions.get_extension_for_class(x509.SubjectAlternativeName).value.get_values_for_type(x509.DNSName)
    except x509.ExtensionNotFound:
        sans = []
    nb, na = leaf.not_valid_before_utc, leaf.not_valid_after_utc
    now = datetime.now(timezone.utc)
    return {
        "subject_cn": _name_attr(leaf.subject, x509.NameOID.COMMON_NAME),
        "issuer_cn": _name_attr(leaf.issuer, x509.NameOID.COMMON_NAME),
        "issuer_org": _name_attr(leaf.issuer, x509.NameOID.ORGANIZATION_NAME),
        "not_before": nb.isoformat(), "not_after": na.isoformat(),
        "days_remaining": (na - now).days, "expired": na < now, "not_yet_valid": nb > now,
        "key_type": key_type, "key_bits": key_bits, "signature_algorithm": sig_name,
        "pq_signature": pq, "san_count": len(sans), "sans_sample": sans[:5],
        "chain_length": len(chain), "self_signed": leaf.issuer == leaf.subject,
        "chain": [{"subject_cn": _name_attr(c.subject, x509.NameOID.COMMON_NAME),
                   "issuer_cn": _name_attr(c.issuer, x509.NameOID.COMMON_NAME)} for c in chain[:5]],
    }


# --------------------------------------------------------------------------------------- evaluation
def symmetric_profile(cipher: str | None) -> dict:
    c = (cipher or "").upper()
    if not c:
        return {"bits": None, "aead": False, "weak": True, "name": None}
    weak = any(w in c for w in ("RC4", "DES", "NULL", "EXP", "MD5", "ANON", "ADH", "AECDH"))
    aead = any(a in c for a in ("GCM", "CHACHA20", "POLY1305", "CCM"))
    m = re.search(r"(?:AES|CAMELLIA|ARIA)[_-]?(128|256)", c)  # key size, not the SHA256/384 hash suffix
    if m:
        bits = int(m.group(1))
    elif "CHACHA20" in c:
        bits = 256
    elif "DES-CBC3" in c or "3DES" in c or "DES_EDE3" in c:
        bits = 112
    elif "DES" in c:
        bits = 56
    else:
        bits = None
    return {"bits": bits, "aead": aead, "weak": weak, "name": cipher}


def key_exchange_family(protocol: str | None, cipher: str | None, group: str | None) -> str:
    if group in PQC_GROUPS:
        return "ML-KEM hybrid"
    if protocol == "TLSv1.3":
        return "ECDHE" if group and not group.lower().startswith("ffdhe") else ("DHE" if group else "ECDHE")
    c = (cipher or "").upper()
    if c.startswith(("ECDHE-", "ECDH-")):
        return "ECDHE"
    if c.startswith(("DHE-", "EDH-")):
        return "DHE"
    return "RSA key transport"


def certificate_points(cert: dict | None) -> tuple[int, str]:
    if not cert:
        return 0, "No certificate could be read."
    if cert["expired"] or cert["not_yet_valid"]:
        return 0, "The certificate is outside its validity period."
    kt, bits = cert["key_type"], cert["key_bits"] or 0
    if cert["pq_signature"]:
        return 15, f"{kt}: post-quantum signature (NIST FIPS 204/205)."
    if kt.startswith("RSA"):
        return (9, f"{kt}: strong classical key, still quantum-vulnerable (Shor).") if bits >= 3072 else \
               (7, f"{kt}: acceptable classical key, quantum-vulnerable (Shor).") if bits >= 2048 else \
               (0, f"{kt}: below the 2048-bit minimum.")
    if kt in ("ECDSA P-384", "ECDSA P-521", "Ed448"):
        return 9, f"{kt}: strong classical key, still quantum-vulnerable (Shor)."
    if kt in ("ECDSA P-256", "Ed25519"):
        return 7, f"{kt}: standard classical key, quantum-vulnerable (Shor)."
    return 3, f"{kt}: unusual key type."


def evaluate(host: str, ip: str, main: dict, py: dict, support: dict[str, bool], started: float) -> dict:
    protocol = main.get("protocol") or py.get("version")
    cipher = main.get("cipher") or py.get("cipher")
    group = main.get("group") or py.get("group")
    family = key_exchange_family(protocol, cipher, group)
    sym = symmetric_profile(cipher)
    cert = describe_certificate(main.get("certs_pem") or [], py.get("cert_der"))
    verified = main.get("verify_code") == 0 if main.get("verify_code") is not None else bool(py.get("verified"))

    if protocol == "TLSv1.3" and group in PQC_GROUPS:
        tier, label = "quantum_safe", "Hybrid PQC Protected"
    elif protocol == "TLSv1.3" and family in ("ECDHE", "DHE") and sym["aead"] and not sym["weak"]:
        tier, label = "classical_modern", "Classical Only · HNDL Risk"
    else:
        tier, label = "legacy", "Legacy · Vulnerable"

    kx_pts, kx_why = {"ML-KEM hybrid": (50, f"{group}: NIST FIPS 203 ML-KEM hybrid key exchange."),
                      "ECDHE": (15, f"{group or 'ECDHE'}: forward-secret, but breakable by a future quantum computer."),
                      "DHE": (8, "Finite-field DHE: forward-secret, slow and quantum-vulnerable."),
                      "RSA key transport": (0, "Static RSA key exchange: no forward secrecy, quantum-vulnerable.")}[family]
    pr_pts = 15 if protocol == "TLSv1.3" else 6 if protocol == "TLSv1.2" else 0
    if sym["weak"] or not sym["bits"]:
        sy_pts, sy_why = 0, f"{cipher or 'Unknown cipher'}: weak or obsolete."
    elif sym["aead"] and sym["bits"] >= 256:
        sy_pts, sy_why = 15, f"{cipher}: 256-bit AEAD keeps ~128-bit strength against Grover's algorithm."
    elif sym["aead"]:
        sy_pts, sy_why = 10, f"{cipher}: 128-bit AEAD — sound today; 256-bit gives a larger quantum margin."
    else:
        sy_pts, sy_why = 3, f"{cipher}: CBC-mode cipher without AEAD."
    ce_pts, ce_why = certificate_points(cert)
    hy_pts = (3 if verified else 0) + (2 if main.get("ocsp_stapled") else 0)
    breakdown = [
        {"item": "Key exchange", "points": kx_pts, "max": 50, "reason": kx_why},
        {"item": "Protocol", "points": pr_pts, "max": 15, "reason": f"{protocol or 'Unknown'} negotiated."},
        {"item": "Symmetric cipher", "points": sy_pts, "max": 15, "reason": sy_why},
        {"item": "Certificate key", "points": ce_pts, "max": 15, "reason": ce_why},
        {"item": "Chain & OCSP", "points": hy_pts, "max": 5,
         "reason": ("Chain verifies" if verified else "Chain does not verify") + (", OCSP response stapled." if main.get("ocsp_stapled") else ", no OCSP stapling.")},
    ]
    offered_pqc = [g for g in OFFERED_GROUPS if g in PQC_GROUPS]
    return {
        "host": host, "ip": ip, "port": TARGET_PORT,
        "scanned_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "duration_ms": round((time.perf_counter() - started) * 1000),
        "verdict": {"tier": tier, "label": label, "score": sum(b["points"] for b in breakdown), "breakdown": breakdown,
                    "hndl_protected": tier == "quantum_safe"},
        "kex": {"group": group, "family": family, "pqc": group in PQC_GROUPS, "fips203": group in PQC_GROUPS,
                "components": PQC_GROUPS.get(group), "codepoint": (PQC_GROUPS.get(group) or {}).get("codepoint"),
                "temp_key": main.get("temp_key")},
        "protocol": {"version": protocol, "cipher": cipher, "symmetric_bits": sym["bits"], "aead": sym["aead"], "weak": sym["weak"]},
        "certificate": {**(cert or {}), "verified": verified,
                        "verify_message": main.get("verify_message") or py.get("verify_error")} if cert else None,
        "handshake": {
            "client_offered_groups": OFFERED_GROUPS, "server_selected_group": group,
            "pqc_group_support": {g: support.get(g) for g in offered_pqc},
            "alpn": main.get("alpn") or py.get("alpn"),
            "ocsp_stapled": bool(main.get("ocsp_stapled")), "ocsp_cert_status": main.get("ocsp_cert_status"),
            "peer_signature_type": main.get("peer_signature_type"), "peer_signing_digest": main.get("peer_signing_digest"),
            "latency_ms": {"tcp": py.get("tcp_ms"), "tls": py.get("tls_ms"), "openssl_probe": main.get("ms")},
            "cross_check": {"python_ssl_version": py.get("version"), "python_ssl_cipher": py.get("cipher"),
                            "agrees": (py.get("version") in (None, protocol)) and (py.get("cipher") in (None, cipher))},
        },
        "engine": {"openssl": OPENSSL_INFO.get("version"), "python_ssl": ssl.OPENSSL_VERSION},
    }


# ---------------------------------------------------------------------------------------- streaming
STEPS = {"dns": "Resolving DNS", "hello": "Initiating TLS 1.3 ClientHello",
         "keyshare": "Inspecting Key Share", "fips203": "Evaluating NIST FIPS 203 Compliance"}


def _event(**kw) -> bytes:
    return (json.dumps(kw, separators=(",", ":")) + "\n").encode()


async def scan_stream(host: str) -> AsyncIterator[bytes]:
    started = time.perf_counter()
    try:
        await asyncio.wait_for(scan_slots.acquire(), 15)
    except asyncio.TimeoutError:
        yield _event(type="error", message="The scanner is busy. Please try again in a minute.")
        return
    try:
        yield _event(type="step", id="dns", state="active", label=STEPS["dns"])
        try:
            ips = await resolve_target(host)
        except TargetError as e:
            yield _event(type="step", id="dns", state="error", label=STEPS["dns"], detail=str(e))
            yield _event(type="error", message=str(e))
            return
        ip = ips[0]
        yield _event(type="step", id="dns", state="done", label=STEPS["dns"],
                     detail=ip + (f" (+{len(ips) - 1} more)" if len(ips) > 1 else ""))

        yield _event(type="step", id="hello", state="active", label=STEPS["hello"],
                     detail="Offering " + ", ".join(OFFERED_GROUPS))
        main, py = await asyncio.gather(run_s_client(ip, host, ":".join(OFFERED_GROUPS)),
                                        asyncio.to_thread(python_ssl_probe, ip, host))
        if not main.get("ok"):  # very old servers: retry allowing legacy ciphers so we can still grade them
            legacy = await run_s_client(ip, host, ":".join(OFFERED_GROUPS), extra=["-cipher", "ALL:@SECLEVEL=0"])
            if legacy.get("ok"):
                main = legacy
        if not main.get("ok") and not py.get("ok"):
            msg = f"No TLS handshake with {host} on port 443: {main.get('error') or py.get('error')}."
            yield _event(type="step", id="hello", state="error", label=STEPS["hello"], detail=msg)
            yield _event(type="error", message=msg)
            return
        yield _event(type="step", id="hello", state="done", label=STEPS["hello"],
                     detail=f"{main.get('protocol') or py.get('version')} · {main.get('cipher') or py.get('cipher')}"
                            + (f" · {py['tls_ms']:.0f} ms" if py.get("tls_ms") else ""))

        yield _event(type="step", id="keyshare", state="active", label=STEPS["keyshare"])
        results = await asyncio.gather(*(run_s_client(ip, host, g, extra=["-tls1_3"], full=False) for g in PQC_GROUPS))
        support = {g: bool(r.get("ok") and r.get("group") == g) for g, r in zip(PQC_GROUPS, results)}
        group = main.get("group") or py.get("group")
        yield _event(type="step", id="keyshare", state="done", label=STEPS["keyshare"],
                     detail=f"ServerHello selected {group or 'no key share (RSA key transport)'}")

        yield _event(type="step", id="fips203", state="active", label=STEPS["fips203"])
        result = evaluate(host, ip, main, py, support, started)
        yield _event(type="step", id="fips203", state="done", label=STEPS["fips203"], detail=result["verdict"]["label"])
        yield _event(type="result", data=result)
    except Exception:  # never leak internals to the client
        log.exception("scan failed")
        yield _event(type="error", message="The inspection failed unexpectedly. Please try again.")
    finally:
        scan_slots.release()


# ---------------------------------------------------------------------------------------------- app
def detect_openssl() -> dict:
    try:
        ver = subprocess.run([OPENSSL_BIN, "version"], capture_output=True, text=True, timeout=5).stdout.strip()
        groups = subprocess.run([OPENSSL_BIN, "list", "-tls-groups"], capture_output=True, text=True, timeout=5).stdout
    except (OSError, subprocess.SubprocessError):
        return {"version": None, "pqc": False}
    m = re.search(r"OpenSSL (\d+)\.(\d+)", ver)
    ok_version = bool(m) and (int(m.group(1)), int(m.group(2))) >= (3, 5)
    return {"version": ver, "pqc": ok_version and all(g in groups for g in PQC_GROUPS)}


OPENSSL_INFO = detect_openssl()
if not OPENSSL_INFO["pqc"]:
    log.error("OpenSSL 3.5+ with ML-KEM hybrid groups not found (%s); scans will be refused.", OPENSSL_INFO["version"])

app = FastAPI(title="PQC-ready-check", docs_url=None, redoc_url=None, openapi_url=None)
app.add_middleware(CORSMiddleware, allow_origins=ALLOWED_ORIGINS, allow_methods=["GET", "POST"],
                   allow_headers=["Content-Type"], max_age=600)


class ScanRequest(BaseModel):
    domain: str = Field(max_length=300)
    turnstile_token: str = Field(default="", max_length=2048)


@app.get("/api/health")
async def health() -> dict:
    return {"ok": OPENSSL_INFO["pqc"] and bool(TURNSTILE_SECRET), "openssl": OPENSSL_INFO["version"],
            "pqc_groups_available": OPENSSL_INFO["pqc"], "turnstile_configured": bool(TURNSTILE_SECRET)}


@app.post("/api/scan")
async def scan(body: ScanRequest, request: Request) -> StreamingResponse:
    ip = client_ip(request)
    wait = limiter.check(ip)
    if wait is not None:
        raise HTTPException(429, f"Too many scans from your network. Try again in {wait} seconds.",
                            headers={"Retry-After": str(wait)})
    try:
        host = sanitize_domain(body.domain)
    except InputError as e:
        raise HTTPException(400, str(e)) from None
    if not OPENSSL_INFO["pqc"]:
        raise HTTPException(503, "The scanner's OpenSSL does not support ML-KEM; scans are disabled.")
    await verify_turnstile(body.turnstile_token, ip)  # before any socket to the target
    return StreamingResponse(scan_stream(host), media_type="application/x-ndjson",
                             headers={"Cache-Control": "no-store", "X-Accel-Buffering": "no"})
