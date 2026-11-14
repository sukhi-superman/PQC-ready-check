"""Backend tests. Run from backend/:  OPENSSL_BIN=<openssl 3.5+> python -m pytest -q

Integration tests start local `openssl s_server` instances (hybrid PQC, classical TLS 1.3, legacy TLS 1.2)
and run the real probes against them; the SSRF guard and port are monkeypatched to point at localhost
for those tests only (the production code has no switch to allow private targets)."""

import asyncio
import datetime as dt
import json
import os
import socket
import subprocess
import sys
import time
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509.oid import NameOID

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import main  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

client = TestClient(main.app)
HAS_PQC_OPENSSL = main.OPENSSL_INFO["pqc"]


# ------------------------------------------------------------------------------------- sanitising
@pytest.mark.parametrize("raw,expected", [
    ("example.com", "example.com"),
    ("  HTTPS://Example.COM/path?q=1#x ", "example.com"),
    ("http://user:pass@sub.example.co.uk:8443/", "sub.example.co.uk"),
    ("example.com.", "example.com"),
    ("bücher.de", "xn--bcher-kva.de"),
    ("cloudflare.com:443", "cloudflare.com"),
    ("evil.com\\@127.0.0.1", "evil.com"),            # backslash ends the host, like browsers do
    ("http://127.0.0.1@evil.com/", "evil.com"),        # userinfo is dropped, the real host is kept
])
def test_sanitize_ok(raw, expected):
    assert main.sanitize_domain(raw) == expected


@pytest.mark.parametrize("raw", [
    "", "   ", "localhost", "127.0.0.1", "http://10.0.0.1/", "[::1]", "https://[::1]:443", "2130706433",
    "0x7f.0.0.1", "169.254.169.254", "-bad-.com", "a..com", "exa mple.com", "x" * 260 + ".com",
    "example.c0m1", None, 12345, "http://127.0.0.1@", "@10.0.0.1",
])
def test_sanitize_rejects(raw):
    with pytest.raises(main.InputError):
        main.sanitize_domain(raw)


# -------------------------------------------------------------------------------------------- SSRF
@pytest.mark.parametrize("ip,ok", [
    ("1.1.1.1", True), ("8.8.8.8", True), ("2606:4700:4700::1111", True),
    ("127.0.0.1", False), ("10.1.2.3", False), ("172.16.0.1", False), ("192.168.1.1", False),
    ("169.254.169.254", False), ("100.64.0.1", False), ("0.0.0.0", False), ("224.0.0.1", False),
    ("240.0.0.1", False), ("::1", False), ("fe80::1", False), ("fc00::1", False), ("::ffff:127.0.0.1", False),
    ("::ffff:10.0.0.1", False), ("2002:7f00:0001::1", False), ("192.0.2.1", False), ("198.18.0.1", False),
])
def test_is_public_ip(ip, ok):
    assert main.is_public_ip(ip) is ok


def test_resolve_blocks_any_private_answer(monkeypatch):
    async def fake_getaddrinfo(host, port, type):  # noqa: A002
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", port)),
                (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", port))]
    loop = asyncio.new_event_loop()
    monkeypatch.setattr(loop, "getaddrinfo", fake_getaddrinfo)
    with pytest.raises(main.TargetError, match="private, loopback or reserved"):
        loop.run_until_complete(main.resolve_target("rebind.example"))
    loop.close()


def test_resolve_localhost_names_blocked():
    with pytest.raises(main.TargetError):
        asyncio.run(main.resolve_target("localhost"))


# -------------------------------------------------------------------------------------- rate limit
def test_rate_limiter_minute_and_hour():
    rl = main.RateLimiter(per_minute=2, per_hour=3)
    assert rl.check("a", 0) is None and rl.check("a", 1) is None
    assert rl.check("a", 2) is not None             # 3rd within a minute
    assert rl.check("b", 2) is None                 # other clients unaffected
    assert rl.check("a", 70) is None                # new minute
    assert rl.check("a", 140) is not None           # 4th within the hour
    assert rl.check("a", 3700) is None              # hour window moved on


# ---------------------------------------------------------------------- API gate: Turnstile first
@pytest.fixture
def no_network(monkeypatch):
    calls = []

    async def fake_resolve(host):
        calls.append(host)
        raise AssertionError("resolve_target must not run before Turnstile passes")
    monkeypatch.setattr(main, "resolve_target", fake_resolve)
    monkeypatch.setattr(main, "limiter", main.RateLimiter(100, 1000))
    monkeypatch.setattr(main, "OPENSSL_INFO", {"version": "OpenSSL 3.5.x", "pqc": True})
    return calls


class FakeSiteverify:
    result = {"success": False}
    seen = []

    def __init__(self, *a, **k): pass
    async def __aenter__(self): return self
    async def __aexit__(self, *a): return False

    async def post(self, url, data):
        FakeSiteverify.seen.append((url, data))

        class R:
            def json(_self): return FakeSiteverify.result
        return R()


def test_scan_refused_without_turnstile_secret(no_network, monkeypatch):
    monkeypatch.setattr(main, "TURNSTILE_SECRET", "")
    r = client.post("/api/scan", json={"domain": "example.com", "turnstile_token": "x"})
    assert r.status_code == 503 and not no_network


def test_scan_refused_with_missing_token(no_network, monkeypatch):
    monkeypatch.setattr(main, "TURNSTILE_SECRET", "secret")
    r = client.post("/api/scan", json={"domain": "example.com"})
    assert r.status_code == 403 and not no_network


def test_scan_refused_when_siteverify_says_no(no_network, monkeypatch):
    monkeypatch.setattr(main, "TURNSTILE_SECRET", "secret")
    monkeypatch.setattr(main.httpx, "AsyncClient", FakeSiteverify)
    FakeSiteverify.result, FakeSiteverify.seen = {"success": False, "error-codes": ["invalid-input-response"]}, []
    r = client.post("/api/scan", json={"domain": "example.com", "turnstile_token": "tok"})
    assert r.status_code == 403 and not no_network
    url, data = FakeSiteverify.seen[0]
    assert url == main.SITEVERIFY_URL and data["secret"] == "secret" and data["response"] == "tok"


def test_scan_hostname_pinning(no_network, monkeypatch):
    monkeypatch.setattr(main, "TURNSTILE_SECRET", "secret")
    monkeypatch.setattr(main, "TURNSTILE_HOSTNAMES", {"sukhi-superman.github.io"})
    monkeypatch.setattr(main.httpx, "AsyncClient", FakeSiteverify)
    FakeSiteverify.result = {"success": True, "hostname": "evil.example"}
    r = client.post("/api/scan", json={"domain": "example.com", "turnstile_token": "tok"})
    assert r.status_code == 403 and not no_network


def test_bad_domain_rejected_before_turnstile(no_network, monkeypatch):
    monkeypatch.setattr(main, "TURNSTILE_SECRET", "secret")
    FakeSiteverify.seen = []
    monkeypatch.setattr(main.httpx, "AsyncClient", FakeSiteverify)
    r = client.post("/api/scan", json={"domain": "http://127.0.0.1/", "turnstile_token": "tok"})
    assert r.status_code == 400 and not FakeSiteverify.seen and not no_network


def test_rate_limit_returns_429(no_network, monkeypatch):
    monkeypatch.setattr(main, "limiter", main.RateLimiter(1, 10))
    monkeypatch.setattr(main, "TURNSTILE_SECRET", "")
    client.post("/api/scan", json={"domain": "example.com"})
    r = client.post("/api/scan", json={"domain": "example.com"})
    assert r.status_code == 429 and "Retry-After" in r.headers


def test_cors_only_allows_configured_origin():
    r = client.options("/api/scan", headers={"Origin": "https://evil.example", "Access-Control-Request-Method": "POST"})
    assert r.headers.get("access-control-allow-origin") is None
    r = client.options("/api/scan", headers={"Origin": "https://sukhi-superman.github.io", "Access-Control-Request-Method": "POST"})
    assert r.headers.get("access-control-allow-origin") == "https://sukhi-superman.github.io"


# ------------------------------------------------------------------------------- parsing & scoring
def test_symmetric_profile():
    assert main.symmetric_profile("TLS_AES_128_GCM_SHA256") == {"bits": 128, "aead": True, "weak": False, "name": "TLS_AES_128_GCM_SHA256"}
    assert main.symmetric_profile("TLS_AES_256_GCM_SHA384")["bits"] == 256
    assert main.symmetric_profile("TLS_CHACHA20_POLY1305_SHA256")["bits"] == 256
    assert main.symmetric_profile("ECDHE-RSA-AES128-SHA256")["aead"] is False
    assert main.symmetric_profile("DES-CBC3-SHA")["weak"] is True
    assert main.symmetric_profile("RC4-SHA")["weak"] is True


def test_parse_classical_temp_key_tls12():
    text = "CONNECTED(00000003)\nServer Temp Key: ECDH, prime256v1, 256 bits\nNew, TLSv1.2, Cipher is ECDHE-RSA-AES128-GCM-SHA256\nProtocol: TLSv1.2\n"
    p = main.parse_s_client(text)
    assert p["ok"] and p["group"] == "P-256" and p["protocol"] == "TLSv1.2"


def test_parse_failed_handshake():
    p = main.parse_s_client("CONNECTED(00000003)\n...:ssl/record/rec_layer_s3.c:...:sslv3 alert handshake failure\nNew, (NONE), Cipher is (NONE)\n")
    assert not p["ok"] and p["error"] == "the server rejected every option offered"


# ------------------------------------------------------------------------------------- integration
def _cert(key, cn):
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn), x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Local Test CA")])
    now = dt.datetime.now(dt.timezone.utc)
    return (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
            .serial_number(x509.random_serial_number()).not_valid_before(now - dt.timedelta(days=1))
            .not_valid_after(now + dt.timedelta(days=30))
            .add_extension(x509.SubjectAlternativeName([x509.DNSName(cn)]), critical=False)
            .sign(key, hashes.SHA256()))


def _write(tmp, name, key, cert):
    (tmp / f"{name}.key").write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    (tmp / f"{name}.crt").write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    return str(tmp / f"{name}.crt"), str(tmp / f"{name}.key")


def _free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


SERVERS = {
    "hybrid":    ("ec", ["-groups", "X25519MLKEM768:X25519", "-alpn", "h2,http/1.1"]),
    "p256mlkem": ("ec", ["-groups", "SecP256r1MLKEM768:P-256"]),
    "classical": ("ec", ["-groups", "X25519:P-256"]),
    "tls12ecdhe": ("rsa", ["-tls1_2", "-cipher", "ECDHE-RSA-AES128-GCM-SHA256"]),
    "legacy":    ("rsa", ["-tls1_2", "-cipher", "AES128-SHA"]),
}


@pytest.fixture(scope="module")
def tls_servers(tmp_path_factory):
    if not HAS_PQC_OPENSSL:
        pytest.skip("needs OpenSSL 3.5+ (set OPENSSL_BIN)")
    tmp = tmp_path_factory.mktemp("certs")
    eck = ec.generate_private_key(ec.SECP256R1())
    rk = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    files = {"ec": _write(tmp, "ec", eck, _cert(eck, "pqc.test")), "rsa": _write(tmp, "rsa", rk, _cert(rk, "pqc.test"))}
    procs, ports = [], {}
    for name, (kind, extra) in SERVERS.items():
        port = _free_port()
        crt, key = files[kind]
        procs.append(subprocess.Popen([main.OPENSSL_BIN, "s_server", "-accept", f"127.0.0.1:{port}", "-cert", crt,
                                       "-key", key, "-www", *extra], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL))
        ports[name] = port
    time.sleep(1.0)
    yield ports
    for p in procs:
        p.terminate()


def _scan(monkeypatch, port):
    async def local(host):
        return ["127.0.0.1"]
    async def ok(token, ip):
        return None
    monkeypatch.setattr(main, "resolve_target", local)
    monkeypatch.setattr(main, "verify_turnstile", ok)
    monkeypatch.setattr(main, "TARGET_PORT", port)
    monkeypatch.setattr(main, "limiter", main.RateLimiter(100, 1000))
    with client.stream("POST", "/api/scan", json={"domain": "pqc.test", "turnstile_token": "t"}) as r:
        assert r.status_code == 200 and r.headers["content-type"].startswith("application/x-ndjson")
        events = [json.loads(line) for line in r.iter_lines() if line]
    return events


def test_live_hybrid_pqc(tls_servers, monkeypatch):
    ev = _scan(monkeypatch, tls_servers["hybrid"])
    steps = [(e["id"], e["state"]) for e in ev if e["type"] == "step"]
    assert steps == [("dns", "active"), ("dns", "done"), ("hello", "active"), ("hello", "done"),
                     ("keyshare", "active"), ("keyshare", "done"), ("fips203", "active"), ("fips203", "done")]
    r = ev[-1]["data"]
    assert ev[-1]["type"] == "result"
    assert r["verdict"]["tier"] == "quantum_safe" and r["kex"]["group"] == "X25519MLKEM768" and r["kex"]["codepoint"] == "0x11EC"
    assert r["protocol"]["version"] == "TLSv1.3" and r["handshake"]["alpn"] == "h2"
    assert r["handshake"]["pqc_group_support"] == {"X25519MLKEM768": True, "SecP256r1MLKEM768": False, "SecP384r1MLKEM1024": False}
    assert r["certificate"]["key_type"] == "ECDSA P-256" and r["certificate"]["verified"] is False  # self-signed
    assert r["handshake"]["latency_ms"]["tls"] is not None and r["handshake"]["cross_check"]["agrees"]
    assert 75 <= r["verdict"]["score"] <= 100


def test_live_p256_hybrid_selected_via_helloretry(tls_servers, monkeypatch):
    r = _scan(monkeypatch, tls_servers["p256mlkem"])[-1]["data"]
    assert r["kex"]["group"] == "SecP256r1MLKEM768" and r["verdict"]["tier"] == "quantum_safe"
    assert r["handshake"]["pqc_group_support"]["SecP256r1MLKEM768"] is True


def test_live_classical_tls13(tls_servers, monkeypatch):
    r = _scan(monkeypatch, tls_servers["classical"])[-1]["data"]
    assert r["verdict"]["tier"] == "classical_modern" and r["kex"]["group"] == "X25519" and not r["kex"]["pqc"]
    assert not any(r["handshake"]["pqc_group_support"].values())
    assert r["verdict"]["hndl_protected"] is False and r["verdict"]["score"] < 70


def test_live_tls12_ecdhe_is_legacy(tls_servers, monkeypatch):
    r = _scan(monkeypatch, tls_servers["tls12ecdhe"])[-1]["data"]
    assert r["verdict"]["tier"] == "legacy" and r["kex"]["family"] == "ECDHE" and r["protocol"]["version"] == "TLSv1.2"
    assert r["certificate"]["key_type"] == "RSA-2048"


def test_live_rsa_key_transport_is_legacy(tls_servers, monkeypatch):
    r = _scan(monkeypatch, tls_servers["legacy"])[-1]["data"]
    assert r["verdict"]["tier"] == "legacy" and r["kex"]["family"] == "RSA key transport" and r["kex"]["group"] is None
    assert r["protocol"]["aead"] is False and r["verdict"]["score"] < 40


def test_live_nothing_listening(tls_servers, monkeypatch):
    ev = _scan(monkeypatch, _free_port())
    assert ev[-1]["type"] == "error" and "No TLS handshake" in ev[-1]["message"]
