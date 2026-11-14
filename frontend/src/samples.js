// Sample reports shown while the scanning backend is not connected (and offered as previews).
// Same shape as the backend's result payload. Hosts use the reserved .example TLD and IPs come from the
// 203.0.113.0/24 documentation range, so they can never be mistaken for a scan of a real website.

const OFFERED = ['X25519MLKEM768', 'SecP256r1MLKEM768', 'SecP384r1MLKEM1024', 'X25519', 'P-256', 'P-384'];

const cert = (over) => ({
  subject_cn: over.cn, issuer_cn: 'Example Issuing CA R3', issuer_org: 'Example Trust Services',
  not_before: '2026-09-01T00:00:00+00:00', not_after: '2026-11-30T23:59:59+00:00', days_remaining: 16,
  expired: false, not_yet_valid: false, key_type: 'ECDSA P-256', key_bits: 256, signature_algorithm: 'ecdsa-with-SHA256',
  pq_signature: false, san_count: 2, sans_sample: [over.cn, 'www.' + over.cn], chain_length: 2, self_signed: false,
  chain: [{ subject_cn: over.cn, issuer_cn: 'Example Issuing CA R3' }, { subject_cn: 'Example Issuing CA R3', issuer_cn: 'Example Root CA' }],
  verified: true, verify_message: 'ok', ...over.extra,
});

export const SAMPLES = {
  quantum_safe: {
    host: 'hybrid-pqc.example', ip: '203.0.113.10', port: 443, scanned_at: '2026-11-14T09:30:00+00:00', duration_ms: 812,
    verdict: {
      tier: 'quantum_safe', label: 'Hybrid PQC Protected', score: 92, hndl_protected: true,
      breakdown: [
        { item: 'Key exchange', points: 50, max: 50, reason: 'X25519MLKEM768: NIST FIPS 203 ML-KEM hybrid key exchange.' },
        { item: 'Protocol', points: 15, max: 15, reason: 'TLSv1.3 negotiated.' },
        { item: 'Symmetric cipher', points: 15, max: 15, reason: "TLS_AES_256_GCM_SHA384: 256-bit AEAD keeps ~128-bit strength against Grover's algorithm." },
        { item: 'Certificate key', points: 7, max: 15, reason: 'ECDSA P-256: standard classical key, quantum-vulnerable (Shor).' },
        { item: 'Chain & OCSP', points: 5, max: 5, reason: 'Chain verifies, OCSP response stapled.' },
      ],
    },
    kex: { group: 'X25519MLKEM768', family: 'ML-KEM hybrid', pqc: true, fips203: true, codepoint: '0x11EC',
      components: { classical: 'X25519', kem: 'ML-KEM-768', codepoint: '0x11EC', nist_level: '3' }, temp_key: null },
    protocol: { version: 'TLSv1.3', cipher: 'TLS_AES_256_GCM_SHA384', symmetric_bits: 256, aead: true, weak: false },
    certificate: cert({ cn: 'hybrid-pqc.example' }),
    handshake: {
      client_offered_groups: OFFERED, server_selected_group: 'X25519MLKEM768',
      pqc_group_support: { X25519MLKEM768: true, SecP256r1MLKEM768: true, SecP384r1MLKEM1024: false },
      alpn: 'h2', ocsp_stapled: true, ocsp_cert_status: 'good', peer_signature_type: 'ecdsa_secp256r1_sha256', peer_signing_digest: 'SHA256',
      latency_ms: { tcp: 11.8, tls: 24.6, openssl_probe: 58 },
      cross_check: { python_ssl_version: 'TLSv1.3', python_ssl_cipher: 'TLS_AES_256_GCM_SHA384', agrees: true },
    },
    engine: { openssl: 'OpenSSL 3.5.x (sample)', python_ssl: 'OpenSSL 3.5.x (sample)' },
  },
  classical_modern: {
    host: 'classical-tls13.example', ip: '203.0.113.20', port: 443, scanned_at: '2026-11-14T09:31:00+00:00', duration_ms: 944,
    verdict: {
      tier: 'classical_modern', label: 'Classical Only · HNDL Risk', score: 55, hndl_protected: false,
      breakdown: [
        { item: 'Key exchange', points: 15, max: 50, reason: 'X25519: forward-secret, but breakable by a future quantum computer.' },
        { item: 'Protocol', points: 15, max: 15, reason: 'TLSv1.3 negotiated.' },
        { item: 'Symmetric cipher', points: 15, max: 15, reason: "TLS_AES_256_GCM_SHA384: 256-bit AEAD keeps ~128-bit strength against Grover's algorithm." },
        { item: 'Certificate key', points: 7, max: 15, reason: 'RSA-2048: acceptable classical key, quantum-vulnerable (Shor).' },
        { item: 'Chain & OCSP', points: 3, max: 5, reason: 'Chain verifies, no OCSP stapling.' },
      ],
    },
    kex: { group: 'X25519', family: 'ECDHE', pqc: false, fips203: false, codepoint: null, components: null,
      temp_key: { type: 'X25519', curve: '', bits: 253 } },
    protocol: { version: 'TLSv1.3', cipher: 'TLS_AES_256_GCM_SHA384', symmetric_bits: 256, aead: true, weak: false },
    certificate: cert({ cn: 'classical-tls13.example', extra: { key_type: 'RSA-2048', key_bits: 2048, signature_algorithm: 'sha256WithRSAEncryption' } }),
    handshake: {
      client_offered_groups: OFFERED, server_selected_group: 'X25519',
      pqc_group_support: { X25519MLKEM768: false, SecP256r1MLKEM768: false, SecP384r1MLKEM1024: false },
      alpn: 'h2', ocsp_stapled: false, ocsp_cert_status: null, peer_signature_type: 'rsa_pss_rsae_sha256', peer_signing_digest: 'SHA256',
      latency_ms: { tcp: 14.2, tls: 31.0, openssl_probe: 66 },
      cross_check: { python_ssl_version: 'TLSv1.3', python_ssl_cipher: 'TLS_AES_256_GCM_SHA384', agrees: true },
    },
    engine: { openssl: 'OpenSSL 3.5.x (sample)', python_ssl: 'OpenSSL 3.5.x (sample)' },
  },
  legacy: {
    host: 'legacy-tls12.example', ip: '203.0.113.30', port: 443, scanned_at: '2026-11-14T09:32:00+00:00', duration_ms: 1203,
    verdict: {
      tier: 'legacy', label: 'Legacy · Vulnerable', score: 19, hndl_protected: false,
      breakdown: [
        { item: 'Key exchange', points: 0, max: 50, reason: 'Static RSA key exchange: no forward secrecy, quantum-vulnerable.' },
        { item: 'Protocol', points: 6, max: 15, reason: 'TLSv1.2 negotiated.' },
        { item: 'Symmetric cipher', points: 3, max: 15, reason: 'AES128-SHA: CBC-mode cipher without AEAD.' },
        { item: 'Certificate key', points: 7, max: 15, reason: 'RSA-2048: acceptable classical key, quantum-vulnerable (Shor).' },
        { item: 'Chain & OCSP', points: 3, max: 5, reason: 'Chain verifies, no OCSP stapling.' },
      ],
    },
    kex: { group: null, family: 'RSA key transport', pqc: false, fips203: false, codepoint: null, components: null, temp_key: null },
    protocol: { version: 'TLSv1.2', cipher: 'AES128-SHA', symmetric_bits: 128, aead: false, weak: false },
    certificate: cert({ cn: 'legacy-tls12.example', extra: { key_type: 'RSA-2048', key_bits: 2048, signature_algorithm: 'sha256WithRSAEncryption' } }),
    handshake: {
      client_offered_groups: OFFERED, server_selected_group: null,
      pqc_group_support: { X25519MLKEM768: false, SecP256r1MLKEM768: false, SecP384r1MLKEM1024: false },
      alpn: null, ocsp_stapled: false, ocsp_cert_status: null, peer_signature_type: null, peer_signing_digest: null,
      latency_ms: { tcp: 22.5, tls: 48.3, openssl_probe: 91 },
      cross_check: { python_ssl_version: 'TLSv1.2', python_ssl_cipher: 'AES128-SHA', agrees: true },
    },
    engine: { openssl: 'OpenSSL 3.5.x (sample)', python_ssl: 'OpenSSL 3.5.x (sample)' },
  },
};
