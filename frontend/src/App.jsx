import { useCallback, useEffect, useRef, useState } from 'react';
import {
  Activity, AlertTriangle, ArrowRight, Atom, BookOpen, Check, CheckCircle2, ChevronRight, Circle, Clock, ExternalLink,
  FileBadge, Info, KeyRound, Loader2, Lock, Minus, Network, RefreshCw, ShieldAlert, ShieldCheck, ShieldX, X, XCircle,
} from 'lucide-react';
import { SAMPLES } from './samples.js';

/* ------------------------------------------------------------------------------------------ config
   VITE_API_URL            the FastAPI backend, e.g. https://pqc-api.example.com  (empty = sample mode)
   VITE_TURNSTILE_SITE_KEY Cloudflare Turnstile site key (defaults to Cloudflare's always-pass test key) */
const API_URL = (import.meta.env.VITE_API_URL || '').replace(/\/+$/, '');
const SITE_KEY = import.meta.env.VITE_TURNSTILE_SITE_KEY || '1x00000000000000000000AA';
const LIVE = Boolean(API_URL);
const USING_TEST_KEY = SITE_KEY.startsWith('1x0000') || SITE_KEY.startsWith('2x0000') || SITE_KEY.startsWith('3x0000');

const STEP_DEFS = [
  { id: 'dns', label: 'Resolving DNS' },
  { id: 'hello', label: 'Initiating TLS 1.3 ClientHello' },
  { id: 'keyshare', label: 'Inspecting Key Share' },
  { id: 'fips203', label: 'Evaluating NIST FIPS 203 Compliance' },
];

const TIERS = {
  quantum_safe: { label: 'Hybrid PQC Protected', short: 'Quantum-safe', color: 'var(--color-safe)', Icon: ShieldCheck, chip: 'bg-safe/15 text-safe ring-safe/30' },
  classical_modern: { label: 'Classical Only / HNDL Risk', short: 'Classical only', color: 'var(--color-warn)', Icon: ShieldAlert, chip: 'bg-warn/15 text-warn ring-warn/30' },
  legacy: { label: 'Legacy / Vulnerable', short: 'At risk', color: 'var(--color-risk)', Icon: ShieldX, chip: 'bg-risk/15 text-risk ring-risk/30' },
};

const PQC_INFO = {
  X25519MLKEM768: { classical: 'X25519', kem: 'ML-KEM-768', codepoint: '0x11EC' },
  SecP256r1MLKEM768: { classical: 'P-256', kem: 'ML-KEM-768', codepoint: '0x11EB' },
  SecP384r1MLKEM1024: { classical: 'P-384', kem: 'ML-KEM-1024', codepoint: '0x11ED' },
};

/* ---------------------------------------------------------------------------------------- helpers */
// Mirrors the backend's sanitising so users see what will actually be scanned (the backend re-checks).
export function cleanDomain(raw) {
  let s = (raw || '').trim();
  s = s.replace(/^[a-z][a-z0-9+.-]*:\/\//i, '').split(/[/?#\\]/)[0];
  s = s.slice(s.lastIndexOf('@') + 1);
  if (s.startsWith('[')) return null;
  s = s.split(':')[0].replace(/\.+$/, '').toLowerCase();
  if (!s || s.length > 253 || /^[\d.]+$/.test(s)) return null;
  const labels = s.split('.');
  if (labels.length < 2) return null;
  if (!labels.every((l) => /^(?!-)[\p{L}\p{N}-]{1,63}(?<!-)$/u.test(l))) return null;
  if (!/^(xn--[a-z0-9-]+|\p{L}{2,63})$/u.test(labels[labels.length - 1])) return null;
  return s;
}

const fmtDate = (iso) => (iso ? new Date(iso).toLocaleDateString('en-GB', { day: '2-digit', month: 'short', year: 'numeric' }) : '—');
const fmtTime = (iso) => (iso ? new Date(iso).toLocaleString('en-GB', { day: '2-digit', month: 'short', hour: '2-digit', minute: '2-digit', timeZoneName: 'short' }) : '—');
const ms = (v) => (v == null ? '—' : `${v < 10 ? v.toFixed(1) : Math.round(v)} ms`);

let turnstilePromise;
function loadTurnstile() {
  if (window.turnstile) return Promise.resolve(window.turnstile);
  if (!turnstilePromise) {
    turnstilePromise = new Promise((resolve, reject) => {
      const s = document.createElement('script');
      s.src = 'https://challenges.cloudflare.com/turnstile/v0/api.js?render=explicit';
      s.async = true;
      s.onload = () => (window.turnstile ? resolve(window.turnstile) : reject(new Error('turnstile missing')));
      s.onerror = () => { turnstilePromise = null; reject(new Error('turnstile blocked')); };
      document.head.appendChild(s);
      setTimeout(() => reject(new Error('turnstile timeout')), 12000);
    });
  }
  return turnstilePromise;
}

// POST /api/scan and read the NDJSON progress stream line by line.
async function streamScan(domain, token, onEvent, signal) {
  const res = await fetch(`${API_URL}/api/scan`, {
    method: 'POST', headers: { 'Content-Type': 'application/json' }, signal,
    body: JSON.stringify({ domain, turnstile_token: token }),
  });
  if (!res.ok) {
    let detail;
    try { detail = (await res.json()).detail; } catch { /* not JSON */ }
    throw new Error(typeof detail === 'string' ? detail : `The scan request failed (HTTP ${res.status}).`);
  }
  const reader = res.body.getReader();
  const decoder = new TextDecoder();
  let buf = '';
  for (;;) {
    const { value, done } = await reader.read();
    if (done) break;
    buf += decoder.decode(value, { stream: true });
    let i;
    while ((i = buf.indexOf('\n')) >= 0) {
      const line = buf.slice(0, i).trim();
      buf = buf.slice(i + 1);
      if (line) onEvent(JSON.parse(line));
    }
  }
  if (buf.trim()) onEvent(JSON.parse(buf));
}

/* -------------------------------------------------------------------------------------------- app */
export default function App() {
  const [input, setInput] = useState('');
  const [token, setToken] = useState('');
  const [resetKey, setResetKey] = useState(0);
  const [status, setStatus] = useState('idle'); // idle | scanning | done | error
  const [steps, setSteps] = useState({});
  const [error, setError] = useState('');
  const [notice, setNotice] = useState('');
  const [report, setReport] = useState(LIVE ? null : SAMPLES.quantum_safe);
  const [isSample, setIsSample] = useState(!LIVE);
  const abortRef = useRef(null);
  const reportRef = useRef(null);

  const showSample = (tier) => {
    setReport(SAMPLES[tier]);
    setIsSample(true);
    requestAnimationFrame(() => reportRef.current?.scrollIntoView({ behavior: 'smooth', block: 'start' }));
  };

  const onSubmit = async (e) => {
    e.preventDefault();
    setError(''); setNotice('');
    const domain = cleanDomain(input);
    if (!domain) { setError('Enter a public domain name, such as cloudflare.com.'); return; }
    if (!LIVE) {
      setNotice(`Live scanning isn't switched on yet, so ${domain} was not scanned. The report below is a labelled sample showing what a scan returns.`);
      showSample('quantum_safe');
      return;
    }
    if (!token) { setError('Please complete the verification check first.'); return; }
    abortRef.current?.abort();
    const ctrl = new AbortController();
    abortRef.current = ctrl;
    setStatus('scanning'); setSteps({}); setReport(null); setIsSample(false);
    try {
      await streamScan(domain, token, (ev) => {
        if (ev.type === 'step') setSteps((s) => ({ ...s, [ev.id]: { state: ev.state, detail: ev.detail } }));
        else if (ev.type === 'result') {
          setReport(ev.data); setStatus('done');
          requestAnimationFrame(() => reportRef.current?.scrollIntoView({ behavior: 'smooth', block: 'start' }));
        } else if (ev.type === 'error') { setError(ev.message); setStatus('error'); }
      }, ctrl.signal);
      setStatus((s) => (s === 'scanning' ? 'error' : s));
    } catch (err) {
      if (err.name === 'AbortError') return;
      setError(err.message === 'Failed to fetch' ? 'Could not reach the scanning service. Please try again shortly.' : err.message);
      setStatus('error');
    } finally {
      setResetKey((k) => k + 1); // Turnstile tokens are single-use
    }
  };

  const scanning = status === 'scanning';

  return (
    <div className="min-h-screen">
      {/* ------------------------------------------------------------------------------- hero */}
      <header className="bg-cream">
        <nav className="mx-auto flex max-w-6xl items-center justify-between px-5 py-5">
          <a href="./" className="flex items-center gap-2 font-semibold tracking-tight text-ink">
            <span className="grid h-7 w-7 place-items-center rounded-lg bg-olive text-cream"><ShieldCheck size={16} aria-hidden /></span>
            PQC-ready-check
          </a>
          <a href="#references" className="text-sm text-ink-2 hover:text-ink">Standards &amp; sources</a>
        </nav>

        <section className="mx-auto max-w-6xl px-5 pb-16 pt-10 text-center sm:pt-16">
          <p className="font-mono text-xs font-semibold tracking-[0.25em] text-olive-ink sm:text-sm">
            <span aria-hidden>— </span>FREE · NO SIGN-IN · SECONDS
          </p>
          <h1 className="mt-6 text-[2.4rem] font-semibold leading-[1.08] tracking-[-0.03em] text-ink sm:text-[3.4rem] lg:text-[4.1rem] xl:text-[4.6rem]">
            Is your website <span className="whitespace-nowrap font-serif text-[1.08em] font-normal italic tracking-normal text-olive-ink">quantum&#8209;safe</span>?
          </h1>
          <p className="mx-auto mt-6 max-w-4xl text-lg leading-relaxed text-ink-2 sm:text-2xl sm:leading-relaxed">
            Scan any domain&apos;s live TLS handshake for quantum-vulnerable cryptography — and get its post-quantum readiness score instantly.
          </p>

          <form onSubmit={onSubmit} className="mx-auto mt-10 max-w-3xl" noValidate>
            <div className="flex flex-col gap-3 sm:flex-row sm:gap-5">
              <label htmlFor="domain" className="sr-only">Domain to scan</label>
              <input
                id="domain" type="text" inputMode="url" autoComplete="off" spellCheck="false" maxLength={300}
                placeholder="yourcompany.in" value={input} onChange={(e) => setInput(e.target.value)} disabled={scanning}
                className="h-16 w-full min-w-0 shrink-0 rounded-full sm:w-auto sm:flex-1 border border-ink/15 bg-white px-7 text-lg text-ink shadow-sm placeholder:text-ink/45 focus:border-olive focus:outline-none focus:ring-4 focus:ring-olive/15 disabled:opacity-60 sm:text-xl"
              />
              <button
                type="submit" disabled={scanning}
                className={`inline-flex h-16 items-center justify-center gap-3 rounded-full bg-olive px-9 text-lg font-semibold text-cream shadow-[0_10px_24px_-8px_rgb(74_107_34/0.55)] transition hover:bg-olive-2 disabled:cursor-progress sm:text-xl ${scanning ? 'btn-scanning' : ''}`}
              >
                {scanning ? (<><Loader2 className="animate-spin" size={20} aria-hidden /> Inspecting…</>) : (<>Scan free <ArrowRight size={20} aria-hidden /></>)}
              </button>
            </div>

            <div className="mt-5 flex flex-col items-center gap-2">
              <Turnstile onToken={setToken} resetKey={resetKey} />
              {USING_TEST_KEY && (
                <p className="font-mono text-[11px] text-ink-2/80">Verification is running with Cloudflare&apos;s test key while the service is being set up.</p>
              )}
            </div>
          </form>

          <p className="mt-6 font-mono text-[13px] text-ink-2 sm:text-sm">
            We only read what&apos;s publicly negotiated in a TLS handshake — no login, nothing stored.
          </p>

          {error && (
            <div role="alert" className="rise mx-auto mt-6 flex max-w-2xl items-start gap-3 rounded-2xl border border-risk/30 bg-risk/10 px-5 py-4 text-left text-[15px] text-[#8a1f1a]">
              <XCircle size={20} className="mt-0.5 shrink-0" aria-hidden /> <span>{error}</span>
            </div>
          )}
          {notice && (
            <div role="status" className="rise mx-auto mt-6 flex max-w-2xl items-start gap-3 rounded-2xl border border-olive/25 bg-olive/10 px-5 py-4 text-left text-[15px] text-olive-2">
              <Info size={20} className="mt-0.5 shrink-0" aria-hidden /> <span>{notice}</span>
            </div>
          )}

          {(scanning || Object.keys(steps).length > 0) && LIVE && <Progress steps={steps} scanning={scanning} />}

          {!LIVE && (
            <div className="mx-auto mt-8 max-w-2xl rounded-2xl border border-ink/10 bg-cream-2/70 px-5 py-4 text-left text-[15px] text-ink-2">
              <p className="flex items-start gap-2">
                <Info size={18} className="mt-0.5 shrink-0 text-olive-ink" aria-hidden />
                <span><b className="text-ink">Live scanning is being set up.</b> The scanning service isn&apos;t connected yet, so nothing is scanned. Explore labelled sample reports for each outcome:</span>
              </p>
              <SampleButtons onPick={showSample} light />
            </div>
          )}
          {LIVE && status === 'idle' && (
            <p className="mt-6 text-sm text-ink-2">
              Not ready to scan? <button type="button" onClick={() => showSample('quantum_safe')} className="font-semibold text-olive-ink underline underline-offset-4">See a sample report</button>
            </p>
          )}
        </section>
      </header>

      {/* -------------------------------------------------------------------------- dashboard */}
      {report && (
        <main ref={reportRef} className="ops scroll-mt-0 bg-ops pb-16 pt-10 text-fg" aria-label="Scan report">
          <Report data={report} sample={isSample} onSample={showSample} />
        </main>
      )}

      <References engine={report && !isSample ? report.engine : null} />
    </div>
  );
}

/* ------------------------------------------------------------------------------------- Turnstile */
function Turnstile({ onToken, resetKey }) {
  const el = useRef(null);
  const id = useRef(null);
  const [state, setState] = useState('loading');

  useEffect(() => {
    let cancelled = false;
    loadTurnstile().then((ts) => {
      if (cancelled || !el.current || id.current != null) return;
      id.current = ts.render(el.current, {
        sitekey: SITE_KEY, theme: 'light', size: 'flexible',
        callback: (t) => { onToken(t); setState('ok'); },
        'expired-callback': () => onToken(''),
        'error-callback': () => { onToken(''); setState('error'); },
      });
      setState('ready');
    }).catch(() => !cancelled && setState('blocked'));
    return () => {
      cancelled = true;
      if (id.current != null) { window.turnstile?.remove(id.current); id.current = null; }
    };
  }, [onToken]);

  useEffect(() => {
    if (resetKey && id.current != null) { window.turnstile?.reset(id.current); onToken(''); }
  }, [resetKey, onToken]);

  return (
    <div className="w-full max-w-[400px]">
      <div ref={el} className="min-h-[65px]" />
      {state === 'loading' && <p className="font-mono text-xs text-ink-2">Loading verification…</p>}
      {state === 'blocked' && <p className="font-mono text-xs text-[#8a1f1a]">The verification widget could not load. Disable content blockers for challenges.cloudflare.com and reload.</p>}
    </div>
  );
}

/* -------------------------------------------------------------------------------------- progress */
function Progress({ steps, scanning }) {
  return (
    <ol aria-live="polite" className="rise mx-auto mt-8 max-w-2xl space-y-2 rounded-2xl border border-ink/10 bg-white/70 p-4 text-left font-mono text-[13px] shadow-sm sm:p-5 sm:text-sm">
      {STEP_DEFS.map((s) => {
        const st = steps[s.id]?.state || (scanning ? 'pending' : 'skipped');
        const Icon = st === 'done' ? CheckCircle2 : st === 'active' ? Loader2 : st === 'error' ? XCircle : Circle;
        const tone = st === 'done' ? 'text-olive-ink' : st === 'active' ? 'text-ink' : st === 'error' ? 'text-[#b4271f]' : 'text-ink/35';
        return (
          <li key={s.id} className={`flex items-start gap-3 ${tone}`}>
            <Icon size={18} className={`mt-px shrink-0 ${st === 'active' ? 'animate-spin' : ''}`} aria-hidden />
            <div className="min-w-0">
              <span className="font-semibold">{s.label}</span>
              <span className="sr-only"> — {st}</span>
              {steps[s.id]?.detail && <div className="break-words text-ink-2">{steps[s.id].detail}</div>}
            </div>
          </li>
        );
      })}
    </ol>
  );
}

function SampleButtons({ onPick, light }) {
  const base = light ? 'border-ink/15 bg-white text-ink hover:border-olive' : 'border-edge bg-panel-2 text-fg hover:border-lime/60';
  return (
    <div className="mt-3 flex flex-wrap gap-2">
      {Object.entries(TIERS).map(([k, t]) => (
        <button key={k} type="button" onClick={() => onPick(k)} className={`inline-flex items-center gap-2 rounded-full border px-4 py-2 text-sm font-medium transition ${base}`}>
          <t.Icon size={16} style={{ color: t.color }} aria-hidden /> {t.short}
        </button>
      ))}
    </div>
  );
}

/* ---------------------------------------------------------------------------------------- report */
function Report({ data, sample, onSample }) {
  const tier = TIERS[data.verdict.tier];
  return (
    <div className="mx-auto max-w-6xl px-5">
      {sample && (
        <div className="mb-6 flex flex-col gap-3 rounded-xl border border-warn/40 bg-warn/10 px-4 py-3 text-sm text-[#f1d08c] sm:flex-row sm:items-center sm:justify-between">
          <p className="flex items-start gap-2"><AlertTriangle size={18} className="mt-px shrink-0" aria-hidden />
            <span><b>Sample report</b> — illustrative data for a fictional host. This is not a live scan.</span></p>
          <SampleButtons onPick={onSample} />
        </div>
      )}

      <div className="flex flex-col gap-3 border-b border-edge pb-5 sm:flex-row sm:items-end sm:justify-between">
        <div className="min-w-0">
          <p className="font-mono text-xs uppercase tracking-[0.2em] text-dim">TLS handshake report</p>
          <h2 className="mt-1 break-all font-mono text-2xl font-semibold text-fg sm:text-3xl">{data.host}</h2>
          <p className="mt-1 font-mono text-xs text-dim">
            {data.ip}:{data.port} · scanned {fmtTime(data.scanned_at)} · {ms(data.duration_ms)} total
          </p>
        </div>
        <span className={`inline-flex items-center gap-2 self-start rounded-full px-3 py-1.5 text-sm font-semibold ring-1 sm:self-auto ${tier.chip}`}>
          <tier.Icon size={16} aria-hidden /> {tier.label}
        </span>
      </div>

      <section className="mt-6 grid gap-4 md:grid-cols-2 xl:grid-cols-4" aria-label="Summary">
        <VerdictCard data={data} />
        <KexCard data={data} />
        <ProtocolCard data={data} />
        <CertCard data={data} />
      </section>

      <section className="mt-4 grid gap-4 lg:grid-cols-5">
        <HandshakeInspector data={data} />
        <ScoreBreakdown data={data} />
      </section>

      <Advisory data={data} />
    </div>
  );
}

function Card({ title, Icon, children, className = '' }) {
  return (
    <div className={`rounded-xl border border-edge bg-panel p-5 ${className}`}>
      <h3 className="flex items-center gap-2 text-xs font-semibold uppercase tracking-[0.14em] text-dim">
        <Icon size={15} aria-hidden /> {title}
      </h3>
      <div className="mt-4">{children}</div>
    </div>
  );
}

function Flag({ ok, yes, no, neutral }) {
  if (neutral) return <span className="inline-flex items-center gap-1 rounded-md bg-panel-2 px-2 py-0.5 text-xs font-medium text-dim ring-1 ring-edge"><Minus size={12} aria-hidden />{neutral}</span>;
  return ok
    ? <span className="inline-flex items-center gap-1 rounded-md bg-safe/12 px-2 py-0.5 text-xs font-semibold text-safe ring-1 ring-safe/30"><Check size={12} aria-hidden />{yes}</span>
    : <span className="inline-flex items-center gap-1 rounded-md bg-risk/12 px-2 py-0.5 text-xs font-semibold text-risk ring-1 ring-risk/30"><X size={12} aria-hidden />{no}</span>;
}

function Gauge({ score, color }) {
  const r = 52, c = Math.PI * r, v = Math.max(0, Math.min(100, score)) / 100;
  return (
    <svg viewBox="0 0 128 76" className="w-40" role="img" aria-label={`Quantum readiness score ${score} out of 100`}>
      <path d="M12 68 A52 52 0 0 1 116 68" fill="none" stroke="var(--color-edge)" strokeWidth="11" strokeLinecap="round" />
      <path d="M12 68 A52 52 0 0 1 116 68" fill="none" stroke={color} strokeWidth="11" strokeLinecap="round"
        strokeDasharray={`${c * v} ${c}`} style={{ transition: 'stroke-dasharray .8s ease' }} />
      <text x="64" y="62" textAnchor="middle" className="fill-fg font-mono" fontSize="26" fontWeight="600">{score}</text>
      <text x="64" y="74" textAnchor="middle" className="fill-dim font-mono" fontSize="8">/ 100</text>
    </svg>
  );
}

function VerdictCard({ data }) {
  const t = TIERS[data.verdict.tier];
  return (
    <Card title="Quantum readiness verdict" Icon={t.Icon}>
      <div className="flex flex-col items-center text-center">
        <Gauge score={data.verdict.score} color={t.color} />
        <span className="mt-2 inline-flex items-center gap-2 rounded-lg px-3 py-1.5 text-base font-bold" style={{ background: `color-mix(in srgb, ${t.color} 18%, transparent)`, color: t.color }}>
          <t.Icon size={18} aria-hidden /> {t.label}
        </span>
        <p className="mt-3 text-sm text-dim">
          Harvest-now-decrypt-later: <b className={data.verdict.hndl_protected ? 'text-safe' : 'text-risk'}>{data.verdict.hndl_protected ? 'mitigated' : 'exposed'}</b>
        </p>
      </div>
    </Card>
  );
}

function KexCard({ data }) {
  const k = data.kex;
  const pq = PQC_INFO[k.group];
  return (
    <Card title="Negotiated key exchange" Icon={KeyRound}>
      <p className={`break-all font-mono text-2xl font-semibold ${k.pqc ? 'text-safe' : k.group ? 'text-warn' : 'text-risk'}`}>{k.group || 'None'}</p>
      <p className="mt-1 text-sm text-dim">{k.family}{k.group ? '' : ' — no ephemeral key share'}</p>
      <div className="mt-4 space-y-2 text-sm">
        <div className="flex items-center justify-between gap-2"><span className="text-dim">ML-KEM (FIPS 203)</span><Flag ok={k.fips203} yes="Active" no="Not active" /></div>
        {pq ? (
          <>
            <div className="flex justify-between gap-2"><span className="text-dim">Components</span><span className="text-right font-mono">{pq.classical} + {pq.kem}</span></div>
            <div className="flex justify-between gap-2"><span className="text-dim">IANA codepoint</span><span className="font-mono">{pq.codepoint}</span></div>
            <p className="pt-1 text-xs leading-relaxed text-dim">
              {pq.kem === 'ML-KEM-1024' ? 'ML-KEM-1024 matches the CNSA 2.0 key-establishment parameter set.' : 'ML-KEM-768 (NIST category 3). CNSA 2.0 national-security systems call for ML-KEM-1024.'}
            </p>
          </>
        ) : (
          <p className="pt-1 text-xs leading-relaxed text-dim">
            {k.group ? `${k.group} alone can be broken by Shor's algorithm on a future quantum computer, so recorded sessions could be decrypted later.` : 'Static RSA key transport has no forward secrecy: one stolen or factored key decrypts every recorded session.'}
          </p>
        )}
      </div>
    </Card>
  );
}

function ProtocolCard({ data }) {
  const p = data.protocol;
  const grover = p.symmetric_bits >= 256 ? '256-bit key keeps ~128-bit security even against Grover\'s algorithm.'
    : p.symmetric_bits >= 128 ? '128-bit key: still approved by NIST; 256-bit gives the widest quantum margin.'
      : 'Short or obsolete key: replace it.';
  return (
    <Card title="Protocol & symmetric cipher" Icon={Lock}>
      <p className={`font-mono text-2xl font-semibold ${p.version === 'TLSv1.3' ? 'text-fg' : 'text-risk'}`}>{p.version || '—'}</p>
      <p className="mt-1 break-all font-mono text-sm text-dim">{p.cipher || '—'}</p>
      <div className="mt-4 space-y-2 text-sm">
        <div className="flex items-center justify-between gap-2"><span className="text-dim">Symmetric key</span><span className="font-mono">{p.symmetric_bits ? `${p.symmetric_bits}-bit` : '—'}</span></div>
        <div className="flex items-center justify-between gap-2"><span className="text-dim">AEAD</span><Flag ok={p.aead} yes="Yes" no="No (CBC)" /></div>
        <p className="pt-1 text-xs leading-relaxed text-dim">{grover}</p>
      </div>
    </Card>
  );
}

function CertCard({ data }) {
  const c = data.certificate;
  if (!c) return <Card title="Certificate & signature" Icon={FileBadge}><p className="text-sm text-dim">The certificate could not be read.</p></Card>;
  return (
    <Card title="Certificate & signature" Icon={FileBadge}>
      <p className={`font-mono text-2xl font-semibold ${c.pq_signature ? 'text-safe' : 'text-fg'}`}>{c.key_type}</p>
      <p className="mt-1 break-all font-mono text-sm text-dim">{c.signature_algorithm}</p>
      <div className="mt-4 space-y-2 text-sm">
        <div className="flex justify-between gap-2"><span className="text-dim">Issuer</span><span className="truncate text-right" title={c.issuer_org || c.issuer_cn}>{c.issuer_org || c.issuer_cn || '—'}</span></div>
        <div className="flex justify-between gap-2"><span className="text-dim">Valid</span><span className="text-right font-mono text-xs">{fmtDate(c.not_before)} → {fmtDate(c.not_after)}</span></div>
        <div className="flex items-center justify-between gap-2"><span className="text-dim">Chain</span>
          <Flag ok={c.verified && !c.expired} yes={`Trusted · ${c.days_remaining} d left`} no={c.expired ? 'Expired' : (c.verify_message || 'Not trusted')} />
        </div>
        <p className="pt-1 text-xs leading-relaxed text-dim">
          {c.pq_signature ? 'Post-quantum signature (NIST FIPS 204/205).' : 'Classical signature: quantum-vulnerable (Shor). Transition target: NIST FIPS 204 ML-DSA. Signatures can’t be harvested for later, so this is less urgent than key exchange.'}
        </p>
      </div>
    </Card>
  );
}

function HandshakeInspector({ data }) {
  const h = data.handshake;
  const selected = h.server_selected_group;
  const rows = [
    ['TCP connect', ms(h.latency_ms?.tcp), Clock],
    ['TLS handshake', ms(h.latency_ms?.tls), Activity],
    ['ALPN', h.alpn || 'none negotiated', Network],
    ['OCSP stapling', h.ocsp_stapled ? `stapled${h.ocsp_cert_status ? ` · ${h.ocsp_cert_status}` : ''}` : 'not stapled', FileBadge],
    ['Peer signature', h.peer_signature_type || '—', KeyRound],
    ['Engine cross-check', h.cross_check?.agrees ? 'OpenSSL & Python agree' : 'probes differ', CheckCircle2],
  ];
  return (
    <Card title="TLS handshake inspector" Icon={Activity} className="lg:col-span-3">
      <div className="grid items-stretch gap-3 md:grid-cols-[1fr_auto_1fr]">
        <div className="rounded-lg border border-edge bg-panel-2 p-4">
          <p className="font-mono text-xs font-semibold text-lime">ClientHello <span className="font-normal text-dim">· our scanner</span></p>
          <p className="mt-1 text-xs text-dim">supported_groups, in preference order</p>
          <ul className="mt-3 space-y-1.5">
            {h.client_offered_groups.map((g) => (
              <li key={g} className={`flex items-center justify-between gap-2 rounded-md px-2 py-1 font-mono text-[13px] ${g === selected ? 'bg-lime/12 ring-1 ring-lime/40' : ''}`}>
                <span className="break-all">{g}</span>
                {PQC_INFO[g] ? <span className="inline-flex shrink-0 items-center gap-1 rounded bg-safe/12 px-1.5 text-[10px] font-semibold text-safe"><Atom size={11} aria-hidden />ML-KEM</span>
                  : <span className="shrink-0 text-[10px] text-dim">classical</span>}
              </li>
            ))}
          </ul>
        </div>
        <div className="hidden items-center justify-center text-dim md:flex" aria-hidden><ChevronRight size={28} /></div>
        <div className="flex flex-col rounded-lg border border-edge bg-panel-2 p-4">
          <p className="font-mono text-xs font-semibold text-lime">ServerHello <span className="font-normal text-dim">· {data.host}</span></p>
          <p className="mt-1 text-xs text-dim">selected key_share group</p>
          <p className={`mt-3 break-all font-mono text-xl font-semibold ${PQC_INFO[selected] ? 'text-safe' : selected ? 'text-warn' : 'text-risk'}`}>{selected || 'none (RSA key transport)'}</p>
          <p className="mt-1 font-mono text-xs text-dim">{data.protocol.version} · {data.protocol.cipher}</p>
          <p className="mt-4 text-xs font-semibold text-dim">PQC groups accepted when offered alone</p>
          <ul className="mt-2 space-y-1.5">
            {Object.entries(h.pqc_group_support || {}).map(([g, ok]) => (
              <li key={g} className="flex items-center justify-between gap-2 font-mono text-[13px]">
                <span className="break-all">{g}</span>
                {ok == null ? <Flag neutral="untested" /> : <Flag ok={ok} yes="accepted" no="rejected" />}
              </li>
            ))}
          </ul>
        </div>
      </div>
      <dl className="mt-4 grid gap-x-6 gap-y-3 sm:grid-cols-2 xl:grid-cols-3">
        {rows.map(([k, v, I]) => (
          <div key={k} className="flex items-start gap-2">
            <I size={15} className="mt-0.5 shrink-0 text-dim" aria-hidden />
            <div className="min-w-0"><dt className="text-xs text-dim">{k}</dt><dd className="break-all font-mono text-sm">{v}</dd></div>
          </div>
        ))}
      </dl>
    </Card>
  );
}

function ScoreBreakdown({ data }) {
  const color = TIERS[data.verdict.tier].color;
  return (
    <Card title="How the score adds up" Icon={BookOpen} className="lg:col-span-2">
      <ul className="space-y-4">
        {data.verdict.breakdown.map((b) => (
          <li key={b.item}>
            <div className="flex items-baseline justify-between gap-2 text-sm">
              <span className="font-medium">{b.item}</span>
              <span className="font-mono text-dim"><b className="text-fg">{b.points}</b> / {b.max}</span>
            </div>
            <div className="mt-1.5 h-2 overflow-hidden rounded-full bg-panel-2" role="img" aria-label={`${b.points} of ${b.max} points`}>
              <div className="h-full rounded-full" style={{ width: `${(b.points / b.max) * 100}%`, background: color }} />
            </div>
            <p className="mt-1 text-xs leading-relaxed text-dim">{b.reason}</p>
          </li>
        ))}
      </ul>
      <p className="mt-4 border-t border-edge pt-3 font-mono text-sm">Total <b>{data.verdict.score}</b> / 100</p>
    </Card>
  );
}

/* -------------------------------------------------------------------------------------- advisory */
const ADVICE = {
  quantum_safe: {
    title: 'Key exchange is protected against harvest-now-decrypt-later',
    body: (d) => `${d.host} negotiated ${d.kex.group}, which combines classical ${PQC_INFO[d.kex.group]?.classical} with ${PQC_INFO[d.kex.group]?.kem} (NIST FIPS 203). An attacker who records this traffic today would have to break both, so a future quantum computer alone cannot decrypt it.`,
    steps: [
      'Keep the hybrid group first in your server’s preference list and keep TLS 1.3 enabled.',
      'Check every edge — CDNs, load balancers, API gateways and origin servers can each negotiate differently.',
      'Plan the certificate migration to ML-DSA (NIST FIPS 204) as publicly trusted post-quantum certificates become available.',
      'For national-security workloads under CNSA 2.0, prefer ML-KEM-1024 (SecP384r1MLKEM1024).',
    ],
  },
  classical_modern: {
    title: 'Modern TLS, but recorded traffic could be decrypted later',
    body: (d) => `${d.host} uses TLS 1.3 with ${d.kex.group || 'classical ECDHE'} only. That is strong against today’s computers, but an adversary can record the encrypted traffic now and decrypt it once a cryptographically relevant quantum computer exists (“harvest now, decrypt later”).`,
    steps: [
      'Upgrade the TLS terminator to a library with ML-KEM support (for example OpenSSL 3.5 or later).',
      'Offer X25519MLKEM768 ahead of X25519 so hybrid-capable clients get post-quantum key exchange.',
      'If a CDN or load balancer terminates TLS, enable its post-quantum key agreement setting.',
      'Re-scan to confirm the ServerHello now selects an ML-KEM group.',
    ],
    snippet: '# nginx built against OpenSSL 3.5+\nssl_protocols TLSv1.3 TLSv1.2;\nssl_ecdh_curve X25519MLKEM768:X25519:prime256v1;',
  },
  legacy: {
    title: 'Outdated TLS configuration — fix this first',
    body: (d) => `${d.host} negotiated ${d.protocol.version || 'an old protocol'}${d.kex.family === 'RSA key transport' ? ' with static RSA key exchange' : ''}${d.protocol.aead ? '' : ' and a non-AEAD cipher'}. Recorded traffic is exposed to future quantum attacks, and parts of this configuration are weak even against classical attackers today.`,
    steps: [
      'Enable TLS 1.3 and remove static-RSA and CBC cipher suites.',
      'Use ECDHE with AEAD ciphers (AES-GCM or ChaCha20-Poly1305) for any remaining TLS 1.2 clients.',
      'Then add the hybrid group X25519MLKEM768 so key exchange becomes quantum-resistant.',
      'Re-scan to confirm TLS 1.3 and an ML-KEM group are negotiated.',
    ],
    snippet: '# nginx built against OpenSSL 3.5+\nssl_protocols TLSv1.3 TLSv1.2;\nssl_ecdh_curve X25519MLKEM768:X25519:prime256v1;\nssl_ciphers ECDHE+AESGCM:ECDHE+CHACHA20;',
  },
};

const TIMELINE = [
  ['Aug 2024', 'NIST publishes FIPS 203 (ML-KEM), FIPS 204 (ML-DSA) and FIPS 205 (SLH-DSA).'],
  ['2025', 'NSA CNSA 2.0: web browsers, servers and cloud services should support and prefer CNSA 2.0 algorithms.'],
  ['Aug 2026', 'IETF RFC 10024 standardises X25519MLKEM768, SecP256r1MLKEM768 and SecP384r1MLKEM1024 for TLS 1.3.'],
  ['Oct 2026', 'NIST IR 8547 (final) sets the federal transition schedule away from quantum-vulnerable algorithms.'],
  ['After 2030', 'NIST IR 8547: RSA, ECDSA, ECDH and finite-field DH are deprecated.'],
  ['2033', 'NSA CNSA 2.0: web browsers, servers and cloud services use CNSA 2.0 algorithms exclusively.'],
  ['After 2035', 'NIST IR 8547: quantum-vulnerable public-key algorithms are disallowed.'],
];

function Advisory({ data }) {
  const a = ADVICE[data.verdict.tier];
  const t = TIERS[data.verdict.tier];
  return (
    <section className="mt-4 grid gap-4 lg:grid-cols-5" aria-label="Threat and remediation advisory">
      <Card title="Threat & remediation advisory" Icon={t.Icon} className="lg:col-span-3">
        <h3 className="text-lg font-semibold" style={{ color: t.color }}>{a.title}</h3>
        <p className="mt-2 leading-relaxed text-fg/90">{a.body(data)}</p>
        <ol className="mt-4 space-y-2">
          {a.steps.map((s, i) => (
            <li key={s} className="flex gap-3 text-sm leading-relaxed">
              <span className="grid h-6 w-6 shrink-0 place-items-center rounded-full bg-panel-2 font-mono text-xs text-lime ring-1 ring-edge">{i + 1}</span>
              <span className="pt-0.5">{s}</span>
            </li>
          ))}
        </ol>
        {a.snippet && <pre className="mt-4 overflow-x-auto rounded-lg border border-edge bg-ops p-4 font-mono text-[13px] leading-relaxed text-lime">{a.snippet}</pre>}
        <p className="mt-4 text-xs leading-relaxed text-dim">
          Why key exchange first: recorded sessions can be decrypted retroactively once key exchange is broken, but a forged signature only matters at the moment of the connection. NIST, CISA and NSA therefore prioritise migrating key establishment.
        </p>
      </Card>
      <Card title="Migration timeline" Icon={Clock} className="lg:col-span-2">
        <ol className="relative space-y-4 border-l border-edge pl-5">
          {TIMELINE.map(([when, what]) => (
            <li key={when + what} className="relative">
              <span className="absolute -left-[25px] top-1.5 h-2.5 w-2.5 rounded-full bg-lime ring-4 ring-panel" aria-hidden />
              <p className="font-mono text-xs font-semibold text-lime">{when}</p>
              <p className="text-sm leading-relaxed text-fg/90">{what}</p>
            </li>
          ))}
        </ol>
      </Card>
    </section>
  );
}

/* ------------------------------------------------------------------------------------ references */
const REFS = [
  ['NIST', [
    ['NIST CSRC — Post-Quantum Cryptography project', 'https://csrc.nist.gov/projects/post-quantum-cryptography'],
    ['FIPS 203 — Module-Lattice-Based Key-Encapsulation Mechanism (ML-KEM)', 'https://csrc.nist.gov/pubs/fips/203/final'],
    ['FIPS 204 — Module-Lattice-Based Digital Signature (ML-DSA)', 'https://csrc.nist.gov/pubs/fips/204/final'],
    ['NIST IR 8547 — Transition to Post-Quantum Cryptography Standards', 'https://csrc.nist.gov/pubs/ir/8547/final'],
  ]],
  ['IETF', [
    ['RFC 10024 — PQ/T Hybrid Key Agreement Mechanisms for TLS 1.3', 'https://www.rfc-editor.org/rfc/rfc10024'],
    ['IETF TLS Working Group', 'https://datatracker.ietf.org/wg/tls/about/'],
  ]],
  ['Government guidance', [
    ['CISA, NSA & NIST — Quantum-Readiness: Migration to Post-Quantum Cryptography', 'https://www.cisa.gov/resources-tools/resources/quantum-readiness-migration-post-quantum-cryptography'],
    ['NSA — Post-Quantum Cybersecurity Resources (CNSA 2.0)', 'https://www.nsa.gov/Cybersecurity/Post-Quantum-Cybersecurity-Resources/'],
  ]],
  ['Cloudflare research', [
    ['Cloudflare Radar — Post-quantum encryption adoption', 'https://radar.cloudflare.com/post-quantum'],
    ['Cloudflare docs — Post-quantum cryptography', 'https://developers.cloudflare.com/ssl/post-quantum-cryptography/'],
  ]],
];

function References({ engine }) {
  return (
    <footer id="references" className="border-t border-ink/10 bg-cream">
      <div className="mx-auto max-w-6xl px-5 py-12">
        <h2 className="text-2xl font-semibold tracking-tight">Standards &amp; sources</h2>
        <p className="mt-2 max-w-3xl text-ink-2">
          Verdicts follow NIST FIPS 203/204 and the IETF hybrid key-exchange specification. A domain is <b>quantum-safe</b> when it negotiates TLS 1.3 with a NIST ML-KEM hybrid group, <b>classical modern</b> when it uses TLS 1.3 with ECDHE and an AEAD cipher only, and <b>legacy</b> otherwise.
        </p>
        <div className="mt-8 grid gap-8 sm:grid-cols-2 lg:grid-cols-4">
          {REFS.map(([group, links]) => (
            <div key={group}>
              <h3 className="font-mono text-xs font-semibold uppercase tracking-[0.18em] text-olive-ink">{group}</h3>
              <ul className="mt-3 space-y-2.5">
                {links.map(([label, href]) => (
                  <li key={href}>
                    <a href={href} target="_blank" rel="noopener noreferrer" className="group inline-flex items-start gap-1.5 text-sm text-ink hover:text-olive-ink">
                      <span className="underline decoration-ink/20 underline-offset-4 group-hover:decoration-olive">{label}</span>
                      <ExternalLink size={13} className="mt-1 shrink-0 opacity-60" aria-hidden />
                    </a>
                  </li>
                ))}
              </ul>
            </div>
          ))}
        </div>
        <div className="mt-10 flex flex-col gap-2 border-t border-ink/10 pt-6 font-mono text-xs text-ink-2 sm:flex-row sm:justify-between">
          <p>Results describe one handshake from our scanner at scan time; servers behind load balancers or CDNs may vary.</p>
          <p className="flex items-center gap-1.5"><RefreshCw size={12} aria-hidden /> {engine?.openssl ? `Engine: ${engine.openssl.split(' (')[0]}` : 'Engine: OpenSSL 3.5+'}</p>
        </div>
      </div>
    </footer>
  );
}
