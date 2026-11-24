// server.js
'use strict';

const crypto = require('node:crypto');
const express = require('express');
const helmet = require('helmet');
const cookieParser = require('cookie-parser');
const rateLimit = require('express-rate-limit');
const { Pool } = require('pg');

/* ============================ config ============================ */

const env = process.env;
const PORT = Number(env.PORT || 3000);
const IS_PROD = env.NODE_ENV === 'production';
const SESSION_TTL_DAYS = Number(env.SESSION_TTL_DAYS || 14);
const MAX_ACCOUNTS = Number(env.MAX_ACCOUNTS_PER_USER || 10);
const COOKIE = 'dd_sid';

const REQUIRED = ['DATABASE_URL', 'ENCRYPTION_KEY', 'AUTOMATION_BASE_URL',
  'AUTOMATION_SHARED_SECRET'];

const missing = REQUIRED.filter((k) => !env[k]);
if (missing.length) {
  console.error('[fatal] missing vars: ' + missing.join(', '));
  process.exit(1);
}

const KEY = Buffer.from(env.ENCRYPTION_KEY, 'hex');
if (KEY.length !== 32) {
  console.error('[fatal] ENCRYPTION_KEY must be 64 hex chars');
  process.exit(1);
}

const BACKEND = env.AUTOMATION_BASE_URL.replace(/\/+$/, '');

/* ============================ database ============================ */

const pool = new Pool({
  connectionString: env.DATABASE_URL,
  ssl: env.DATABASE_SSL === 'true' ? { rejectUnauthorized: false } : false,
  max: 10,
  idleTimeoutMillis: 30000,
});

pool.on('error', (e) => console.error('[pg]', e.message));

const db = {
  q: (t, p) => pool.query(t, p),
  one: async (t, p) => (await pool.query(t, p)).rows[0] || null,
  many: async (t, p) => (await pool.query(t, p)).rows,
};

const SCHEMA = `
CREATE EXTENSION IF NOT EXISTS "pgcrypto";
CREATE TABLE IF NOT EXISTS users (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  email TEXT NOT NULL UNIQUE,
  password_hash TEXT NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  last_login_at TIMESTAMPTZ
);
CREATE TABLE IF NOT EXISTS sessions (
  id TEXT PRIMARY KEY,
  user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  csrf_token TEXT NOT NULL,
  user_agent TEXT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  expires_at TIMESTAMPTZ NOT NULL
);
CREATE INDEX IF NOT EXISTS sessions_user_idx ON sessions(user_id);
CREATE TABLE IF NOT EXISTS accounts (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  discord_user_id TEXT NOT NULL,
  username TEXT NOT NULL,
  global_name TEXT,
  avatar_url TEXT,
  access_token_enc TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'connecting',
  last_error TEXT,
  last_checked_at TIMESTAMPTZ,
  last_status_change TIMESTAMPTZ NOT NULL DEFAULT now(),
  session_started_at TIMESTAMPTZ,
  connected_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  CONSTRAINT accounts_user_discord_unique UNIQUE (user_id, discord_user_id)
);
CREATE INDEX IF NOT EXISTS accounts_user_idx ON accounts(user_id);
CREATE TABLE IF NOT EXISTS account_events (
  id BIGSERIAL PRIMARY KEY,
  account_id UUID REFERENCES accounts(id) ON DELETE CASCADE,
  user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  event TEXT NOT NULL,
  detail TEXT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
`;

async function migrate() {
  await pool.query(SCHEMA);
  console.log('[db] schema ready');
}

/* ============================ crypto ============================ */

const sha256 = (v) => crypto.createHash('sha256').update(v).digest('hex');
const rand = (n = 32) => crypto.randomBytes(n).toString('base64url');

function encrypt(text) {
  if (text == null) return null;
  const iv = crypto.randomBytes(12);
  const c = crypto.createCipheriv('aes-256-gcm', KEY, iv);
  const body = Buffer.concat([c.update(String(text), 'utf8'), c.final()]);
  return Buffer.concat([iv, c.getAuthTag(), body]).toString('base64');
}

function decrypt(payload) {
  if (!payload) return null;
  try {
    const raw = Buffer.from(payload, 'base64');
    const d = crypto.createDecipheriv('aes-256-gcm', KEY, raw.subarray(0, 12));
    d.setAuthTag(raw.subarray(12, 28));
    return Buffer.concat([d.update(raw.subarray(28)), d.final()]).toString('utf8');
  } catch { return null; }
}

function hashPassword(pw) {
  const salt = crypto.randomBytes(16);
  return 'scrypt$' + salt.toString('hex') + '$' + crypto.scryptSync(pw, salt, 64).toString('hex');
}

function verifyPassword(pw, stored) {
  try {
    const [scheme, salt, hash] = String(stored).split('$');
    if (scheme !== 'scrypt') return false;
    const derived = crypto.scryptSync(pw, Buffer.from(salt, 'hex'), 64);
    const expected = Buffer.from(hash, 'hex');
    return derived.length === expected.length && crypto.timingSafeEqual(derived, expected);
  } catch { return false; }
}

function same(a, b) {
  const x = Buffer.from(String(a));
  const y = Buffer.from(String(b));
  return x.length === y.length && crypto.timingSafeEqual(x, y);
}

/* ============================ backend client ============================ */

async function backend(method, path, body) {
  const raw = body === undefined ? '' : JSON.stringify(body);
  const ts = Date.now().toString();
  const sig = crypto.createHmac('sha256', env.AUTOMATION_SHARED_SECRET)
    .update(ts + '.' + method.toUpperCase() + '.' + path + '.' + raw).digest('hex');

  try {
    const res = await fetch(BACKEND + path, {
      method,
      headers: {
        'content-type': 'application/json',
        'x-automation-timestamp': ts,
        'x-automation-signature': sig,
      },
      body: raw || undefined,
      signal: AbortSignal.timeout(20000),
    });
    const text = await res.text();
    let data = null;
    if (text) { try { data = JSON.parse(text); } catch { data = { raw: text }; } }
    return { ok: res.ok, status: res.status, data };
  } catch (e) {
    return { ok: false, status: 0, data: { error: e.message } };
  }
}

/* ============================ discord ============================ */

const API = 'https://discord.com/api/v10';

async function me(token) {
  const res = await fetch(API + '/users/@me', {
    headers: { authorization: token },
    signal: AbortSignal.timeout(15000),
  });
  if (!res.ok) throw new Error('user_failed:' + res.status);
  return res.json();
}

function avatarUrl(u) {
  if (u.avatar) {
    const ext = u.avatar.startsWith('a_') ? 'gif' : 'png';
    return 'https://cdn.discordapp.com/avatars/' + u.id + '/' + u.avatar + '.' + ext + '?size=128';
  }
  let i = 0;
  try { i = Number((BigInt(u.id) >> 22n) % 6n); } catch { i = 0; }
  return 'https://cdn.discordapp.com/embed/avatars/' + i + '.png';
}

/* ============================ app ============================ */

const app = express();
app.set('trust proxy', 1);
app.disable('x-powered-by');

app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'"],
      styleSrc: ["'self'", 'https://fonts.googleapis.com'],
      fontSrc: ["'self'", 'https://fonts.gstatic.com'],
      imgSrc: ["'self'", 'data:', 'https://cdn.discordapp.com'],
      connectSrc: ["'self'"],
      frameAncestors: ["'none'"],
    },
  },
  crossOriginEmbedderPolicy: false,
}));

app.use(express.json({ limit: '64kb' }));
app.use(cookieParser());

const authLimit = rateLimit({ windowMs: 600000, limit: 25, standardHeaders: 'draft-7',
  legacyHeaders: false, message: { error: 'Too many attempts, wait a few minutes.' } });
const actLimit = rateLimit({ windowMs: 60000, limit: 60, standardHeaders: 'draft-7',
  legacyHeaders: false, message: { error: 'Slow down.' } });

app.use(async (req, _res, next) => {
  req.session = null;
  req.user = null;
  const token = req.cookies?.[COOKIE];
  if (!token || token.length < 20) return next();
  try {
    const row = await db.one(
      'SELECT s.id, s.csrf_token, u.id AS uid, u.email FROM sessions s JOIN users u ON u.id = s.user_id WHERE s.id = $1 AND s.expires_at > now()',
      [sha256(token)]
    );
    if (row) {
      req.session = { id: row.id, csrf: row.csrf_token };
      req.user = { id: row.uid, email: row.email };
    }
  } catch (e) { console.error('[session]', e.message); }
  next();
});

function auth(req, res, next) {
  if (!req.user) return res.status(401).json({ error: 'Sign in required' });
  next();
}

function csrf(req, res, next) {
  const h = req.get('x-csrf-token');
  if (!h || !req.session || !same(h, req.session.csrf)) {
    return res.status(403).json({ error: 'Bad CSRF token' });
  }
  next();
}

async function openSession(res, userId, ua) {
  const token = rand(32);
  const csrfToken = rand(24);
  const expires = new Date(Date.now() + SESSION_TTL_DAYS * 86400000);
  await db.q('INSERT INTO sessions (id, user_id, csrf_token, user_agent, expires_at) VALUES ($1,$2,$3,$4,$5)',
    [sha256(token), userId, csrfToken, String(ua || '').slice(0, 250), expires]);
  res.cookie(COOKIE, token, { httpOnly: true, secure: IS_PROD, sameSite: 'lax', path: '/', expires });
  return csrfToken;
}

function pub(r) {
  return {
    id: r.id, username: r.username, globalName: r.global_name, avatarUrl: r.avatar_url,
    status: r.status, lastError: r.last_error, lastCheckedAt: r.last_checked_at,
    lastStatusChange: r.last_status_change, sessionStartedAt: r.session_started_at,
    connectedAt: r.connected_at,
  };
}

async function owned(userId, id) {
  return db.one('SELECT * FROM accounts WHERE id = $1 AND user_id = $2', [id, userId]);
}

async function sync(acc) {
  const r = await backend('GET', '/internal/accounts/' + encodeURIComponent(acc.id) + '/status');

  if (!r.ok) {
    let s = acc.status;
    if (r.status === 404) s = 'offline';
    if (r.status === 401) s = 'reauth_required';
    await db.q('UPDATE accounts SET status=$1, last_error=$2, last_checked_at=now() WHERE id=$3',
      [s, r.data?.error || 'backend_' + r.status, acc.id]);
    return { ...acc, status: s };
  }

  const reported = String(r.data?.status || 'offline');
  const ok = ['online', 'connecting', 'offline', 'error', 'reauth_required'];
  const s = ok.includes(reported) ? reported : 'offline';

  const upd = await db.one(
    'UPDATE accounts SET status=$1, last_error=$2, last_checked_at=now(), last_status_change=CASE WHEN status IS DISTINCT FROM $1 THEN now() ELSE last_status_change END, session_started_at=COALESCE($3::timestamptz, session_started_at), updated_at=now() WHERE id=$4 RETURNING *',
    [s, r.data?.error || null, r.data?.sessionStartedAt || null, acc.id]
  );
  return upd || { ...acc, status: s };
}

/* ============================ routes ============================ */

app.get('/health', async (_req, res) => {
  try { await db.q('SELECT 1'); res.json({ ok: true }); }
  catch { res.status(503).json({ ok: false }); }
});

app.get('/style.css', (_req, res) => {
  res.type('text/css').set('cache-control', 'public, max-age=300').send(CSS);
});

app.get('/script.js', (_req, res) => {
  res.type('text/javascript').set('cache-control', 'public, max-age=300').send(CLIENT);
});

app.get('/', (_req, res) => {
  res.type('html').send(PAGE);
});

app.get('/api/session', (req, res) => {
  if (!req.user) return res.json({ authenticated: false });
  res.json({ authenticated: true, csrfToken: req.session.csrf, user: { email: req.user.email } });
});

app.post('/api/auth/register', authLimit, async (req, res) => {
  const email = String(req.body?.email || '').trim().toLowerCase();
  const pw = String(req.body?.password || '');
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/.test(email)) return res.status(400).json({ error: 'Invalid email' });
  if (pw.length < 10) return res.status(400).json({ error: 'Password needs 10+ characters' });
  try {
    const u = await db.one('INSERT INTO users (email, password_hash) VALUES ($1,$2) RETURNING id, email',
      [email, hashPassword(pw)]);
    res.status(201).json({ csrfToken: await openSession(res, u.id, req.get('user-agent')), user: { email: u.email } });
  } catch (e) {
    if (e.code === '23505') return res.status(409).json({ error: 'Email already registered' });
    res.status(500).json({ error: 'Could not register' });
  }
});

app.post('/api/auth/login', authLimit, async (req, res) => {
  const email = String(req.body?.email || '').trim().toLowerCase();
  const pw = String(req.body?.password || '');
  const u = await db.one('SELECT id, email, password_hash FROM users WHERE email = $1', [email]);
  if (!u || !verifyPassword(pw, u.password_hash)) return res.status(401).json({ error: 'Wrong email or password' });
  await db.q('UPDATE users SET last_login_at = now() WHERE id = $1', [u.id]);
  res.json({ csrfToken: await openSession(res, u.id, req.get('user-agent')), user: { email: u.email } });
});

app.post('/api/auth/logout', auth, csrf, async (req, res) => {
  await db.q('DELETE FROM sessions WHERE id = $1', [req.session.id]);
  res.clearCookie(COOKIE, { path: '/' });
  res.json({ ok: true });
});

app.post('/api/accounts/connect', auth, csrf, actLimit, async (req, res) => {
  const token = String(req.body?.token || '').trim().replace(/^Bearer\s+/i, '');
  if (token.length < 30) return res.status(400).json({ error: 'Paste a valid Discord token' });

  let profile;
  try { profile = await me(token); }
  catch { return res.status(400).json({ error: 'Discord rejected that token' }); }

  const { count } = await db.one('SELECT count(*)::int AS count FROM accounts WHERE user_id = $1', [req.user.id]);
  const existing = await db.one(
    'SELECT id FROM accounts WHERE user_id = $1 AND discord_user_id = $2',
    [req.user.id, profile.id]
  );
  if (!existing && count >= MAX_ACCOUNTS) {
    return res.status(409).json({ error: 'Limit of ' + MAX_ACCOUNTS + ' accounts reached' });
  }

  const acc = existing
    ? await db.one(
      "UPDATE accounts SET username=$1, global_name=$2, avatar_url=$3, access_token_enc=$4, status='connecting', last_error=NULL, updated_at=now() WHERE id=$5 RETURNING *",
      [profile.username, profile.global_name || null, avatarUrl(profile), encrypt(token), existing.id])
    : await db.one(
      "INSERT INTO accounts (user_id, discord_user_id, username, global_name, avatar_url, access_token_enc, status) VALUES ($1,$2,$3,$4,$5,$6,'connecting') RETURNING *",
      [req.user.id, profile.id, profile.username, profile.global_name || null, avatarUrl(profile), encrypt(token)]);

  const push = await backend('POST', '/internal/accounts/connect', { accountId: acc.id, token });

  if (!push.ok) {
    await db.q("UPDATE accounts SET status='error', last_error=$1 WHERE id=$2", ['backend_' + push.status, acc.id]);
    return res.status(502).json({ error: 'Backend unreachable' });
  }

  await db.q("UPDATE accounts SET status='online', last_checked_at=now() WHERE id=$1", [acc.id]);
  res.status(201).json({ account: pub(acc) });
});

app.get('/api/accounts', auth, async (req, res) => {
  const rows = await db.many('SELECT * FROM accounts WHERE user_id = $1 ORDER BY connected_at DESC', [req.user.id]);
  const out = await Promise.allSettled(rows.map(sync));
  const accounts = out.map((r, i) => pub(r.status === 'fulfilled' ? r.value : rows[i]));
  res.json({ accounts, total: accounts.length, online: accounts.filter((a) => a.status === 'online').length, limit: MAX_ACCOUNTS });
});

app.get('/api/accounts/:id/status', auth, async (req, res) => {
  const acc = await owned(req.user.id, req.params.id);
  if (!acc) return res.status(404).json({ error: 'Not found' });
  const s = await sync(acc);
  res.json({ id: s.id, status: s.status, lastError: s.last_error || null,
    lastCheckedAt: s.last_checked_at || new Date().toISOString(), sessionStartedAt: s.session_started_at || null });
});

app.delete('/api/accounts/:id', auth, csrf, actLimit, async (req, res) => {
  const acc = await owned(req.user.id, req.params.id);
  if (!acc) return res.status(404).json({ error: 'Not found' });

  const removal = await backend('DELETE', '/internal/accounts/' + encodeURIComponent(acc.id));
  await db.q('DELETE FROM accounts WHERE id = $1 AND user_id = $2', [acc.id, req.user.id]);
  await db.q('INSERT INTO account_events (user_id, event, detail) VALUES ($1,$2,$3)', [req.user.id, 'disconnected', acc.username]);

  res.json({ ok: true, backendAcknowledged: removal.ok });
});

app.use((req, res) => {
  if (req.method === 'GET') return res.redirect('/');
  res.status(404).json({ error: 'Not found' });
});

app.use((err, _req, res, _next) => {
  console.error('[error]', err);
  res.status(500).json({ error: 'Server error' });
});

/* ============================ assets ============================ */

const PAGE = `<!DOCTYPE html>
<html lang="en"><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="color-scheme" content="dark"><title>Nexus</title>
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&display=swap" rel="stylesheet">
<link rel="stylesheet" href="/style.css">
</head><body>
<div class="aurora"></div>
<section id="auth-view" class="auth-view" hidden><div class="auth-card">
<div class="brand brand--center"><span class="brand__mark">N</span><span class="brand__name">Nexus</span></div>
<h1 class="auth-title">Account control, done properly.</h1>
<p class="auth-sub">Sign in to manage your connected Discord accounts.</p>
<div class="tabs">
<button class="tab is-active" data-tab="login">Sign in</button>
<button class="tab" data-tab="register">Create account</button></div>
<form id="auth-form" class="stack" novalidate>
<label class="field"><span class="field__label">Email</span>
<input type="email" id="auth-email" autocomplete="email" placeholder="you@example.com" required></label>
<label class="field"><span class="field__label">Password</span>
<input type="password" id="auth-password" autocomplete="current-password" placeholder="10+ characters" minlength="10" required></label>
<p id="auth-error" class="form-error" hidden></p>
<button type="submit" id="auth-submit" class="btn btn--primary btn--block"><span class="btn__label">Sign in</span></button>
</form></div></section>
<div id="app-view" hidden>
<header class="topbar"><div class="topbar__inner">
<div class="brand"><span class="brand__mark">N</span><span class="brand__name">Nexus</span></div>
<div class="topbar__right"><span class="user-chip" id="user-email">—</span>
<button id="sign-out" class="btn btn--ghost btn--sm">Sign out</button></div>
</div></header>
<main class="page">
<section class="hero"><div><h1 class="hero__title">Connected accounts</h1>
<p class="hero__sub">Each account runs on an isolated session. Disconnecting one never touches another.</p></div>
<button id="connect-btn" class="btn btn--primary">+ Connect account</button></section>
<section class="stats">
<article class="stat"><span class="stat__value" id="stat-total">0</span><span class="stat__label">Connected</span></article>
<article class="stat"><span class="stat__value stat__value--online" id="stat-online">0</span><span class="stat__label">Online</span></article>
<article class="stat"><span class="stat__value" id="stat-limit">10</span><span class="stat__label">Limit</span></article></section>
<section class="accounts-head"><h2 class="section-title">Your accounts</h2>
<span class="muted">Auto-refreshing</span></section>
<div id="accounts-grid" class="grid"></div>
<section id="empty-state" class="empty" hidden>
<h3>No accounts connected</h3><p class="muted">Connect your first Discord account to get started.</p>
<button class="btn btn--primary" id="empty-connect">Connect account</button></section>
</main>
<footer class="footer"><span>Nexus</span><span>•</span><span>Tokens stay server-side</span></footer>
</div>
<dialog id="confirm-dialog" class="dialog"><form method="dialog" class="dialog__inner">
<h2 class="dialog__title">Disconnect account?</h2>
<p class="dialog__text">The session for <strong id="dialog-account">this account</strong> will be removed. Others stay untouched.</p>
<div class="dialog__actions"><button class="btn btn--ghost" value="cancel">Cancel</button>
<button class="btn btn--danger" value="confirm">Disconnect</button></div>
</form></dialog>
<dialog id="token-dialog" class="dialog"><form id="token-form" class="dialog__inner">
<h2 class="dialog__title">Connect an account</h2>
<p class="dialog__text">Paste the account's Discord token. It is encrypted before storage.</p>
<textarea id="token-input" rows="4" placeholder="Paste token here" required></textarea>
<p id="token-error" class="form-error" hidden></p>
<div class="dialog__actions">
<button type="button" class="btn btn--ghost" id="token-cancel">Cancel</button>
<button type="submit" class="btn btn--primary">Connect</button></div>
</form></dialog>
<div id="toasts" class="toasts"></div>
<script src="/script.js" defer></script>
</body></html>`;

const CSS = `
:root{--bg:#08070d;--panel:#13121d;--panel-2:#171625;--line:rgba(255,255,255,.07);--line-strong:rgba(255,255,255,.14);--text:#f3f1fa;--text-dim:#a29fbd;--text-faint:#6f6b8a;--accent:#8b5cf6;--accent-2:#a855f7;--accent-soft:rgba(139,92,246,.14);--green:#34d399;--amber:#fbbf24;--red:#f87171;--radius:20px;--shadow:0 24px 60px -28px rgba(0,0,0,.9);--ease:cubic-bezier(.22,1,.36,1)}
*{box-sizing:border-box}html,body{height:100%}
body{margin:0;background:var(--bg);color:var(--text);font-family:Inter,-apple-system,"Segoe UI",Roboto,sans-serif;font-size:15px;line-height:1.55;-webkit-font-smoothing:antialiased;overflow-x:hidden}
.aurora{position:fixed;inset:-20% -10% auto -10%;height:70vh;pointer-events:none;z-index:0;background:radial-gradient(48% 60% at 18% 0%,rgba(139,92,246,.28),transparent 70%),radial-gradient(40% 50% at 82% 10%,rgba(88,101,242,.2),transparent 70%);filter:blur(20px)}
[hidden]{display:none!important}
.brand{display:inline-flex;align-items:center;gap:10px}
.brand--center{justify-content:center;width:100%;margin-bottom:6px}
.brand__mark{display:grid;place-items:center;width:34px;height:34px;border-radius:10px;font-weight:800;color:#fff;background:linear-gradient(140deg,var(--accent),var(--accent-2))}
.brand__name{font-weight:700;font-size:17px}
.btn{display:inline-flex;align-items:center;justify-content:center;gap:8px;border:1px solid transparent;border-radius:12px;padding:11px 18px;font:inherit;font-weight:600;font-size:14px;color:var(--text);background:var(--panel-2);cursor:pointer;transition:.16s;white-space:nowrap}
.btn:active{transform:scale(.98)}.btn:disabled{opacity:.55;cursor:not-allowed}
.btn--primary{background:linear-gradient(135deg,var(--accent),var(--accent-2));box-shadow:0 14px 34px -16px rgba(139,92,246,.95)}
.btn--ghost{background:rgba(255,255,255,.04);border-color:var(--line);color:var(--text-dim)}
.btn--danger{background:rgba(248,113,113,.14);border-color:rgba(248,113,113,.35);color:#fecaca}
.btn--sm{padding:8px 13px;font-size:13px;border-radius:10px}.btn--block{width:100%}
.auth-view{position:relative;z-index:1;min-height:100dvh;display:grid;place-items:center;padding:28px 18px}
.auth-card{width:100%;max-width:424px;padding:34px 30px;border-radius:26px;background:linear-gradient(170deg,rgba(23,22,37,.96),rgba(12,11,20,.98));border:1px solid var(--line);box-shadow:var(--shadow);animation:rise .5s var(--ease) both}
.auth-title{font-size:22px;margin:14px 0 6px;text-align:center}.auth-sub{margin:0 0 22px;color:var(--text-dim);font-size:13.5px;text-align:center}
.tabs{display:grid;grid-template-columns:1fr 1fr;gap:4px;padding:4px;margin-bottom:20px;border-radius:12px;background:rgba(255,255,255,.04);border:1px solid var(--line)}
.tab{border:0;border-radius:9px;padding:9px;font:inherit;font-size:13.5px;font-weight:600;color:var(--text-faint);background:transparent;cursor:pointer}
.tab.is-active{color:#fff;background:rgba(139,92,246,.22)}
.stack{display:grid;gap:14px}.field{display:grid;gap:7px}
.field__label{font-size:12.5px;font-weight:600;color:var(--text-dim)}
input{width:100%;padding:12px 14px;border-radius:12px;border:1px solid var(--line);background:rgba(255,255,255,.03);color:var(--text);font:inherit;font-size:14.5px}
input:focus{outline:none;border-color:rgba(168,85,247,.6);box-shadow:0 0 0 4px rgba(139,92,246,.12)}
textarea{width:100%;padding:12px 14px;border-radius:12px;border:1px solid var(--line);background:rgba(255,255,255,.03);color:var(--text);font:inherit;font-size:13px;resize:vertical;margin-bottom:12px}
textarea:focus{outline:none;border-color:rgba(168,85,247,.6);box-shadow:0 0 0 4px rgba(139,92,246,.12)}
.form-error{margin:0;padding:9px 12px;border-radius:10px;font-size:13px;color:#fecaca;background:rgba(248,113,113,.1);border:1px solid rgba(248,113,113,.28)}
.topbar{position:sticky;top:0;z-index:20;border-bottom:1px solid var(--line);background:rgba(8,7,13,.82);backdrop-filter:blur(16px)}
.topbar__inner{max-width:1120px;margin:0 auto;padding:13px 22px;display:flex;align-items:center;justify-content:space-between;gap:16px}
.topbar__right{display:flex;align-items:center;gap:12px}
.user-chip{font-size:12.5px;color:var(--text-dim);padding:7px 12px;border-radius:999px;border:1px solid var(--line);max-width:240px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.page{position:relative;z-index:1;max-width:1120px;margin:0 auto;padding:38px 22px 64px}
.hero{display:flex;align-items:flex-end;justify-content:space-between;gap:22px;flex-wrap:wrap;margin-bottom:26px}
.hero__title{margin:0 0 6px;font-size:clamp(26px,4vw,36px);letter-spacing:-.035em;line-height:1.12}
.hero__sub{margin:0;color:var(--text-dim);font-size:14px;max-width:52ch}
.stats{display:grid;grid-template-columns:repeat(3,1fr);gap:12px;margin-bottom:34px}
.stat{padding:16px 18px;border-radius:12px;border:1px solid var(--line);background:linear-gradient(160deg,rgba(255,255,255,.045),rgba(255,255,255,.012))}
.stat__value{display:block;font-size:26px;font-weight:800;line-height:1.15}
.stat__value--online{color:var(--green)}
.stat__label{font-size:12px;color:var(--text-faint);text-transform:uppercase;letter-spacing:.08em;font-weight:600}
.accounts-head{display:flex;justify-content:space-between;align-items:baseline;margin-bottom:14px}
.section-title{margin:0;font-size:16px}.muted{color:var(--text-faint);font-size:12.5px}
.grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(300px,1fr));gap:16px}
.card{position:relative;overflow:hidden;padding:20px;border-radius:var(--radius);border:1px solid var(--line);background:linear-gradient(165deg,var(--panel-2),var(--panel) 60%,#100f19);box-shadow:var(--shadow);animation:rise .45s var(--ease) both;transition:transform .2s,border-color .2s}
.card:hover{transform:translateY(-3px);border-color:rgba(168,85,247,.34)}
.card.is-busy{opacity:.62;pointer-events:none}
.card__head{display:flex;align-items:center;gap:12px;margin-bottom:16px}
.avatar{width:46px;height:46px;flex:0 0 46px;border-radius:14px;object-fit:cover;background:var(--panel-2);border:1px solid var(--line-strong)}
.card__id{min-width:0;flex:1}
.card__name{font-weight:700;font-size:15px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.card__handle{font-size:12px;color:var(--text-faint);white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.pill{display:inline-flex;align-items:center;gap:6px;padding:5px 10px;border-radius:999px;font-size:11px;font-weight:700;text-transform:uppercase;letter-spacing:.07em;border:1px solid transparent;white-space:nowrap}
.pill__dot{width:6px;height:6px;border-radius:50%;background:currentColor}
.pill--online{color:var(--green);background:rgba(52,211,153,.12);border-color:rgba(52,211,153,.3)}
.pill--online .pill__dot{animation:pulse 2s infinite}
.pill--connecting{color:var(--amber);background:rgba(251,191,36,.12);border-color:rgba(251,191,36,.3)}
.pill--offline{color:var(--text-faint);background:rgba(255,255,255,.05);border-color:var(--line)}
.pill--error{color:var(--red);background:rgba(248,113,113,.12);border-color:rgba(248,113,113,.3)}
.pill--reauth_required{color:var(--accent-2);background:var(--accent-soft);border-color:rgba(168,85,247,.35)}
.card__meta{display:grid;gap:8px;margin-bottom:16px}
.meta-row{display:flex;justify-content:space-between;gap:12px;font-size:12.5px}
.meta-row__key{color:var(--text-faint)}.meta-row__val{color:var(--text-dim);text-align:right}
.card__error{margin:0 0 14px;padding:8px 11px;border-radius:10px;font-size:12px;color:#fecaca;background:rgba(248,113,113,.09);border:1px solid rgba(248,113,113,.22);overflow-wrap:anywhere}
.card__actions{display:flex;gap:8px}.card__actions .btn{flex:1}
.empty{margin-top:10px;padding:52px 24px;text-align:center;border-radius:var(--radius);border:1px dashed var(--line-strong);background:rgba(255,255,255,.018)}
.empty h3{margin:0 0 6px;font-size:17px}.empty p{margin:0 0 18px}
.dialog{border:0;padding:0;background:transparent;max-width:420px;width:calc(100% - 36px);color:var(--text)}
.dialog::backdrop{background:rgba(4,3,9,.72);backdrop-filter:blur(6px)}
.dialog__inner{padding:26px 24px;border-radius:22px;border:1px solid var(--line-strong);background:linear-gradient(170deg,#191826,#0d0c15)}
.dialog__title{margin:0 0 8px;font-size:18px}
.dialog__text{margin:0 0 18px;font-size:13.5px;color:var(--text-dim)}
.dialog__text strong{color:var(--text)}
.dialog__actions{display:flex;gap:10px}.dialog__actions .btn{flex:1}
.toasts{position:fixed;right:18px;bottom:18px;z-index:60;display:grid;gap:10px;max-width:min(360px,calc(100vw - 36px))}
.toast{padding:12px 15px;border-radius:13px;font-size:13.5px;border:1px solid var(--line-strong);background:#16151f;animation:slide-in .3s var(--ease) both}
.toast--ok{border-color:rgba(52,211,153,.35)}.toast--err{border-color:rgba(248,113,113,.35)}
.toast.is-out{animation:slide-out .25s var(--ease) forwards}
.footer{max-width:1120px;margin:0 auto;padding:20px 22px 34px;display:flex;gap:10px;font-size:12px;color:var(--text-faint);border-top:1px solid var(--line)}
@keyframes rise{from{opacity:0;transform:translateY(12px)}to{opacity:1;transform:none}}
@keyframes slide-in{from{opacity:0;transform:translateX(16px)}to{opacity:1;transform:none}}
@keyframes slide-out{to{opacity:0;transform:translateX(16px)}}
@keyframes pulse{0%,100%{opacity:1}50%{opacity:.28}}
@media(max-width:720px){.page{padding:26px 16px 52px}.user-chip{display:none}
.stats{grid-template-columns:1fr 1fr}.stats .stat:last-child{display:none}
.hero{align-items:stretch}.hero .btn{width:100%}.grid{grid-template-columns:1fr}
.dialog__actions{flex-direction:column-reverse}}`;

const CLIENT = `
const state={csrfToken:null,user:null,accounts:[],limit:10,pollTimer:null,pendingDelete:null,busy:new Set()};
const $=function(s){return document.querySelector(s)};
const els={authView:$('#auth-view'),appView:$('#app-view'),authForm:$('#auth-form'),authEmail:$('#auth-email'),authPassword:$('#auth-password'),authError:$('#auth-error'),authSubmit:$('#auth-submit'),userEmail:$('#user-email'),signOut:$('#sign-out'),connectBtn:$('#connect-btn'),emptyConnect:$('#empty-connect'),grid:$('#accounts-grid'),empty:$('#empty-state'),statTotal:$('#stat-total'),statOnline:$('#stat-online'),statLimit:$('#stat-limit'),dialog:$('#confirm-dialog'),dialogAccount:$('#dialog-account'),tokenDialog:$('#token-dialog'),tokenForm:$('#token-form'),tokenInput:$('#token-input'),tokenError:$('#token-error'),tokenCancel:$('#token-cancel'),toasts:$('#toasts')};
async function api(path,opts){
opts=opts||{};
var method=(opts.method||'GET').toUpperCase();
var headers={};
if(opts.body)headers['content-type']='application/json';
if(method!=='GET'&&state.csrfToken)headers['x-csrf-token']=state.csrfToken;
var res=await fetch(path,{method:method,headers:headers,credentials:'same-origin',body:opts.body?JSON.stringify(opts.body):undefined});
var data=null;
try{data=await res.json()}catch(e){data=null}
if(!res.ok){var err=new Error((data&&data.error)||('Request failed ('+res.status+')'));err.status=res.status;throw err}
return data}
function toast(msg,kind){
kind=kind||'ok';
var n=document.createElement('div');
n.className='toast toast--'+kind;
n.textContent=msg;
els.toasts.appendChild(n);
setTimeout(function(){n.classList.add('is-out');setTimeout(function(){n.remove()},260)},4200)}
function ago(v){
if(!v)return '—';
var t=new Date(v).getTime();
if(isNaN(t))return '—';
var m=Math.round((Date.now()-t)/60000);
if(m<1)return 'just now';
if(m<60)return m+'m ago';
var h=Math.round(m/60);
if(h<24)return h+'h ago';
var d=Math.round(h/24);
if(d<30)return d+'d ago';
return new Date(v).toLocaleDateString()}
function when(v){
if(!v)return '—';
var d=new Date(v);
if(isNaN(d.getTime()))return '—';
return d.toLocaleString()}
var LABELS={online:'Online',connecting:'Connecting',offline:'Offline',error:'Error',reauth_required:'Reconnect'};
function pill(status){
var s=LABELS[status]?status:'offline';
var p=document.createElement('span');
p.className='pill pill--'+s;
p.innerHTML='<span class="pill__dot"></span>'+LABELS[s];
return p}
function row(k,v){
var r=document.createElement('div');r.className='meta-row';
var a=document.createElement('span');a.className='meta-row__key';a.textContent=k;
var b=document.createElement('span');b.className='meta-row__val';b.textContent=v;
r.append(a,b);return r}
function cardFor(acc){
var card=document.createElement('article');
card.className='card';
if(state.busy.has(acc.id))card.classList.add('is-busy');
var head=document.createElement('div');head.className='card__head';
var img=document.createElement('img');img.className='avatar';img.loading='lazy';img.alt=acc.username;
img.src=acc.avatarUrl||'https://cdn.discordapp.com/embed/avatars/0.png';
img.onerror=function(){img.src='https://cdn.discordapp.com/embed/avatars/0.png'};
var box=document.createElement('div');box.className='card__id';
var name=document.createElement('div');name.className='card__name';name.textContent=acc.globalName||acc.username;
var handle=document.createElement('div');handle.className='card__handle';handle.textContent='@'+acc.username;
box.append(name,handle);head.append(img,box,pill(acc.status));
var meta=document.createElement('div');meta.className='card__meta';
meta.append(row('Connected',when(acc.connectedAt)),row('Uptime',acc.sessionStartedAt?ago(acc.sessionStartedAt):'—'),row('Last checked',ago(acc.lastCheckedAt)),row('Status changed',ago(acc.lastStatusChange)));
card.append(head,meta);
if(acc.lastError){var e=document.createElement('p');e.className='card__error';e.textContent=acc.lastError;card.append(e)}
var acts=document.createElement('div');acts.className='card__actions';
var rf=document.createElement('button');rf.className='btn btn--ghost btn--sm';rf.textContent='Refresh';
rf.onclick=function(){refreshOne(acc)};
var rm=document.createElement('button');rm.className='btn btn--danger btn--sm';rm.textContent='Disconnect';
rm.onclick=function(){openConfirm(acc)};
acts.append(rf,rm);card.append(acts);
return card}
function render(){
els.grid.replaceChildren();
els.statTotal.textContent=String(state.accounts.length);
els.statOnline.textContent=String(state.accounts.filter(function(a){return a.status==='online'}).length);
els.statLimit.textContent=String(state.limit);
if(!state.accounts.length){els.empty.hidden=false;els.grid.hidden=true;return}
els.empty.hidden=true;els.grid.hidden=false;
state.accounts.forEach(function(a){els.grid.append(cardFor(a))});
els.connectBtn.disabled=state.accounts.length>=state.limit}
async function load(silent){
try{
var d=await api('/api/accounts');
state.accounts=d.accounts||[];
state.limit=d.limit||state.limit;
render()}
catch(e){if(e.status===401)return showAuth();if(!silent)toast(e.message,'err')}}
async function refreshOne(acc){
state.busy.add(acc.id);render();
try{
var d=await api('/api/accounts/'+acc.id+'/status');
var t=state.accounts.find(function(a){return a.id===acc.id});
if(t){t.status=d.status;t.lastError=d.lastError;t.lastCheckedAt=d.lastCheckedAt;t.sessionStartedAt=d.sessionStartedAt}
toast('Status refreshed for @'+acc.username)}
catch(e){toast(e.message,'err')}
finally{state.busy.delete(acc.id);render()}}
function startPoll(){
stopPoll();
state.pollTimer=setInterval(function(){if(!document.hidden)load(true)},20000)}
function stopPoll(){if(state.pollTimer)clearInterval(state.pollTimer);state.pollTimer=null}
function openToken(){
els.tokenInput.value='';
els.tokenError.hidden=true;
els.tokenDialog.showModal();
els.tokenInput.focus()}
async function submitToken(e){
e.preventDefault();
els.tokenError.hidden=true;
try{
var d=await api('/api/accounts/connect',{method:'POST',body:{token:els.tokenInput.value}});
var i=state.accounts.findIndex(function(a){return a.id===d.account.id});
if(i>=0)state.accounts[i]=d.account;else state.accounts.unshift(d.account);
els.tokenDialog.close();
render();
toast('@'+d.account.username+' connected')}
catch(err){els.tokenError.textContent=err.message;els.tokenError.hidden=false}}
function openConfirm(acc){state.pendingDelete=acc;els.dialogAccount.textContent='@'+acc.username;els.dialog.showModal()}
async function doDelete(){
var acc=state.pendingDelete;
state.pendingDelete=null;
if(!acc)return;
state.busy.add(acc.id);render();
try{
await api('/api/accounts/'+acc.id,{method:'DELETE'});
state.accounts=state.accounts.filter(function(a){return a.id!==acc.id});
toast('@'+acc.username+' disconnected')}
catch(e){toast(e.message,'err')}
finally{state.busy.delete(acc.id);render()}}
function showAuth(){stopPoll();els.appView.hidden=true;els.authView.hidden=false;els.authPassword.value='';els.authError.hidden=true}
function showApp(){
els.authView.hidden=true;els.appView.hidden=false;
els.userEmail.textContent=(state.user&&state.user.email)||'—';
els.grid.replaceChildren();els.empty.hidden=true;els.grid.hidden=false;
load();startPoll()}
var mode='login';
document.querySelectorAll('.tab').forEach(function(tab){
tab.onclick=function(){
mode=tab.dataset.tab;
document.querySelectorAll('.tab').forEach(function(t){t.classList.toggle('is-active',t===tab)});
els.authSubmit.querySelector('.btn__label').textContent=mode==='login'?'Sign in':'Create account';
els.authError.hidden=true}});
els.authForm.onsubmit=async function(e){
e.preventDefault();
els.authError.hidden=true;els.authSubmit.disabled=true;
try{
var d=await api(mode==='login'?'/api/auth/login':'/api/auth/register',{method:'POST',body:{email:els.authEmail.value.trim(),password:els.authPassword.value}});
state.csrfToken=d.csrfToken;state.user=d.user;
els.authForm.reset();showApp();toast(mode==='login'?'Welcome back':'Account created')}
catch(e){els.authError.textContent=e.message;els.authError.hidden=false}
finally{els.authSubmit.disabled=false}};
els.signOut.onclick=async function(){
try{await api('/api/auth/logout',{method:'POST'})}catch(e){}
state.csrfToken=null;state.user=null;state.accounts=[];
showAuth();toast('Signed out')};
els.connectBtn.onclick=openToken;
els.emptyConnect.onclick=openToken;
els.tokenForm.onsubmit=submitToken;
els.tokenCancel.onclick=function(){els.tokenDialog.close()};
els.dialog.addEventListener('close',function(){
if(els.dialog.returnValue==='confirm')doDelete();else state.pendingDelete=null});
document.addEventListener('visibilitychange',function(){if(!document.hidden&&state.user)load(true)});
(async function boot(){
try{
var s=await api('/api/session');
if(!s.authenticated){showAuth();return}
state.csrfToken=s.csrfToken;state.user=s.user;showApp()}
catch(e){showAuth()}})();`;

/* ============================ boot ============================ */

setInterval(() => {
  pool.query('DELETE FROM sessions WHERE expires_at < now()')
    .catch((e) => console.error('[cleanup]', e.message));
}, 3600000).unref();

(async () => {
  await migrate();
  const server = app.listen(PORT, () => console.log('[dashboard] :' + PORT));

  const stop = (sig) => {
    console.log('[dashboard] ' + sig);
    server.close(() => pool.end().then(() => process.exit(0)));
    setTimeout(() => process.exit(1), 10000).unref();
  };
  process.on('SIGTERM', () => stop('SIGTERM'));
  process.on('SIGINT', () => stop('SIGINT'));
})();