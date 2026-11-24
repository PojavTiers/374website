// automation/index.js
'use strict';

const crypto = require('node:crypto');
const express = require('express');
const { Client } = require('discord.js-selfbot-v13');

const PORT = Number(process.env.PORT || 3000);
const SECRET = process.env.AUTOMATION_SHARED_SECRET;

if (!SECRET) {
  console.error('[fatal] AUTOMATION_SHARED_SECRET missing');
  process.exit(1);
}

const sessions = new Map();

function verify(req, raw) {
  const ts = req.get('x-automation-timestamp') || '';
  const sig = req.get('x-automation-signature') || '';
  if (!ts || !sig) return false;
  if (Math.abs(Date.now() - Number(ts)) > 300000) return false;
  const canonical = ts + '.' + req.method.toUpperCase() + '.' + req.path + '.' + raw;
  const expected = crypto.createHmac('sha256', SECRET).update(canonical).digest('hex');
  const a = Buffer.from(sig);
  const b = Buffer.from(expected);
  return a.length === b.length && crypto.timingSafeEqual(a, b);
}

async function kill(id) {
  const s = sessions.get(id);
  if (!s) return false;
  sessions.delete(id);
  s.client.removeAllListeners();
  try { await s.client.destroy(); } catch {}
  return true;
}

async function start(p) {
  const { accountId, token } = p;
  if (!accountId || !token) throw new Error('accountId and token required');

  await kill(accountId);

  const rec = {
    accountId,
    status: 'connecting',
    error: null,
    sessionStartedAt: new Date().toISOString(),
    client: null,
  };
  sessions.set(accountId, rec);

  const client = new Client({ checkUpdate: false, readyStatus: 'online' });
  rec.client = client;

  client.on('ready', () => {
    const l = sessions.get(accountId);
    if (!l) return;
    l.status = 'online';
    l.error = null;
    l.sessionStartedAt = new Date().toISOString();
  });
  client.on('shardReconnecting', () => {
    const l = sessions.get(accountId);
    if (l) { l.status = 'connecting'; l.error = 'Reconnecting'; }
  });
  client.on('shardResume', () => {
    const l = sessions.get(accountId);
    if (l) { l.status = 'online'; l.error = null; }
  });
  client.on('shardDisconnect', (e) => {
    const l = sessions.get(accountId);
    if (l) { l.status = e && e.code === 1000 ? 'offline' : 'connecting'; l.error = 'Gateway closed (' + (e && e.code) + ')'; }
  });
  client.on('error', (err) => {
    const l = sessions.get(accountId);
    if (l) { l.status = 'error'; l.error = String(err && err.message || err).slice(0, 300); }
  });

  await client.login(token);
  return rec;
}

const app = express();
app.disable('x-powered-by');
app.use(express.json({ limit: '128kb' }));

app.use((req, res, next) => {
  if (req.path === '/health') return next();
  const raw = req.body && Object.keys(req.body).length ? JSON.stringify(req.body) : '';
  if (!verify(req, raw)) return res.status(401).json({ error: 'invalid_signature' });
  next();
});

app.get('/health', (_req, res) => {
  res.json({ ok: true, sessions: sessions.size,
    online: [...sessions.values()].filter((s) => s.status === 'online').length });
});

app.post('/internal/accounts/connect', async (req, res) => {
  try {
    const r = await start(req.body || {});
    res.json({ ok: true, status: r.status });
  } catch (e) {
    const id = req.body && req.body.accountId;
    const l = id && sessions.get(id);
    if (l) { l.status = 'error'; l.error = String(e.message).slice(0, 300); }
    res.status(502).json({ ok: false, error: String(e.message).slice(0, 300) });
  }
});

app.get('/internal/accounts/:id/status', (req, res) => {
  const r = sessions.get(req.params.id);
  if (!r) return res.status(404).json({ error: 'unknown_session' });
  res.json({ status: r.status, error: r.error, sessionStartedAt: r.sessionStartedAt });
});

app.delete('/internal/accounts/:id', async (req, res) => {
  const ok = await kill(req.params.id);
  if (!ok) return res.status(404).json({ error: 'unknown_session' });
  res.json({ ok: true });
});

const server = app.listen(PORT, () => console.log('[automation] :' + PORT));

async function stop(sig) {
  console.log(sig);
  await Promise.allSettled([...sessions.keys()].map(kill));
  server.close(() => process.exit(0));
  setTimeout(() => process.exit(1), 12000).unref();
}
process.on('SIGTERM', () => stop('SIGTERM'));
process.on('SIGINT', () => stop('SIGINT'));