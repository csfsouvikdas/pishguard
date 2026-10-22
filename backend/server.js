'use strict';
const fs = require('fs');
const path = require('path');
const express = require('express');
const helmet = require('helmet');
const cors = require('cors');
const rateLimit = require('express-rate-limit');
const { analyze } = require('../shared/detector');

const PORT = process.env.PORT || 3000;
const SAFE_BROWSING_KEY = process.env.SAFE_BROWSING_KEY || '';
const DATA_DIR = process.env.DATA_DIR || path.join(__dirname, 'data');
fs.mkdirSync(DATA_DIR, { recursive: true });

// ---- blocklist (one domain per line) ----
function loadBlocklist() {
  try {
    return new Set(fs.readFileSync(path.join(__dirname, 'data', 'blocklist.txt'), 'utf8')
      .split('\n').map(s => s.trim().toLowerCase()).filter(s => s && !s.startsWith('#')));
  } catch { return new Set(); }
}
const blocklist = loadBlocklist();

// ---- tiny TTL cache ----
const cache = new Map();
const TTL = 10 * 60 * 1000;
const cacheGet = k => { const v = cache.get(k); if (v && Date.now() - v.t < TTL) return v.d; cache.delete(k); };
const cacheSet = (k, d) => { if (cache.size > 5000) cache.clear(); cache.set(k, { t: Date.now(), d }); };

// ---- optional Google Safe Browsing ----
async function safeBrowsing(urls) {
  if (!SAFE_BROWSING_KEY || !urls.length) return new Set();
  try {
    const r = await fetch(`https://safebrowsing.googleapis.com/v4/threatMatches:find?key=${SAFE_BROWSING_KEY}`, {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        client: { clientId: 'phishguard', clientVersion: '1.0.0' },
        threatInfo: {
          threatTypes: ['MALWARE', 'SOCIAL_ENGINEERING', 'UNWANTED_SOFTWARE', 'POTENTIALLY_HARMFUL_APPLICATION'],
          platformTypes: ['ANY_PLATFORM'], threatEntryTypes: ['URL'],
          threatEntries: urls.map(url => ({ url }))
        }
      })
    });
    const j = await r.json();
    return new Set((j.matches || []).map(m => m.threat.url));
  } catch (e) { console.error('SafeBrowsing error', e.message); return new Set(); }
}

const app = express();
app.set('trust proxy', 1);
app.use(helmet({ contentSecurityPolicy: { directives: { defaultSrc: ["'self'"], scriptSrc: ["'self'"], styleSrc: ["'self'", "'unsafe-inline'"] } } }));
app.use(cors());                       // extension calls from any origin
app.use(express.json({ limit: '50kb' }));
app.use('/api', rateLimit({ windowMs: 60_000, limit: 120, standardHeaders: true, legacyHeaders: false }));

app.get('/api/health', (_req, res) => res.json({ ok: true, blocklist: blocklist.size, safeBrowsing: !!SAFE_BROWSING_KEY }));

app.post('/api/check', async (req, res) => {
  const body = req.body || {};
  const urls = Array.isArray(body.urls) ? body.urls.slice(0, 25) : (body.url ? [body.url] : []);
  if (!urls.length || urls.some(u => typeof u !== 'string' || u.length > 2048))
    return res.status(400).json({ error: 'Provide "url" or "urls" (max 25 strings, 2048 chars each).' });

  const results = {}; const pending = [];
  for (const u of urls) {
    const c = cacheGet(u);
    if (c) results[u] = c; else pending.push(u);
  }
  const flagged = await safeBrowsing(pending);
  for (const u of pending) {
    const r = analyze(u, { blocklist });
    if (flagged.has(u)) {
      r.reasons.unshift({ points: 100, reason: 'Flagged by Google Safe Browsing' });
      r.score = 100; r.verdict = 'danger';
    }
    cacheSet(u, r); results[u] = r;
  }
  res.json({ results: urls.map(u => results[u]) });
});

app.post('/api/report', (req, res) => {
  const { url, note } = req.body || {};
  if (typeof url !== 'string' || url.length > 2048) return res.status(400).json({ error: 'Invalid url' });
  fs.appendFile(path.join(DATA_DIR, 'reports.jsonl'),
    JSON.stringify({ t: new Date().toISOString(), url, note: String(note || '').slice(0, 500) }) + '\n',
    err => err ? res.status(500).json({ error: 'Could not save' }) : res.json({ ok: true }));
});

app.use(express.static(path.join(__dirname, 'public')));
if (require.main === module) app.listen(PORT, () => console.log(`PhishGuard API on :${PORT}`));
module.exports = app;
