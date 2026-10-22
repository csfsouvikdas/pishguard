const DEFAULTS = { apiUrl: 'http://localhost:3000', serverChecks: true, warnOnClick: true };
const cache = new Map();

async function settings() { return { ...DEFAULTS, ...(await chrome.storage.sync.get(DEFAULTS)) }; }

async function serverCheck(urls) {
  const s = await settings();
  if (!s.serverChecks) return [];
  const fresh = urls.filter(u => !cache.has(u));
  if (fresh.length) {
    try {
      const r = await fetch(s.apiUrl.replace(/\/$/, '') + '/api/check', {
        method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ urls: fresh.slice(0, 25) })
      });
      (await r.json()).results.forEach(x => cache.set(x.url, x));
    } catch (e) { /* offline: fall back to local result */ }
  }
  return urls.map(u => cache.get(u)).filter(Boolean);
}

chrome.runtime.onMessage.addListener((msg, _sender, send) => {
  if (msg.type === 'check') { serverCheck(msg.urls).then(r => send({ results: r })); return true; }
  if (msg.type === 'settings') { settings().then(send); return true; }
  if (msg.type === 'report') {
    settings().then(s => fetch(s.apiUrl.replace(/\/$/, '') + '/api/report', {
      method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ url: msg.url })
    }).then(() => send({ ok: true })).catch(() => send({ ok: false })));
    return true;
  }
});
