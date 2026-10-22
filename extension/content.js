(() => {
  const seen = new WeakMap();
  let settings = { warnOnClick: true, serverChecks: true };
  chrome.runtime.sendMessage({ type: 'settings' }, s => { if (s) settings = s; });

  function mark(a, res) {
    a.dataset.pgVerdict = res.verdict;
    a.title = (a.title ? a.title + '\n' : '') + `⚠ PhishGuard: ${res.verdict} (${res.score}/100)\n` + res.reasons.map(r => '• ' + r.reason).join('\n');
  }

  function scan(root) {
    const links = (root.querySelectorAll ? root.querySelectorAll('a[href]') : []);
    const toServer = [];
    links.forEach(a => {
      if (seen.has(a)) return;
      const res = PhishDetector.analyze(a.href);
      seen.set(a, res);
      if (res.verdict === 'suspicious' || res.verdict === 'danger') {
        mark(a, res);
        // privacy: only suspicious links ever leave the browser
        if (settings.serverChecks) toServer.push(a);
      }
    });
    if (!toServer.length) return;
    const urls = [...new Set(toServer.map(a => a.href))];
    chrome.runtime.sendMessage({ type: 'check', urls }, resp => {
      if (!resp) return;
      const map = Object.fromEntries(resp.results.map(r => [r.url, r]));
      toServer.forEach(a => { const r = map[a.href]; if (r && r.score > seen.get(a).score) { seen.set(a, r); mark(a, r); } });
    });
  }

  function warn(a, res) {
    return new Promise(resolve => {
      const host = document.createElement('div'); host.id = 'pg-overlay';
      const sh = host.attachShadow({ mode: 'closed' });
      sh.innerHTML = `<style>
        .bg{position:fixed;inset:0;background:#000a;z-index:2147483647;display:grid;place-items:center;font:15px system-ui,sans-serif}
        .box{background:#fff;color:#111;max-width:460px;border-radius:14px;padding:22px;border-top:6px solid #dc2626;box-shadow:0 10px 40px #0008}
        h2{margin:0 0 8px}code{display:block;word-break:break-all;background:#f3f4f6;padding:8px;border-radius:6px;margin:8px 0}
        ul{padding-left:18px}button{padding:10px 16px;border:0;border-radius:8px;font-weight:600;cursor:pointer;margin-right:8px}
        .stay{background:#2563eb;color:#fff}.go{background:#e5e7eb}</style>
        <div class="bg"><div class="box"><h2>⚠️ Likely phishing link</h2>
        <code></code><ul></ul>
        <button class="stay">Go back (safe)</button><button class="go">Proceed anyway</button></div></div>`;
      sh.querySelector('code').textContent = res.url;
      const ul = sh.querySelector('ul');
      res.reasons.forEach(r => { const li = document.createElement('li'); li.textContent = r.reason; ul.appendChild(li); });
      sh.querySelector('.stay').onclick = () => { host.remove(); resolve(false); };
      sh.querySelector('.go').onclick = () => { host.remove(); resolve(true); };
      document.documentElement.appendChild(host);
    });
  }

  document.addEventListener('click', async e => {
    const a = e.target.closest && e.target.closest('a[href]');
    if (!a || !settings.warnOnClick || e.__pgBypass) return;
    let res = seen.get(a) || PhishDetector.analyze(a.href);
    if (res.verdict !== 'danger') return;
    e.preventDefault(); e.stopPropagation();
    if (await warn(a, res)) {
      if (a.target === '_blank') window.open(a.href, '_blank', 'noopener'); else location.href = a.href;
    }
  }, true);

  scan(document);
  new MutationObserver(muts => muts.forEach(m => m.addedNodes.forEach(n => n.nodeType === 1 && scan(n))))
    .observe(document.body || document.documentElement, { childList: true, subtree: true });
})();
