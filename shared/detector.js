/* PhishGuard detection engine (UMD) — used by the extension AND the API. */
(function (root, factory) {
  if (typeof module === 'object' && module.exports) module.exports = factory();
  else root.PhishDetector = factory();
})(typeof self !== 'undefined' ? self : this, function () {
  'use strict';

  // brand -> official registrable domains
  const BRANDS = {
    paypal: ['paypal.com'], google: ['google.com', 'google.co.in', 'gmail.com', 'youtube.com'],
    microsoft: ['microsoft.com', 'live.com', 'office.com', 'outlook.com', 'microsoftonline.com'],
    apple: ['apple.com', 'icloud.com'], amazon: ['amazon.com', 'amazon.in', 'amazon.co.uk'],
    facebook: ['facebook.com', 'fb.com'], instagram: ['instagram.com'], netflix: ['netflix.com'],
    whatsapp: ['whatsapp.com', 'whatsapp.net'], linkedin: ['linkedin.com'], github: ['github.com'],
    dropbox: ['dropbox.com'], paytm: ['paytm.com'], phonepe: ['phonepe.com'],
    sbi: ['sbi.co.in', 'onlinesbi.sbi'], hdfcbank: ['hdfcbank.com'], icicibank: ['icicibank.com'],
    binance: ['binance.com'], coinbase: ['coinbase.com'], metamask: ['metamask.io'],
    chase: ['chase.com'], wellsfargo: ['wellsfargo.com'], dhl: ['dhl.com'], fedex: ['fedex.com'],
    anthropic: ['anthropic.com', 'claude.ai']
  };
  const SUSPICIOUS_TLDS = new Set(['zip', 'mov', 'tk', 'ml', 'ga', 'cf', 'gq', 'xyz', 'top', 'click',
    'country', 'support', 'work', 'rest', 'icu', 'buzz', 'cfd', 'sbs', 'monster', 'cyou', 'link']);
  const SHORTENERS = new Set(['bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'ow.ly', 'is.gd', 'buff.ly',
    'cutt.ly', 'rb.gy', 'shorturl.at', 'tiny.cc', 'rebrand.ly']);
  const KEYWORDS = ['login', 'signin', 'verify', 'secure', 'account', 'update', 'banking', 'confirm',
    'password', 'wallet', 'suspend', 'unlock', 'invoice', 'billing', 'authenticate', 'recover', 'kyc'];
  const SECOND_LEVEL = new Set(['co', 'com', 'org', 'net', 'gov', 'ac', 'edu']);

  function registrable(host) {
    const p = host.split('.');
    if (p.length <= 2) return host;
    const tld = p[p.length - 1], sld = p[p.length - 2];
    return (tld.length === 2 && SECOND_LEVEL.has(sld)) ? p.slice(-3).join('.') : p.slice(-2).join('.');
  }

  function levenshtein(a, b) {
    const m = a.length, n = b.length;
    if (!m) return n; if (!n) return m;
    let prev = Array.from({ length: n + 1 }, (_, i) => i);
    for (let i = 1; i <= m; i++) {
      const cur = [i];
      for (let j = 1; j <= n; j++)
        cur[j] = Math.min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (a[i - 1] === b[j - 1] ? 0 : 1));
      prev = cur;
    }
    return prev[n];
  }

  const isIPv4 = h => /^\d{1,3}(\.\d{1,3}){3}$/.test(h);
  const isOfficial = reg => Object.values(BRANDS).some(list => list.includes(reg));

  function analyze(input, opts) {
    opts = opts || {};
    const blocklist = opts.blocklist || new Set();
    let u;
    try { u = new URL(input); } catch (e) {
      return { url: input, score: 0, verdict: 'invalid', reasons: [] };
    }
    if (u.protocol !== 'http:' && u.protocol !== 'https:')
      return { url: input, score: 0, verdict: 'ignored', reasons: [] };

    const host = u.hostname.toLowerCase().replace(/\.$/, '');
    const reg = registrable(host);
    const reasons = [];
    let score = 0;
    const add = (pts, why) => { score += pts; reasons.push({ points: pts, reason: why }); };

    if (blocklist.has(host) || blocklist.has(reg)) add(100, 'Domain is on the known-phishing blocklist');
    if (u.username || u.password) add(30, 'URL contains credentials/“@” trick to hide the real domain');

    // trusted domains short-circuit (unless creds trick / blocklisted)
    if (isOfficial(reg) && score === 0)
      return { url: input, host, score: 0, verdict: 'safe', reasons: [] };

    if (isIPv4(host)) add(35, 'Uses a raw IP address instead of a domain');
    if (host.includes('xn--')) add(30, 'Punycode domain (possible look-alike / homograph attack)');
    if (u.protocol === 'http:') add(10, 'Connection is not encrypted (HTTP)');
    const tld = host.split('.').pop();
    if (SUSPICIOUS_TLDS.has(tld)) add(15, `Uncommon TLD “.${tld}” often abused by phishing`);
    const labels = host.split('.');
    if (!isIPv4(host) && labels.length > 4) add(10, 'Excessive number of subdomains');
    if ((host.match(/-/g) || []).length >= 3) add(10, 'Many hyphens in domain name');
    if ((host.match(/\d/g) || []).length >= 4 && !isIPv4(host)) add(5, 'Many digits in domain name');
    if (u.port && !['80', '443'].includes(u.port)) add(10, `Non-standard port ${u.port}`);
    if (SHORTENERS.has(host)) add(10, 'URL shortener hides the real destination');
    if (input.length > 200) add(10, 'Extremely long URL'); else if (input.length > 100) add(5, 'Long URL');
    if ((input.match(/%[0-9a-f]{2}/gi) || []).length >= 5) add(5, 'Heavy percent-encoding');
    if (/[?&](url|redirect|redir|next|goto|dest|return)=https?(:|%3a)/i.test(u.search)) add(10, 'Embeds another URL (possible open redirect)');

    const hay = (host + u.pathname).toLowerCase();
    const hits = KEYWORDS.filter(k => hay.includes(k));
    if (hits.length) add(Math.min(20, hits.length * 5), `Sensitive keywords: ${hits.slice(0, 4).join(', ')}`);

    // brand impersonation
    const sld = reg.split('.')[0];
    let flagged = false;
    for (const [brand, domains] of Object.entries(BRANDS)) {
      if (domains.includes(reg)) continue;
      if (brand.length >= 5 && host.includes(brand)) {
        add(40, `Impersonates “${brand}” but is not an official ${brand} domain`); flagged = true; break;
      }
    }
    if (!flagged) {
      const norm = sld.replace(/1/g, 'l').replace(/0/g, 'o').replace(/[-0-9]/g, '');
      for (const [brand, domains] of Object.entries(BRANDS)) {
        if (brand.length < 5 || domains.includes(reg)) continue;
        const d = levenshtein(norm, brand);
        if (d <= (brand.length > 7 ? 2 : 1) && (d > 0 || sld !== brand)) { add(35, `Domain looks like a typo of “${brand}”`); break; }
      }
    }

    score = Math.min(100, score);
    const verdict = score >= 60 ? 'danger' : score >= 30 ? 'suspicious' : 'safe';
    return { url: input, host, score, verdict, reasons };
  }

  return { analyze, registrable, levenshtein, BRANDS };
});
