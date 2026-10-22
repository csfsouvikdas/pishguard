const $ = id => document.getElementById(id);
let current = '';
function render(r) {
  current = r.url; const out = $('out'); out.className = r.verdict; out.textContent = '';
  const h = document.createElement('b'); h.textContent = `${r.verdict.toUpperCase()} — ${r.score}/100`; out.appendChild(h);
  const ul = document.createElement('ul');
  (r.reasons.length ? r.reasons : [{ reason: 'No red flags found.' }]).forEach(x => { const li = document.createElement('li'); li.textContent = x.reason; ul.appendChild(li); });
  out.appendChild(ul);
  $('report').hidden = r.verdict === 'safe';
}
async function check(url) {
  if (!/^https?:\/\//i.test(url)) url = 'http://' + url;
  let r = PhishDetector.analyze(url); render(r);
  chrome.runtime.sendMessage({ type: 'check', urls: [url] }, resp => {
    const s = resp && resp.results && resp.results[0]; if (s && s.score > r.score) render(s);
  });
}
$('go').onclick = () => $('u').value && check($('u').value.trim());
$('opts').onclick = e => { e.preventDefault(); chrome.runtime.openOptionsPage(); };
$('report').onclick = () => chrome.runtime.sendMessage({ type: 'report', url: current }, () => { $('report').textContent = 'Reported — thanks!'; });
chrome.tabs.query({ active: true, currentWindow: true }, ([t]) => { if (t && t.url && /^https?:/.test(t.url)) { $('u').value = t.url; check(t.url); } });
