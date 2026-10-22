const $ = id => document.getElementById(id);
async function check() {
  let url = $('u').value.trim(); if (!url) return;
  if (!/^https?:\/\//i.test(url)) url = 'http://' + url;
  const out = $('out'); out.hidden = false; out.className = ''; out.textContent = 'Checking…';
  try {
    const r = await fetch('/api/check', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ url }) });
    const d = (await r.json()).results[0];
    out.className = d.verdict; out.textContent = '';
    const h = document.createElement('div'); h.innerHTML = '<span class="v"></span> · risk score <b></b>/100';
    h.querySelector('.v').textContent = d.verdict; h.querySelector('b').textContent = d.score; out.appendChild(h);
    const ul = document.createElement('ul');
    (d.reasons.length ? d.reasons : [{ reason: 'No red flags found.' }]).forEach(x => { const li = document.createElement('li'); li.textContent = x.reason; ul.appendChild(li); });
    out.appendChild(ul);
  } catch { out.textContent = 'Could not reach the server.'; }
}
$('go').onclick = check; $('u').onkeydown = e => e.key === 'Enter' && check();
