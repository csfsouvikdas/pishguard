const D = { apiUrl: 'http://localhost:3000', serverChecks: true, warnOnClick: true };
chrome.storage.sync.get(D, s => { apiUrl.value = s.apiUrl; serverChecks.checked = s.serverChecks; warnOnClick.checked = s.warnOnClick; });
save.onclick = () => chrome.storage.sync.set({ apiUrl: apiUrl.value.trim(), serverChecks: serverChecks.checked, warnOnClick: warnOnClick.checked }, () => { msg.textContent = 'Saved ✓'; });
