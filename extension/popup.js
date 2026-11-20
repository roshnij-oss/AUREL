const out = document.getElementById("out");
let current = "";
async function show(url) {
  current = url;
  const { online } = await chrome.storage.local.get({ online: false });
  try {
    const r = await api("/api/scan", { url, online, save: false });
    out.innerHTML = r.valid
      ? `<span class="pill ${r.level}">${esc(r.verdict)} · ${r.score}</span> <span class="note">Confidence: ${esc(r.confidence.level)}</span><div id="u">${esc(r.url)}</div>
         <ul>${r.findings.slice(0, 4).map(f => `<li>${esc(f.indicator)}</li>`).join("") || "<li>No suspicious indicators found</li>"}</ul>
         <div class="note">${r.incomplete.length} check(s) not run. A low score never proves a site is safe.</div>`
      : esc(r.error);
  } catch { out.innerHTML = "AUREL isn't running. Start it on this computer with <b>python run.py</b>, then reopen this popup."; }
}
chrome.tabs.query({ active: true, currentWindow: true }, ([t]) => t && /^https?:/.test(t.url) ? show(t.url) : (out.textContent = "Open a website to check it."));
document.getElementById("go").onclick = () => { const v = document.getElementById("m").value.trim(); if (v) show(v); };
document.getElementById("full").onclick = () => current && chrome.tabs.create({ url: `${API}/?url=${encodeURIComponent(current)}` });
for (const k of ["enabled", "online"]) {
  const box = document.getElementById(k === "enabled" ? "en" : "on");
  chrome.storage.local.get({ enabled: true, online: false }, s => (box.checked = s[k]));
  box.onchange = () => chrome.storage.local.set({ [k]: box.checked });
}
