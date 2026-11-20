const url = new URLSearchParams(location.search).get("url") || "";
document.getElementById("u").textContent = url;
api("/api/scan", { url, save: false }).then(r => (r.findings || []).slice(0, 4).forEach(f => {
  const li = document.createElement("li"); li.textContent = f.indicator; document.getElementById("why").append(li); })).catch(() => {});
document.getElementById("back").onclick = () => (history.length > 1 ? history.go(-2) : window.close());
document.getElementById("more").onclick = () => (location.href = `${API}/?url=${encodeURIComponent(url)}`);
document.getElementById("fp").onclick = async e => { try { await api("/api/feedback", { url, kind: "false_positive" }); e.target.textContent = "Reported. Thank you."; } catch { e.target.textContent = "AUREL isn't running."; } e.target.disabled = true; };
document.getElementById("go").onclick = async () => {
  const { bypass = [] } = await chrome.storage.session.get("bypass");
  await chrome.storage.session.set({ bypass: [...bypass, url] });
  location.href = url;
};
