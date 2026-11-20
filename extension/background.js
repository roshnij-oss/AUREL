// AUREL background monitor (Manifest V3). Service workers are suspended at any time, so every listener is registered
// at top level and all state lives in chrome.storage, never in memory. Only URLs are sent, and only to the local service.
const API = "http://127.0.0.1:5000";
const COLORS = { low: "#6f9bff", medium: "#f5c542", high: "#ff4d4f", down: "#6b7280" };

async function settings() { return chrome.storage.local.get({ enabled: true, online: false }); }

async function scan(url) {
  const { online } = await settings();
  const ctl = new AbortController(), t = setTimeout(() => ctl.abort(), 6000);
  try {
    const res = await fetch(`${API}/api/scan`, { method: "POST", headers: { "Content-Type": "application/json" }, signal: ctl.signal,
      body: JSON.stringify({ url, online, source: "extension" }) });
    return res.ok ? await res.json() : null;
  } finally { clearTimeout(t); }
}
const notify = (id, title, message) => chrome.notifications.create(id, { type: "basic", iconUrl: "icon128.png", title, message });
const top = r => r.findings.slice(0, 2).map(f => f.indicator).join(", ") || "multiple weak signals";

async function check(tabId, url) {
  if (!url || !/^https?:/.test(url) || url.startsWith(API)) return;
  const { enabled } = await settings();
  if (!enabled) return chrome.action.setBadgeText({ tabId, text: "" });
  const { bypass = [], last = {}, notified = [] } = await chrome.storage.session.get(["bypass", "last", "notified"]);
  if (bypass.includes(url) || last[tabId] === url) return;
  last[tabId] = url; await chrome.storage.session.set({ last });
  try {
    const r = await scan(url);
    if (!r || !r.valid) return;
    chrome.action.setBadgeText({ tabId, text: r.level === "low" ? "" : r.level === "high" ? "!!" : "!" });
    chrome.action.setBadgeBackgroundColor({ tabId, color: COLORS[r.level] });
    if (r.level === "high") {
      const key = r.registered_domain;
      if (!notified.includes(key)) { notified.push(key); await chrome.storage.session.set({ notified: notified.slice(-50) });
        notify("aurel-" + key, "AUREL: High Risk website", `${r.hostname}: ${top(r)}.`); }
      // Interstitial only for high-confidence threats: confirmed by intelligence, or a very high score.
      if (r.confidence.level === "High" || r.score >= 75)
        chrome.tabs.update(tabId, { url: chrome.runtime.getURL("warning.html") + "?url=" + encodeURIComponent(url) });
    }
    await chrome.storage.session.set({ svcDown: false });
  } catch (e) {                       // service not running, timeout or network failure: degrade quietly
    last[tabId] = null; await chrome.storage.session.set({ last, svcDown: true });
    chrome.action.setBadgeText({ tabId, text: "?" }); chrome.action.setBadgeBackgroundColor({ tabId, color: COLORS.down });
  }
}

chrome.tabs.onUpdated.addListener((tabId, info, tab) => { if (info.status === "loading") check(tabId, tab.url); });
chrome.tabs.onRemoved.addListener(async tabId => { const { last = {} } = await chrome.storage.session.get("last"); delete last[tabId]; chrome.storage.session.set({ last }); });

// After a browser restart or extension update, re-check what is open right now.
const recheck = () => chrome.tabs.query({ active: true }, tabs => tabs.forEach(t => check(t.id, t.url)));
chrome.runtime.onStartup.addListener(recheck);
chrome.runtime.onInstalled.addListener(() => {
  chrome.contextMenus.removeAll(() => chrome.contextMenus.create({ id: "aurel-link", title: "Check link with AUREL", contexts: ["link"] }));
  recheck();
});
chrome.contextMenus.onClicked.addListener(async info => {
  try {
    const r = await scan(info.linkUrl);
    if (!r || !r.valid) return notify("aurel-ctx", "AUREL", (r && r.error) || "Could not read that link.");
    notify("aurel-ctx", `AUREL: ${r.verdict} (${r.score})`, `${r.hostname}: ${top(r)}.`);
  } catch { notify("aurel-ctx", "AUREL", "The local service isn't running. Start it with: python run.py"); }
});
