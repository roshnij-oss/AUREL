// Shared by the popup and warning page. The background worker keeps its own copy (service workers can't share globals).
const API = "http://127.0.0.1:5000";
const esc = s => String(s ?? "").replace(/[&<>"']/g, c => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
async function api(path, body) {
  const ctl = new AbortController(), t = setTimeout(() => ctl.abort(), 6000);
  try {
    const r = await fetch(API + path, { method: body ? "POST" : "GET", headers: body ? { "Content-Type": "application/json" } : {}, body: body ? JSON.stringify(body) : undefined, signal: ctl.signal });
    return await r.json();
  } finally { clearTimeout(t); }
}
