"""AUREL detection engine.

Layers: URL structure, hostname obfuscation and homographs, brand impersonation and typosquatting,
domain and TLD reputation, redirect analysis, threat intelligence, explainable ML, and a risk engine
that groups related indicators so they are never counted repeatedly.

AUREL never fetches a submitted URL. The only network activity (all opt-in via online=True) is:
RDAP for domain age, Safe Browsing / URLhaus lookups, and HEAD requests to well-known URL-shortener
services (public IPs only, redirects read but never followed to the final site)."""
import ipaddress, json, math, os, re, socket, unicodedata, urllib.error, urllib.request
from datetime import datetime, timezone
from urllib.parse import parse_qs, urlencode, urljoin, urlparse

HERE = os.path.dirname(os.path.abspath(__file__))
BLOCKLIST_PATH = os.environ.get("AUREL_BLOCKLIST") or os.path.join(HERE, "..", "data", "blocklist.txt")
MAX_URL = 2048
UA = {"User-Agent": "AUREL/1.0 (local phishing analysis)"}

KEYWORDS = ["login", "signin", "verify", "account", "update", "secure", "banking", "password", "confirm", "wallet",
            "suspend", "unlock", "billing", "invoice", "otp", "kyc", "refund", "recover", "validate", "authenticate"]
SHORTENERS = {"bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "cutt.ly", "rb.gy", "buff.ly", "tiny.cc", "shorturl.at"}
HIGH_TLDS = {"zip", "mov", "tk", "ml", "ga", "cf", "gq", "top", "xyz", "click", "work", "support", "country", "icu", "buzz", "cyou", "rest", "monster", "cam", "loan", "men", "bid"}
MID_TLDS = {"info", "biz", "online", "site", "live", "shop", "club", "vip", "link", "store", "tech", "fun"}
TWO_PART_SUFFIXES = {"co.uk", "co.in", "com.au", "org.uk", "gov.in", "ac.in", "co.jp", "com.br", "net.in", "org.in", "com.cn", "co.za"}
BRAND_DOMAINS = {
    "paypal": ("paypal.com", "paypal.me", "paypalobjects.com"),
    "google": ("google.com", "google.co.in", "google.co.uk", "googleapis.com", "googleusercontent.com", "gstatic.com", "goo.gl", "google.org", "googlevideo.com"),
    "microsoft": ("microsoft.com", "microsoftonline.com", "live.com", "office.com", "windows.com", "azure.com", "msn.com", "bing.com", "outlook.com", "sharepoint.com", "office365.com"),
    "apple": ("apple.com", "icloud.com"), "amazon": ("amazon.com", "amazon.in", "amazon.co.uk", "amazon.de", "amazon.co.jp", "amazonaws.com", "amzn.to"),
    "facebook": ("facebook.com", "fb.com", "fbcdn.net", "facebook.net"), "instagram": ("instagram.com",), "netflix": ("netflix.com", "nflxso.net"),
    "whatsapp": ("whatsapp.com", "whatsapp.net"), "linkedin": ("linkedin.com", "licdn.com"), "dropbox": ("dropbox.com", "dropboxusercontent.com"),
    "paytm": ("paytm.com", "paytm.in"), "flipkart": ("flipkart.com",), "sbi": ("sbi.co.in", "onlinesbi.com", "onlinesbi.sbi"),
    "hdfcbank": ("hdfcbank.com",), "icicibank": ("icicibank.com",), "irctc": ("irctc.co.in",), "binance": ("binance.com",),
    "coinbase": ("coinbase.com",), "metamask": ("metamask.io",), "twitter": ("twitter.com", "x.com", "t.co", "twimg.com"),
    "dhl": ("dhl.com", "dhl.de"), "fedex": ("fedex.com",), "usps": ("usps.com",), "chase": ("chase.com", "jpmorgan.com"),
    "wellsfargo": ("wellsfargo.com",), "bankofamerica": ("bankofamerica.com",), "docusign": ("docusign.com", "docusign.net"),
    "adobe": ("adobe.com", "adobelogin.com"), "zoom": ("zoom.us", "zoom.com"), "github": ("github.com", "github.io", "githubusercontent.com"),
    "telegram": ("telegram.org", "t.me", "telegram.me"), "spotify": ("spotify.com", "scdn.co"), "discord": ("discord.com", "discord.gg", "discordapp.com"),
}
CONFUSABLES = {"а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "х": "x", "у": "y", "і": "i", "ј": "j", "ѕ": "s", "һ": "h", "ԁ": "d",
               "ɡ": "g", "ο": "o", "ν": "v", "α": "a", "ι": "i", "κ": "k", "τ": "t", "ρ": "p", "ı": "i", "ƅ": "b", "ǀ": "l"}
LEET = str.maketrans("01345", "oleas")
CAPS = {"transport": 15, "structure": 30, "wording": 16, "obfuscation": 45, "brand": 45, "domain": 24, "reputation": 30, "redirect": 30}
LAYERS = {"structure": "URL structure", "wording": "URL structure", "obfuscation": "Hostname and homographs", "brand": "Brand impersonation",
          "domain": "Domain and TLD reputation", "reputation": "Domain and TLD reputation", "transport": "HTTPS", "redirect": "Redirect analysis"}


# ---------- helpers ----------
def edit_distance(a, b):
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb)))
        prev = cur
    return prev[-1]


def entropy(s):
    return -sum((s.count(c) / len(s)) * math.log2(s.count(c) / len(s)) for c in set(s)) if s else 0.0


def registered_domain(host):
    parts = host.split(".")
    if len(parts) >= 3 and ".".join(parts[-2:]) in TWO_PART_SUFFIXES:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:]) if len(parts) >= 2 else host


def ip_kind(host):
    """'ip' valid address, 'obfuscated' (decimal/hex/octal forms), 'malformed' (IP-like but invalid), or None."""
    h = host.strip("[]")
    try:
        ipaddress.ip_address(h)
        return "ip"
    except ValueError:
        pass
    parts = h.split(".")
    if all(re.fullmatch(r"0x[0-9a-f]+|\d+", x) for x in parts):
        if len(parts) <= 4 and (len(parts) < 4 or any(x.startswith("0x") or (len(x) > 1 and x.startswith("0")) for x in parts)):
            return "obfuscated"
        return "malformed"
    return None


def to_unicode(host):
    out = []
    for lab in host.split("."):
        if lab.startswith("xn--"):
            try:
                lab = lab.encode("ascii").decode("idna")
            except Exception:
                pass
        out.append(lab)
    return ".".join(out)


def scripts_of(s):
    out = set()
    for ch in s:
        if ch.isalpha():
            try:
                out.add(unicodedata.name(ch).split()[0])
            except ValueError:
                out.add("UNKNOWN")
    return out


def skeleton(s):
    s = "".join(CONFUSABLES.get(c, c) for c in s)
    return "".join(c for c in unicodedata.normalize("NFKD", s) if ord(c) < 128)


def _parse(raw):
    raw = (raw or "").strip() if isinstance(raw, str) else ""
    if not raw:
        return {"error": "Enter a URL to scan."}
    if len(raw) > MAX_URL:
        return {"error": f"That URL is too long (limit {MAX_URL} characters)."}
    if re.search(r"[\s\x00-\x1f]", raw):
        return {"error": "URLs cannot contain spaces or control characters."}
    has_scheme = bool(re.match(r"^[a-z][a-z0-9+.\-]*://", raw, re.I))
    m = re.match(r"^(javascript|data|file|ftp|mailto|tel|vbscript|blob|about|chrome):", raw, re.I)
    if m and not has_scheme:
        return {"error": f"Unsupported scheme '{m.group(1)}:'. AUREL analyses http and https links only."}
    url = raw if has_scheme else "http://" + raw
    try:
        p = urlparse(url)
        host, port = (p.hostname or "").rstrip(".").lower(), p.port
    except ValueError:
        return {"error": "That URL could not be parsed."}
    if p.scheme.lower() not in ("http", "https"):
        return {"error": f"Unsupported scheme '{p.scheme}'. AUREL analyses http and https links only."}
    if not host or not (ip_kind(host) or "." in host):
        return {"error": "Enter a full web address such as https://example.com."}
    return {"url": url, "p": p, "host": host, "port": port, "normalised": not has_scheme}


def combine(findings):
    """Group related indicators: strongest counts fully, the rest 35%, each group capped. Sets f['impact']."""
    groups, total = {}, 0.0
    for f in findings:
        groups.setdefault(f["group"], []).append(f)
    for g, fs in groups.items():
        fs.sort(key=lambda f: -f["weight"])
        raw = [f["weight"] * (1 if i == 0 else .35) for i, f in enumerate(fs)]
        s, cap = sum(raw), CAPS.get(g, 30)
        k = min(1, cap / s) if s else 1
        for f, r in zip(fs, raw):
            f["impact"] = round(r * k, 1)
        total += min(s, cap)
    if total > 100:                      # keep displayed impacts reconciled with the capped score
        for f in findings:
            f["impact"] = round(f["impact"] * 100 / total, 1)
    return min(round(total), 100)


# ---------- threat intelligence (local feed + optional APIs) ----------
_feed = {"mtime": None, "urls": set(), "hosts": set()}


def _norm(u):
    return re.sub(r"^https?://", "", u.split("#")[0]).rstrip("/")


def feed_available():
    try:
        m = os.path.getmtime(BLOCKLIST_PATH)
    except OSError:
        _feed.update(mtime=None, urls=set(), hosts=set())
        return False
    if m != _feed["mtime"]:
        urls, hosts = set(), set()
        with open(BLOCKLIST_PATH, encoding="utf-8", errors="ignore") as fh:
            for line in fh:
                l = line.strip().lower()
                if l and not l.startswith("#"):
                    (urls if "/" in l else hosts).add(_norm(l) if "/" in l else l)
        _feed.update(mtime=m, urls=urls, hosts=hosts)
    return bool(_feed["urls"] or _feed["hosts"])


def check_feed(url, host, reg):
    return feed_available() and (_norm(url.lower()) in _feed["urls"] or host in _feed["hosts"] or reg in _feed["hosts"])


def check_threat_intel(url):
    """Optional API lookups. Keys come from environment variables only. The URL is sent to the services queried."""
    res = {"configured": False, "match": False, "queried": [], "sources": [], "errors": []}
    gsb = os.environ.get("GSB_API_KEY")
    if gsb:
        res["configured"] = True; res["queried"].append("Google Safe Browsing")
        body = {"client": {"clientId": "aurel", "clientVersion": "1.0"}, "threatInfo": {
            "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE"], "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"], "threatEntries": [{"url": url}]}}
        try:
            req = urllib.request.Request(f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={gsb}",
                                         data=json.dumps(body).encode(), headers={"Content-Type": "application/json"})
            with urllib.request.urlopen(req, timeout=5) as r:
                if json.load(r).get("matches"):
                    res["match"] = True; res["sources"].append("Google Safe Browsing")
        except Exception as e:
            res["errors"].append("Safe Browsing: " + type(e).__name__)
    uh = os.environ.get("URLHAUS_API_KEY")
    if uh:
        res["configured"] = True; res["queried"].append("URLhaus")
        try:
            req = urllib.request.Request("https://urlhaus-api.abuse.ch/v1/url/", data=urlencode({"url": url}).encode(), headers={"Auth-Key": uh})
            with urllib.request.urlopen(req, timeout=5) as r:
                if json.load(r).get("query_status") == "ok":
                    res["match"] = True; res["sources"].append("URLhaus")
        except Exception as e:
            res["errors"].append("URLhaus: " + type(e).__name__)
    return res


def domain_age_days(domain):
    """Registration age via public RDAP. Sends only the registered domain to rdap.org. None if unavailable."""
    if not re.fullmatch(r"[a-z0-9.\-]{3,253}", domain):
        return None
    try:
        req = urllib.request.Request(f"https://rdap.org/domain/{domain}", headers={"Accept": "application/json", **UA})
        with urllib.request.urlopen(req, timeout=5) as r:
            for e in json.load(r).get("events", []):
                if e.get("eventAction") == "registration":
                    return (datetime.now(timezone.utc) - datetime.fromisoformat(e["eventDate"].replace("Z", "+00:00"))).days
    except Exception:
        pass
    return None


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *a, **k):
        return None


def _public_host(host):
    try:
        return all(ipaddress.ip_address(i[4][0]).is_global for i in socket.getaddrinfo(host, 443, type=socket.SOCK_STREAM))
    except Exception:
        return False


def resolve_shortener(url, max_hops=4):
    """SSRF-safe: only contacts known shortener hosts that resolve to public IPs, HEAD only, reads Location without following."""
    chain, cur = [url], url
    for _ in range(max_hops):
        h = (urlparse(cur).hostname or "").lower()
        if h not in SHORTENERS or not _public_host(h):
            return chain, None
        req = urllib.request.Request("https://" + cur.split("://", 1)[1], method="HEAD", headers=UA)
        try:
            urllib.request.build_opener(_NoRedirect).open(req, timeout=4)
            return chain, None
        except urllib.error.HTTPError as e:
            loc = e.headers.get("Location")
            if e.code in (301, 302, 303, 307, 308) and loc:
                cur = urljoin(cur, loc)
                if not re.match(r"https?://", cur, re.I):
                    return chain, "unsupported redirect target"
                chain.append(cur)
                continue
            return chain, None
        except Exception as e:
            return chain, type(e).__name__
    return chain, None


# ---------- main analysis ----------
def analyze(raw, online=False, use_ml=True, progress=None, use_feeds=True):
    P = progress or (lambda *_: None)
    v = _parse(raw)
    if "error" in v:
        return {"valid": False, "error": v["error"]}
    url, p, host, port = v["url"], v["p"], v["host"], v["port"]
    P("URL validation")
    kind = ip_kind(host)
    try:
        ahost = host if host.isascii() else host.encode("idna").decode("ascii")
    except UnicodeError:
        ahost = host
    uhost = to_unicode(ahost)
    reg = host if kind else registered_domain(ahost)
    subs = [] if kind or ahost == reg else [s for s in ahost[:-len(reg)].strip(".").split(".") if s]
    tld = "" if kind else (reg.split(".", 1)[1] if "." in reg else reg)
    label = "" if kind else reg.split(".")[0]
    findings = []

    def add(group, name, weight, why, evidence=None):
        findings.append({"indicator": name, "weight": weight, "explanation": why, "evidence": evidence, "group": group})

    # 1. URL structure
    if p.scheme == "http":
        add("transport", "No HTTPS", 12, "The connection is unencrypted, so data sent to this site can be intercepted. (HTTPS alone never proves a site is legitimate.)", "scheme: http")
    if len(url) > 75:
        add("structure", "Unusually long URL", 8 if len(url) < 120 else 12, "Long URLs are often used to hide the real destination.", f"{len(url)} characters")
    real_subs = [s for s in subs if s != "www"]
    if len(real_subs) >= 3:
        add("structure", "Excessive subdomains", 14, "Stacked subdomains imitate trusted names, e.g. brand.com.evil.example.", ".".join(subs))
    if port and port not in (80, 443):
        add("structure", "Non-standard port", 8, "Ordinary websites rarely use an unusual port.", f":{port}")
    odd = sorted(set(re.findall(r"[^a-z0-9.\-]", ahost))) if ahost.isascii() and not kind else []
    if odd:
        add("structure", "Unusual characters in hostname", 10, "Valid hostnames use letters, digits and hyphens only.", " ".join(odd))
    if len(re.findall(r"%[0-9a-f]{2}", url.lower())) >= 5:
        add("structure", "Heavy percent-encoding", 8, "Excessive encoding can hide the real path or keywords.", f"{len(re.findall(r'%[0-9a-f]{2}', url.lower()))} escapes")
    low = url.lower().split("://", 1)[1]
    hits = sorted({k for k in KEYWORDS if k in low})
    if hits:
        add("wording", "Suspicious keywords", min(4 * len(hits), 16), "Account-related wording is common in phishing URLs, but also in genuine login pages, so it counts lightly.", ", ".join(hits))
    P("URL structure")

    # 2. Hostname obfuscation and homographs
    if kind == "ip":
        add("obfuscation", "IP address as host", 30, "Legitimate services rarely use a raw IP address instead of a domain name.", host)
    elif kind == "obfuscated":
        add("obfuscation", "IP address obfuscation", 35, "Decimal, hexadecimal or octal numbers can hide a raw IP address; browsers still resolve them.", host)
    elif kind == "malformed":
        add("obfuscation", "Malformed IP-like hostname", 30, "The hostname looks like an IP address but is not valid.", host)
    if "@" in (p.netloc or ""):
        add("obfuscation", "@ symbol in URL", 25, "Text before @ is ignored by browsers and is used to disguise the real destination.", p.netloc.split("@")[0] + "@")
    if "xn--" in ahost:
        add("obfuscation", "Punycode domain", 18, "An internationalised domain that may use look-alike characters to imitate a real name.", uhost)
    scripts = scripts_of(uhost)
    if len(scripts) > 1 or ({"CYRILLIC", "GREEK"} & scripts and "LATIN" in scripts):
        add("obfuscation", "Homograph risk (mixed scripts)", 35, "Letters from different alphabets can look identical to Latin letters and spoof a trusted name.", f"{', '.join(sorted(scripts))} in {uhost}")
    P("Hostname & homograph")

    # 3. Brand impersonation and typosquatting
    if not kind:
        sk = skeleton(uhost)
        label_sk = skeleton(to_unicode(label))
        tokens = [t for t in re.split(r"[.\-]", sk) if t]
        variants = tokens + [t.translate(LEET) for t in tokens]
        for b, legit in BRAND_DOMAINS.items():
            if reg in legit or (to_unicode(label) == b and tld.split(".")[-1] not in HIGH_TLDS):
                continue
            tok = next((t for t in variants if t == b or (len(b) >= 6 and b in t)), None)
            if tok:
                add("brand", f"Possible impersonation of '{b}'", 38, f"The hostname contains '{b}' (or a look-alike or leetspeak form) but the registered domain '{reg}' does not belong to that brand.", f"'{tok}' in {uhost}")
                break
            if len(b) >= 5 and len(label_sk) >= 5:
                cands = {label_sk, label_sk.translate(LEET), label_sk.replace("rn", "m").replace("vv", "w")}
                d = min(edit_distance(c, b) for c in cands)
                if 0 < d <= (1 if len(b) < 9 else 2):
                    add("brand", f"Possible impersonation of '{b}'", 38, f"'{label}' differs from '{b}' by {d} character(s), a typosquatting pattern.", f"{label} vs {b}")
                    break
    P("Brand impersonation")

    # 4. Domain and TLD reputation
    age = None
    if not kind:
        hy = host.replace("xn--", "").count("-")
        if hy >= 3:
            add("domain", "Many hyphens in hostname", 8, "Hostnames with several hyphens are common in throwaway phishing domains.", f"{hy} hyphens")
        if sum(c.isdigit() for c in label) >= 4:
            add("domain", "Many digits in domain name", 8, "Established brands rarely use number-heavy domain names.", label)
        ent = entropy(label)
        if len(label) >= 10 and (ent >= 3.5 or (ent >= 3.0 and sum(c.isdigit() for c in label) >= 3)):
            add("domain", "Random-looking domain name", 16, "High character randomness suggests an automatically generated domain.", f"entropy {ent:.2f} for '{label}'")
        last = tld.split(".")[-1]
        if last in HIGH_TLDS:
            add("reputation", f"Frequently abused TLD (.{last})", 12, "This top-level domain is heavily used in low-cost abuse campaigns.", f".{last}")
        elif last in MID_TLDS:
            add("reputation", f"Less-trusted TLD (.{last})", 5, "This TLD sees above-average abuse, so it counts only lightly.", f".{last}")
        age = domain_age_days(reg) if online else None
        if age is not None and age < 30:
            add("reputation", "Very new domain", 25, "Most phishing domains are used within weeks of registration.", f"registered {age} days ago")
        elif age is not None and age < 180:
            add("reputation", "Recently registered domain", 10, "Established organisations usually have older domains.", f"registered {age} days ago")
    P("Domain reputation")

    # 5. Redirect analysis (offline signals; live resolution only for known shorteners and only when online)
    chain, chain_err, is_short = [url], None, ahost in SHORTENERS
    if is_short:
        add("redirect", "URL shortener", 12, "The final destination is hidden behind a shortened link.", ahost)
        if online:
            chain, chain_err = resolve_shortener(url)
            if len(chain) > 1:
                dest = analyze(chain[-1], online=False, use_ml=False, use_feeds=use_feeds)
                add("redirect", "Shortened link resolves elsewhere", 5, "Destination read from the shortener's redirect header (the destination itself was not visited).", " -> ".join(urlparse(c).hostname or c for c in chain))
                if dest.get("valid") and dest["score"] >= 30:
                    add("redirect", "Destination looks risky", 30 if dest["score"] >= 60 else 15, f"The resolved destination scores {dest['score']} ({dest['verdict']}).", chain[-1][:90])
    for k, vals in parse_qs(p.query).items():
        if k.lower() in ("url", "redirect", "redirect_uri", "next", "return", "returnurl", "dest", "destination", "goto", "continue", "target", "u"):
            for val in vals:
                th = (urlparse(val if "://" in val else "//" + val).hostname or "").lower()
                if val.startswith(("http", "//")) and th and registered_domain(th) != reg:
                    add("redirect", "Redirect parameter to another site", 15, f"The '{k}' parameter sends visitors to another site, a common open-redirect trick.", f"{k} -> {th}")
    if "://" in p.path.lower():
        add("redirect", "Embedded URL in path", 10, "A second web address inside the path is a common way to disguise the destination.", p.path[:60])
    P("Redirect analysis")

    # 6. Threat intelligence
    feed_ok = use_feeds and feed_available()
    feed_hit = use_feeds and feed_ok and check_feed(url, ahost, reg)
    ti = check_threat_intel(url) if online else {"configured": False, "match": False, "queried": [], "sources": [], "errors": []}
    P("Threat intelligence")

    # 7. Risk engine
    rule_score = combine(findings)
    confirmed = bool(feed_hit or ti["match"])
    if confirmed:
        src = ([("the local threat feed")] if feed_hit else []) + ti["sources"]
        findings.append({"indicator": "Known threat match", "weight": 100, "impact": 100, "group": "intel", "evidence": ", ".join(src),
                         "explanation": "This URL is listed as malicious by " + " and ".join(src) + ". Confirmed matches outweigh every heuristic."})
        rule_score = 100
    score, ml_res = rule_score, None
    if use_ml and not confirmed:
        try:
            from aurel import ml
            ml_res = ml.predict(url, findings)
        except Exception:
            ml_res = None
        if ml_res:
            score = max(rule_score, round(0.6 * rule_score + 0.4 * ml_res["probability"] * 100))
    level = "high" if score >= 60 else "medium" if score >= 30 else "low"
    P("ML model")
    P("Risk engine")
    findings.sort(key=lambda f: -f["impact"])
    for f in findings:
        f["severity"] = "danger" if f["impact"] >= 25 else "caution" if f["impact"] >= 10 else "info"
        f["layer"] = "Threat intelligence" if f["group"] == "intel" else LAYERS[f["group"]]

    groups = {f["group"] for f in findings}
    ti_why = ("online checks are off" if not online else "no API key configured (set GSB_API_KEY or URLHAUS_API_KEY)" if not ti["configured"]
              else "; ".join(ti["errors"]) if ti["errors"] and not ti["match"] else None)
    age_note = f"Domain age: {age} days." if age is not None else "Domain age not checked (" + ("online checks are off)." if not online else "lookup unavailable).")
    def grp_check(name, gs, detail):
        n = sum(f["group"] in gs for f in findings)
        return {"name": name, "status": "flagged" if n else "passed", "detail": f"{n} indicator(s). {detail}".strip()}
    checks = [
        grp_check("URL structure", {"structure", "wording"}, "Length, subdomains, port, characters and wording."),
        grp_check("Hostname and homographs", {"obfuscation"}, "IP forms, @ tricks, Punycode and mixed-script look-alikes."),
        grp_check("Brand impersonation", {"brand"}, "Typosquatting, leetspeak and brand names in unrelated domains."),
        grp_check("Domain and TLD reputation", {"domain", "reputation"}, "Randomness, hyphens, digits and TLD. " + age_note),
        {"name": "HTTPS", "status": "flagged" if p.scheme == "http" else "passed",
         "detail": "Not encrypted." if p.scheme == "http" else "Encrypted connection. This does not prove the site is legitimate."},
        grp_check("Redirect analysis", {"redirect"}, "Redirects written into the URL; shortener targets are read only when online checks are on."),
        {"name": "Local threat feed", "status": "not_run" if not feed_ok else ("flagged" if feed_hit else "passed"),
         "detail": "Not completed: no feed installed (run python -m tools.update_feeds)." if not feed_ok else ("Listed in the local feed." if feed_hit else "No match in the local feed.")},
        {"name": "Threat-intelligence APIs", "status": "not_run" if ti_why else ("flagged" if ti["match"] else "passed"),
         "detail": ("Not completed: " + ti_why + ".") if ti_why else ("Matched: " + ", ".join(ti["sources"]) + ".") if ti["match"] else "No match in " + ", ".join(ti["queried"]) + ". This does not prove the URL is safe."},
        {"name": "ML model", "status": "passed" if ml_res else "not_run",
         "detail": f"Estimated {round(ml_res['probability'] * 100)}% phishing likelihood." if ml_res else "Not completed: model unavailable (run python -m tools.train_model)."},
    ]
    if is_short:
        checks.append({"name": "Live shortener resolution", "status": "passed" if len(chain) > 1 else "not_run",
                       "detail": "Resolved: " + " -> ".join(urlparse(c).hostname or c for c in chain) if len(chain) > 1 else
                       "Not completed: " + ("online checks are off." if not online else (chain_err or "no redirect returned") + ".")})
    by_design = [{"name": "Certificate inspection", "detail": "Requires connecting to the submitted site, which AUREL never does."},
                 {"name": "Page content analysis", "detail": "AUREL reads the address only, never the page or its forms."}]
    ml_agrees = bool(ml_res) and ((ml_res["probability"] >= .5) == (level != "low"))
    if confirmed:
        conf = {"level": "High", "reason": "Confirmed by a threat-intelligence source."}
    elif not ti_why and ml_agrees:
        conf = {"level": "Moderate", "reason": "Heuristics, ML and threat intelligence all completed and agree. Heuristics alone are never conclusive."}
    elif ti_why or not feed_ok:
        conf = {"level": "Limited", "reason": "Threat intelligence did not run, so this rests on heuristics and the ML model only."}
    else:
        conf = {"level": "Low", "reason": "The heuristic and ML signals disagree."}
    advice = {"high": ["Do not enter passwords, payment details or personal data.", "Leave the page and reach the service by typing its official address yourself or using a bookmark.", "Report the link to your IT or security team."],
              "medium": ["Be cautious: verify the domain matches the organisation you expect.", "Avoid logging in until you confirm the link through another channel."],
              "low": ["Few warning signs were found, but this does not prove the site is safe.", "Still check the domain name before entering sensitive information."]}[level]
    if "brand" in groups:
        advice = advice + ["Open the real brand's site by typing its address, never through this link."]
    if "obfuscation" in groups:
        advice = advice + ["The hostname uses disguised or look-alike characters. Do not trust how it looks."]
    if confirmed:
        advice = ["Do not visit this link. It is a confirmed threat."] + advice
    return {"valid": True, "url": url, "normalised": v["normalised"], "hostname": host, "registered_domain": reg, "subdomain": ".".join(subs), "tld": tld,
            "scheme": p.scheme, "https": p.scheme == "https", "score": score, "rule_score": rule_score, "ml": ml_res, "domain_age_days": age,
            "online": online, "level": level, "verdict": {"low": "Low Risk", "medium": "Suspicious", "high": "High Risk"}[level],
            "verdict_note": "No threats found does not mean the site is safe." if level == "low" else "",
            "confidence": conf, "findings": findings, "checks": checks, "incomplete": [c["name"] for c in checks if c["status"] == "not_run"],
            "by_design": by_design, "redirect_chain": chain, "threat_intel": ti, "recommendations": advice}
