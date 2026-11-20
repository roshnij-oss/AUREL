# Architecture

```
Web app (templates/index.html)      Chrome extension (MV3)
        \                                  /
         +--------  Flask API (server.py, 127.0.0.1 only)  --------+
                         |                                          |
                  engine.analyze()                          SQLite (database.py)
   URL structure -> hostname/homograph -> brand -> domain/TLD -> redirect -> threat intel -> ML -> risk engine
```
One `analyze()` function serves every entry point (scan, stream, bulk, QR, extension), so verdicts are identical everywhere.

## Detection layers
1. URL structure: length, subdomains, port, unusual characters, percent-encoding, wording.
2. Hostname: raw/obfuscated/malformed IPs, `@` tricks, Punycode, mixed-script homographs.
3. Brand: typosquatting (edit distance), leetspeak, confusable-letter skeletons, brand names under unrelated domains, against ~40 brands with their real domains.
4. Domain: entropy, hyphens, digits, TLD reputation tiers, optional RDAP age.
5. Redirects: redirect parameters, embedded URLs, shorteners; optional header-only shortener resolution.
6. Threat intelligence: local feed (offline), Google Safe Browsing and URLhaus (optional).
7. Explainable ML: logistic regression with per-feature contributions; may raise a score, never lower it.
8. Risk engine: indicators are grouped (strongest counts fully, others 35%, per-group caps) so related signals are not counted repeatedly. Confirmed intelligence matches force 100. Each result carries evidence, severity, impact, confidence, completed and unavailable checks.

## Safety decisions
- **No fetching of submitted URLs.** Certificate inspection and page analysis are deliberately not performed (listed as "not performed by design").
- **SSRF:** the only outbound contact with a URL-derived host is the opt-in shortener resolver: known shortener hosts only, public IPs only (checked before connecting), HEAD only, redirects read but never followed to the destination, 4 s timeout, max 4 hops. RDAP input is regex-validated.
- **Local API:** binds to 127.0.0.1; rejects foreign `Host` (DNS rebinding) and foreign `Origin` (cross-site requests); optional `AUREL_EXTENSION_ID` pins the extension. CSP, `nosniff`, `no-referrer`, `no-store` on API responses. Inputs are length-limited (URL 2048, bulk 50, upload 5 MB, PNG dimension guard). Errors return safe JSON.
- **Extension:** permissions are `tabs`, `notifications`, `storage`, `contextMenus` and the local host only. It sends URLs only, scans nothing when disabled, keeps state in `chrome.storage` (service workers can be suspended), shows a grey `?` badge if the service is down, re-checks open tabs after a restart, and only shows the interstitial for high-confidence threats (confirmed match or score >= 75).

## Known limitations
URL-only analysis can miss threats on clean-looking domains and can misjudge unusual legitimate ones. The interstitial replaces the tab once navigation starts, so the page may begin loading first. The extension needs the local service and an open browser. Heuristics are not a substitute for judgement.
