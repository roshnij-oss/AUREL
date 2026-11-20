# AUREL presentation outline (12 slides)

*Tagline: AUREL doesn't just say HIGH RISK. It shows which checks fired, how sure it is, and which checks could not run.*

1. **Problem**: phishing links and QR codes are the easiest way into accounts; users cannot see why a link is risky.
2. **Why it matters**: one click exposes credentials and payments. "Safe/unsafe" labels hide the evidence.
3. **AUREL**: local-first risk intelligence; web app + Chrome extension on one engine; nothing visited, nothing uploaded by default.
4. **Architecture**: web app / extension -> Flask (localhost) -> engine (rules + ML + intel) -> SQLite. Show docs/ARCHITECTURE.md diagram.
5. **Detection methodology**: 8 layers (URL, hostname/homograph, brand/typosquat, domain/TLD, redirects, threat intel, ML, risk engine).
6. **Risk scoring**: grouped indicators avoid double counting; confirmed intel overrides heuristics; confidence level; thresholds 0-29 / 30-59 / 60+.
7. **Explainability**: reasoning panel, evidence per finding, ML contributions, "checks that could not run".
8. **Web demo**: scan with live stages, QR scan (never auto-opens), bulk + CSV, dashboard, history, PDF report, feedback.
9. **Extension demo**: background monitoring, badge, notification, high-confidence interstitial, popup, right-click check, service-down behaviour.
10. **Security and privacy**: no URL fetching, SSRF-guarded shortener resolver, localhost-only API with Host/Origin checks, minimal permissions, extension logs only flagged pages, disclosed online checks.
11. **Testing and results**: 32 automated tests; precision/recall/FPR/FNR from `tools.evaluate` on YOUR real train/test split (see docs/TESTING.md). Never claim 100%.
12. **Limitations and future scope**: URL-only analysis, needs local service, Firefox/Edge, page-content signals, user-feedback retraining, domain-age caching.
