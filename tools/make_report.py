"""Generate the AUREL project report PDF.   pip install reportlab
    python -m tools.make_report --repo https://github.com/YOUR-USERNAME/aurel [--author "Your Name"] [--out AUREL_Project_Report.pdf]
Example verdicts and evaluation figures are computed/read at build time, so the report matches the code you ship."""
import argparse, json, os
from xml.sax.saxutils import escape
from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import HRFlowable, Image, KeepTogether, ListFlowable, ListItem, Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle

from aurel.engine import analyze

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ROYAL, GOLD, INK, MUTE = colors.HexColor("#1d3fb8"), colors.HexColor("#c9a24a"), colors.HexColor("#14171c"), colors.HexColor("#5a6475")
ap = argparse.ArgumentParser()
ap.add_argument("--repo", default="https://github.com/YOUR-USERNAME/aurel")
ap.add_argument("--author", default="")
ap.add_argument("--out", default="AUREL_Project_Report.pdf")
args = ap.parse_args()

ss = getSampleStyleSheet()
BODY = ParagraphStyle("b", parent=ss["Normal"], fontName="Helvetica", fontSize=10, leading=14.5, textColor=INK, spaceAfter=6)
H1 = ParagraphStyle("h1", parent=BODY, keepWithNext=1, fontName="Helvetica-Bold", fontSize=15, leading=19, textColor=ROYAL, spaceBefore=14, spaceAfter=4)
H2 = ParagraphStyle("h2", parent=BODY, keepWithNext=1, fontName="Helvetica-Bold", fontSize=11, leading=15, textColor=INK, spaceBefore=8, spaceAfter=3)
CELL = ParagraphStyle("c", parent=BODY, fontSize=8.6, leading=11, spaceAfter=0)
CELLH = ParagraphStyle("ch", parent=CELL, fontName="Helvetica-Bold", textColor=colors.white)
NOTE = ParagraphStyle("n", parent=BODY, fontSize=8.8, leading=12, textColor=MUTE)
P = lambda t, s=BODY: Paragraph(t, s)


def section(num, title):
    return [P(f"{num}. {title}", H1), HRFlowable(width="100%", thickness=1.2, color=GOLD, spaceAfter=6)]


def bullets(items):
    return ListFlowable([ListItem(P(i), leftIndent=12) for i in items], bulletType="bullet", bulletColor=ROYAL, leftIndent=14, bulletFontSize=9)


def table(rows, widths, header=True):
    data = [[P(c, CELLH if header and r == 0 else CELL) for c in row] for r, row in enumerate(rows)]
    t = Table(data, colWidths=[w * mm for w in widths], repeatRows=1 if header else 0)
    st = [("VALIGN", (0, 0), (-1, -1), "TOP"), ("GRID", (0, 0), (-1, -1), .4, colors.HexColor("#c9cfda")),
          ("TOPPADDING", (0, 0), (-1, -1), 4), ("BOTTOMPADDING", (0, 0), (-1, -1), 4), ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f3f5f9")])]
    if header:
        st.append(("BACKGROUND", (0, 0), (-1, 0), ROYAL))
    t.setStyle(TableStyle(st))
    return t


def footer(c, d):
    c.saveState(); c.setFont("Helvetica", 8); c.setFillColor(MUTE)
    c.drawString(20 * mm, 11 * mm, "AUREL - Adaptive URL & Risk Evaluation Layer | Project Report"); c.drawRightString(190 * mm, 11 * mm, f"Page {d.page}")
    c.setStrokeColor(GOLD); c.setLineWidth(.8); c.line(20 * mm, 15 * mm, 190 * mm, 15 * mm); c.restoreState()


# ---- live data ----
EXAMPLES = [("https://www.wikipedia.org/wiki/Phishing", "Ordinary legitimate page"), ("https://accounts.google.com/signin", "Legitimate login page (keywords, real brand domain)"),
            ("https://paypa1.com/login", "Leetspeak look-alike of a brand"), ("http://paypa1-secure-login.verify-account.xyz/update", "Brand + keywords + risky TLD, no HTTPS"),
            ("http://185.4.9.2/login", "Raw IP address host"), ("http://3232235777/secure/login", "Obfuscated (decimal) IP address"),
            ("https://xn--pple-43d.com/signin", "Punycode look-alike domain"), ("http://bit.ly/verify-account", "URL shortener hiding the destination")]
rows = [["URL", "What it demonstrates", "Verdict", "Score", "Main reasons"]]
for u, why in EXAMPLES:
    r = analyze(u, online=False, use_feeds=False)
    rows.append([escape(u), why, r["verdict"], str(r["score"]), escape("; ".join(f["indicator"] for f in r["findings"][:2]) or "none found")])
try:
    ev = json.load(open(os.path.join(ROOT, "docs", "evaluation.json")))
except Exception:
    ev = None

doc = SimpleDocTemplate(args.out, pagesize=A4, leftMargin=20 * mm, rightMargin=20 * mm, topMargin=18 * mm, bottomMargin=22 * mm, title="AUREL Project Report", author=args.author or "AUREL")
s = []
emb = os.path.join(ROOT, "docs", "emblem.png")
if os.path.exists(emb):
    im = Image(emb, width=26 * mm, height=27.6 * mm); im.hAlign = "CENTER"; s += [im, Spacer(1, 4)]
s += [P("AUREL", ParagraphStyle("t", parent=BODY, fontName="Helvetica-Bold", fontSize=30, leading=34, alignment=TA_CENTER, textColor=ROYAL, spaceAfter=0)),
      P("Adaptive URL &amp; Risk Evaluation Layer", ParagraphStyle("t2", parent=BODY, fontSize=13, alignment=TA_CENTER, textColor=INK, spaceAfter=2)),
      P("Intelligent Digital Risk Detection &amp; Protection System", ParagraphStyle("t3", parent=BODY, fontSize=10, alignment=TA_CENTER, textColor=MUTE, spaceAfter=2))]
if args.author:
    s.append(P(f"Prepared by: {escape(args.author)}", ParagraphStyle("t4", parent=BODY, alignment=TA_CENTER, textColor=MUTE)))

s += section(1, "Project Title") + [P("<b>AUREL: Adaptive URL &amp; Risk Evaluation Layer</b> - a local-first phishing and malicious-link analysis system with a web application and a Chrome browser extension.")]

s += section(2, "Summary") + [
    P("AUREL is a cybersecurity application that helps people recognise suspicious websites before they interact with them. Users paste a link, upload or scan a QR code, or submit a list of links; "
      "a multi-layer detection engine written in Python analyses the address and returns a risk score, a verdict (Low Risk, Suspicious or High Risk), the evidence behind it, a confidence level and a list of checks that could not be completed."),
    P("A companion Chrome extension uses the same engine to monitor the websites a user visits while the browser is open, raising badges, notifications and a warning page for dangerous destinations. "
      "Everything runs on the user's own computer: AUREL reads the URL only, never visits it, and keeps scan history in a local database.")]

s += section(3, "Objective") + [bullets([
    "Build a tool that helps users judge whether a link is suspicious <b>before</b> opening it.",
    "Explain every verdict: show which indicators fired, how strongly, why, and which checks could not run, instead of a bare safe/unsafe label.",
    "Combine several independent detection layers (URL structure, hostname, brand impersonation, domain reputation, redirects, threat intelligence, machine learning) so no single weak heuristic decides the outcome.",
    "Protect users continuously inside the browser while keeping their data private and local.",
    "Be honest about limits: never claim 100% accuracy and never claim a website is safe merely because no threat was found."])]

s += section(4, "Tools &amp; Technology") + [table([
    ["Technology", "Purpose in AUREL"],
    ["Python 3", "Detection engine, risk scoring, ML signal, backend logic and test tooling"],
    ["Flask", "Local API and web server connecting the interface and extension to the engine (bound to 127.0.0.1)"],
    ["SQLite", "Private, local storage for scan history and user feedback"],
    ["HTML, CSS, JavaScript", "Web application interface, live scan progress, charts, opening animation and reports"],
    ["SVG", "Custom shield emblem, animated logo and line icons"],
    ["Chrome Extension (Manifest V3)", "Background URL monitoring, popup, notifications, context menu and warning page"],
    ["OpenCV", "Decoding QR codes from uploaded images (camera scanning uses the browser's detector when available)"],
    ["Threat-intelligence sources (optional)", "Local OpenPhish/URLhaus feed, Google Safe Browsing, URLhaus API and RDAP domain-age lookup"],
    ["unittest, Git &amp; GitHub", "32 automated tests; version control and code hosting"]], [52, 118])]

s += section(5, "Concepts Used") + [
    table([["Concept", "How it is applied"],
           ["Heuristic URL analysis", "Length, subdomain depth, unusual ports and characters, suspicious wording, missing HTTPS (without treating HTTPS as proof of legitimacy)"],
           ["Typosquatting and leetspeak", "Edit-distance comparison and character substitution (for example paypa1 vs paypal) against about 40 well-known brands and their real domains"],
           ["Homograph and Punycode detection", "Unicode script analysis finds look-alike letters from other alphabets (for example a Cyrillic letter inside a Latin name)"],
           ["Shannon entropy", "Measures how random a domain name looks, to flag generated domains"],
           ["IP obfuscation detection", "Recognises raw, decimal, hexadecimal, octal and malformed IP-style hostnames"],
           ["Weighted, grouped risk scoring", "Related indicators are grouped, the strongest counts fully and the rest partially, with per-group caps so one cause is not counted repeatedly"],
           ["Threat intelligence", "Confirmed matches in a feed or API outweigh every heuristic and force a High Risk result"],
           ["Explainable machine learning", "A logistic-regression model adds a probability and lists which features pushed it up or down; it can raise a score but never lower it"],
           ["SSRF and safe analysis", "Submitted URLs are never fetched; the only URL-linked contact is an opt-in, header-only shortener lookup restricted to known shortener hosts on public IPs"],
           ["Privacy by design", "Local-first processing, opt-in and disclosed online checks, extension logs only flagged pages, API keys kept in environment variables"],
           ["Event-driven extension design", "Manifest V3 service worker keeps state in browser storage so it survives suspension and restarts"]], [48, 122])]

s += section(6, "Functionality") + [P("Web application", H2), bullets([
    "<b>Scan:</b> validates and normalises a URL, then shows live analysis stages, risk score, verdict, confidence, findings and recommendations.",
    "<b>QR Scan:</b> upload an image or use the camera; the embedded link is extracted and analysed, and is never opened automatically.",
    "<b>Bulk Scan:</b> up to 50 URLs pasted or loaded from a .txt/.csv file, results table, individual reports and CSV export.",
    "<b>Dashboard:</b> totals, risk distribution, 7-day activity, recent scans and most common indicators from real scan data.",
    "<b>History:</b> locally stored scans with search and verdict filter; reopen any report; compare earlier scans of the same domain.",
    "<b>Reports:</b> reasoning panel (passed, flagged, not run, not performed by design), evidence per finding, PDF export and false-positive / missed-threat feedback."]),
    P("Browser extension", H2), bullets([
    "Automatically checks each visited page URL while the browser is running and the extension is enabled, even when the popup is closed.",
    "Shows a badge for Suspicious and High Risk pages and a notification for High Risk sites.",
    "Displays a warning page, with an option to return to safety, for high-confidence threats.",
    "Popup shows the current URL, verdict and key indicators, a View details button and a manual link scanner; right-click any link to check it first.",
    "Handles an offline service, browser restarts and worker suspension gracefully. It is browser-level protection, not a device firewall."])]

s += section(7, "Detailed Description") + [
    P("Architecture", H2),
    P("The web application and the extension both call one Flask API on the user's computer, which runs a single Python function, <i>analyze()</i>, so a link receives the same assessment everywhere. Results are stored in SQLite. "
      "The server accepts only localhost Host headers and local or extension Origins, limits input sizes and sets security headers."),
    P("Detection pipeline", H2),
    table([["Stage", "What it checks"],
           ["1. URL validation", "Format, length, unsupported schemes (javascript:, data: and others), control characters; adds http:// when the scheme is missing"],
           ["2. URL structure", "Length, subdomains, ports, unusual characters, percent-encoding, suspicious keywords"],
           ["3. Hostname and homographs", "IP forms, the @ trick, Punycode, mixed-script look-alikes"],
           ["4. Brand impersonation", "Typosquatting, leetspeak and brand names under unrelated registered domains"],
           ["5. Domain reputation", "Randomness, hyphens, digits, TLD tiers and optional domain age"],
           ["6. Redirect analysis", "Redirect parameters, embedded URLs, shorteners (optional safe resolution)"],
           ["7. Threat intelligence", "Local feed and optional APIs; confirmed matches override heuristics"],
           ["8. ML model and risk engine", "ML probability, grouped scoring, thresholds (0-29 Low, 30-59 Suspicious, 60+ High), confidence and recommendations"]], [48, 122]),
    Spacer(1, 6),
    P("Result transparency", H2),
    P("Every report lists the evidence for each finding, its severity and counted impact, a confidence level (High only when a threat-intelligence source confirms the result), the checks that completed, the checks that could not run "
      "(for example when no API key is configured) and checks that are deliberately not performed, such as certificate inspection and page-content analysis, because they would require visiting the submitted site."),
    P("Interface and identity", H2),
    P("The interface uses a dark charcoal base with royal blue, silver and restrained gold accents, with yellow and red reserved for warnings and danger. The emblem is a metallic shield crossed by a large letter A; an opening animation assembles the shattered shield, "
      "forms the A, reveals the wordmark and settles the logo into the sidebar, with a reduced-motion option. The same emblem appears in the web app, extension and reports.")]

s += section(8, "Result &amp; Conclusion") + [P("Example results", H2),
    P("The following verdicts were produced by running the engine (offline, rules and ML) on sample links when this report was generated."),
    table(rows, [41, 33, 19, 15, 62]), Spacer(1, 6), P("Testing", H2),
    bullets(["32 automated tests pass. They cover input validation, every detection layer, scoring rules, threat-intelligence handling, API security checks and QR extraction.",
             "Safety tests confirm that offline analysis makes no network calls and that the shortener resolver refuses loopback and private addresses and never contacts the final destination."])]
if ev:
    r, f = ev["rules_only"], ev["full_engine"]
    fmt = lambda v: "n/a" if v is None else f"{v:.3f}"
    s += [P("Evaluation on a small labelled sample", H2),
          table([["Configuration", "URLs", "Precision", "Recall", "False-positive rate", "False-negative rate"],
                 ["Rules only", str(r["n"]), fmt(r["precision"]), fmt(r["recall"]), fmt(r["false_positive_rate"]), fmt(r["false_negative_rate"])],
                 ["Full engine (rules + ML)", str(f["n"]), fmt(f["precision"]), fmt(f["recall"]), fmt(f["false_positive_rate"]), fmt(f["false_negative_rate"])]], [44, 16, 24, 20, 34, 32]),
          P("<b>Important:</b> this 76-URL sample was written by the author alongside the detection rules, and the bundled ML model is trained on synthetic data. These figures are therefore optimistic and are not evidence of real-world accuracy. "
            "The project includes tools to download public datasets (Tranco for legitimate sites, OpenPhish for phishing), retrain the model and measure precision, recall and false-positive and false-negative rates on unseen data.", NOTE)]
s += [P("Conclusion", H2),
      P("AUREL demonstrates that phishing detection can be both useful and transparent: it combines independent checks, explains its reasoning, reports what it could not verify, and keeps user data on the user's device. "
        "Its main limitations are that it analyses URLs only (so a harmful page on a clean-looking domain may be missed and an unusual legitimate site may be flagged), it needs the local service and an open browser, "
        "and the warning page may appear after a page has started loading. A low score never means a website is safe."),
      P("<b>Future scope:</b> evaluation on large real datasets, Firefox and Edge support, user-feedback-driven retraining, caching of domain-age lookups, and optional page-content signals with explicit user consent.")]

s += section(9, "Use Cases") + [bullets([
    "<b>Everyday users:</b> check a link received by email, SMS or messaging apps before clicking it.",
    "<b>QR code safety:</b> scan codes on posters, parking meters, menus or payment prompts and see where they lead before opening them.",
    "<b>Students and employees:</b> learn why a link is suspicious through the evidence and reasoning panel; useful for security-awareness training.",
    "<b>Security and IT teams:</b> triage lists of reported URLs in bulk and export the results to CSV.",
    "<b>Continuous protection:</b> the browser extension warns while browsing, without sending browsing data to any cloud service.",
    "<b>Research and teaching:</b> an inspectable, testable engine for studying phishing indicators and measuring detection accuracy."])]

s += section(10, "GitHub Repository") + [P(f'Source code: <link href="{escape(args.repo)}" color="#1d3fb8"><u>{escape(args.repo)}</u></link>'),
      P("The repository contains the detection engine, web application, Chrome extension, tests, tooling and documentation (README, architecture and testing guides).", NOTE)]

doc.build(s, onFirstPage=footer, onLaterPages=footer)
print("Wrote", args.out)
