# Testing

## Automated (32 tests, no network required)
`python -m unittest discover -s tests -t .`
- Validation and normalisation; hostname/domain/TLD extraction.
- Each detection layer, including IP obfuscation, homographs, typosquatting, leetspeak, entropy, redirects.
- Legitimate brand domains are not flagged; HTTPS is not treated as proof of legitimacy.
- Scoring: no double counting, impacts reconcile with the score, ML never lowers rule scores, confidence is never "High" on heuristics alone.
- Threat intel: local feed (exact URL vs host entries), domain-age and API-failure handling.
- Safety: offline analysis performs **zero** network calls; the shortener resolver refuses non-shorteners, loopback and private addresses, and never contacts the destination.
- API: Host/Origin guards, headers, upload limit, bulk limits, real stage streaming, extension stores only flagged pages, history search with literal `%`, feedback validation, QR extraction (image-to-verdict) and non-URL QR payloads.

## Dataset evaluation
`data/sample_labelled.csv` (76 URLs) was written by hand alongside the rules, so its scores (precision 1.00, recall 0.95-0.98, FPR 0.00) are **optimistic and not evidence of real-world accuracy**. For a defensible result:
1. `python -m tools.fetch_datasets` then `python -m tools.train_model --csv data/train.csv`
2. `python -m tools.evaluate data/test.csv` (reports rules-only and full engine, writes `docs/evaluation.json`).
Quote precision, recall, false-positive and false-negative rates from that run. Known bias: Tranco has domains only, so legitimate URLs get synthetic paths; phishing feeds skew to certain kinds of campaigns. Say so in your presentation.

## Manual checklist (not automatable here)
- [ ] Opening animation plays; shards assemble, A forms, U-R-E-L appear, logo settles into the sidebar; click or any key skips it; "Opening animation: off" and OS reduced-motion both skip it.
- [ ] Scan shows real stage progress; report, reasoning panel, PDF export (print dialog) and feedback buttons work.
- [ ] QR upload, QR camera (permission prompt; denied permission shows a clear message), "Open destination" asks for confirmation.
- [ ] Bulk paste and .csv upload, CSV export; History search and filter; Dashboard numbers match history.
- [ ] Extension: load unpacked; badge appears on suspicious pages; warning page on a high-confidence test URL; popup; View details; right-click "Check link"; stop the server and confirm the grey `?` badge and popup message; restart the browser.
