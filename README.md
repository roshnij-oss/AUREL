# AUREL: Adaptive URL & Risk Evaluation Layer

Local-first phishing and malicious-link analysis. One Python detection engine powers the web app and the Chrome extension. AUREL reads the address only and **never visits a submitted URL**. Every verdict shows the evidence behind it and the checks that could not run.

## Quick start
```
python -m venv venv
venv\Scripts\activate            # Mac/Linux: source venv/bin/activate
pip install -r requirements.txt
python run.py                    # http://127.0.0.1:5000
```
Later runs: activate the venv, then `python run.py`.

## Chrome extension
`chrome://extensions` -> Developer mode -> Load unpacked -> select `extension/`. It needs AUREL running locally, the browser open and the extension enabled. It is browser-level protection only, not a firewall: it cannot see other apps or network traffic.

## Repository layout
```
aurel/        engine.py (detection) · ml.py · database.py (SQLite) · server.py (Flask API) · templates/ · static/
extension/    Manifest V3 extension (background worker, popup, warning page)
tools/        build_assets · train_model · evaluate · fetch_datasets · update_feeds
tests/        engine, API and dataset tests (standard library unittest)
data/         sample_labelled.csv (tiny sample); local DB and feeds are git-ignored
docs/         ARCHITECTURE.md · TESTING.md · PRESENTATION.md
```

## Threat intelligence (all optional)
- **Local feed:** `python -m tools.update_feeds` downloads OpenPhish and URLhaus lists for offline confirmed-threat matching.
- **APIs:** copy `.env.example` to `.env` and set `GSB_API_KEY` (Google Safe Browsing) and/or `URLHAUS_API_KEY`. Keys stay in environment variables, never in frontend code or Git. API checks run only when "Online checks" is ticked.

## Measure accuracy honestly
```
python -m tools.fetch_datasets                       # Tranco (legitimate) + OpenPhish (phishing) -> data/train.csv, data/test.csv
python -m tools.train_model --csv data/train.csv
python -m tools.evaluate data/test.csv               # precision, recall, false-positive and false-negative rates
python -m unittest discover -s tests -t .            # 32 tests
```
The bundled model is a **demo trained on synthetic data**; retrain on real data before quoting any numbers. AUREL never claims 100% accuracy, and a low score never means a site is safe.

## Privacy
History and feedback live in a local SQLite file (`data/aurel.db`). The extension logs only flagged pages. "Online checks" are opt-in and disclosed: the registered domain goes to rdap.org; the full URL goes to Google/URLhaus only if you set those keys; shortened links contact the shortener service only.

## Rebuild the logo assets
`python -m tools.build_assets` regenerates the emblem SVG, extension icons and the shared markup from one source.

## Put it on GitHub
```
git init && git add . && git commit -m "AUREL"
git branch -M main && git remote add origin <your-repo-url> && git push -u origin main
```
`.gitignore` already excludes `.env`, `venv/`, the database and downloaded feeds.
