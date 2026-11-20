"""Build labelled train/test sets from public sources.  python -m tools.fetch_datasets [--n 5000]
Legitimate: Tranco top sites (https://tranco-list.eu). Malicious: OpenPhish feed.
Writes data/train.csv and data/test.csv (80/20). Then:
    python -m tools.train_model --csv data/train.csv
    python -m tools.evaluate data/test.csv
CAVEAT: Tranco lists domains only, so legitimate URLs here get synthetic paths. This introduces dataset bias; read docs/TESTING.md."""
import csv, io, os, random, sys, urllib.request, zipfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
N = int(sys.argv[sys.argv.index("--n") + 1]) if "--n" in sys.argv else 5000
PATHS = ["", "/", "/about", "/login", "/signin", "/account", "/help", "/products", "/news/2026", "/search?q=test", "/docs/start", "/user/settings", "/support/contact"]
get = lambda u: urllib.request.urlopen(urllib.request.Request(u, headers={"User-Agent": "AUREL/1.0"}), timeout=60).read()
random.seed(11)
try:
    z = zipfile.ZipFile(io.BytesIO(get("https://tranco-list.eu/top-1m.csv.zip")))
    domains = [l.split(",")[1] for l in z.read(z.namelist()[0]).decode().splitlines()[:N]]
    phish = [l.strip() for l in get("https://openphish.com/feed.txt").decode().splitlines() if l.strip()][:N]
except Exception as e:
    sys.exit(f"Download failed ({type(e).__name__}: {e}). Check your connection and try again.")
legit = [f"https://{random.choice(['', 'www.'])}{d}{random.choice(PATHS)}" for d in domains[: len(phish)]]
rows = [(u, 0) for u in legit] + [(u, 1) for u in phish]
random.shuffle(rows); cut = int(len(rows) * .8)
for name, part in (("train", rows[:cut]), ("test", rows[cut:])):
    with open(os.path.join(ROOT, "data", f"{name}.csv"), "w", newline="") as f:
        w = csv.writer(f); w.writerow(["url", "label"]); w.writerows(part)
print(f"train={cut} test={len(rows) - cut} (legit={len(legit)}, phishing={len(phish)})")
