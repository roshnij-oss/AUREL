"""Train the ML signal.  Run from the repo root:  python -m tools.train_model [--csv data/train.csv]
  python -m tools.train_model            -> demo model on synthetic URLs
                         python -m tools.train_model --csv data/urls.csv   -> real data (columns: url,label; 1=phishing)
Real sources: Tranco list (legitimate) + OpenPhish/PhishTank feeds (phishing)."""
import csv, json, random, sys
from aurel.engine import analyze
from aurel import ml

random.seed(7)
GOOD = ["wikipedia.org", "github.com", "bbc.co.uk", "amazon.in", "google.com", "microsoft.com", "python.org", "nytimes.com", "flipkart.com",
        "stackoverflow.com", "linkedin.com", "apple.com", "paypal.com", "icicibank.com", "hdfcbank.com", "irctc.co.in", "mozilla.org", "dropbox.com"]
PATHS = ["", "/", "/about", "/products/item-42", "/docs/getting-started", "/news/2026/tech", "/search?q=laptops&page=2", "/account/login", "/signin", "/help/contact", "/user/settings"]
BRANDS = ["paypal", "google", "microsoft", "apple", "amazon", "netflix", "sbi", "hdfc", "icici", "paytm", "facebook", "instagram"]
WORDS = ["secure", "login", "verify", "update", "account", "billing", "support", "confirm", "wallet", "unlock", "kyc"]
TLDS = ["xyz", "top", "tk", "click", "work", "ml", "support", "cf"]
R = random.choice


def good():
    d = R(GOOD); sub = R(["", "www.", "accounts.", "mail.", "docs.", "support."])
    return f"{'https' if random.random() < .95 else 'http'}://{sub}{d}{R(PATHS)}"


def bad():
    b, w1, w2, t = R(BRANDS), R(WORDS), R(WORDS), R(TLDS); k = random.randint(0, 5)
    if k == 0: return f"http://{b}-{w1}-{w2}.{t}/{w1}"
    if k == 1: return f"http://{random.randint(11,223)}.{random.randint(1,254)}.{random.randint(1,254)}.{random.randint(1,254)}/{b}/{w1}.php"
    if k == 2: return f"https://{b}.com.{w1}.{w2}-portal.{t}/signin?session={random.getrandbits(48):x}"
    if k == 3: return f"https://{w1}.{w2}.{b}.{random.choice(['web','online','id'])}.{t}/{w1}/{w2}"
    if k == 4: return f"http://{b.replace('o','0').replace('l','1')}{random.randint(1,99)}.{t}/{w1}-{w2}"
    return f"https://secure-{b}@{random.randint(100000,999999)}-{w1}.{t}/verify"


def load():
    if "--csv" in sys.argv:
        rows = list(csv.DictReader(open(sys.argv[sys.argv.index("--csv") + 1])))
        return [(r["url"], int(r["label"])) for r in rows]
    return [(good(), 0) for _ in range(700)] + [(bad(), 1) for _ in range(700)]


data = load(); random.shuffle(data)
cut = int(len(data) * .8)
feats = lambda rows: ([ml.vector(r["url"], r["findings"]) for r in [{"url": u, "findings": analyze(u, online=False, use_ml=False, use_feeds=False).get("findings", [])} for u, _ in rows]], [l for _, l in rows])
Xtr, ytr = feats(data[:cut]); Xte, yte = feats(data[cut:])
w, b = ml.train(Xtr, ytr)
pred = [1 if b + sum(a * c for a, c in zip(w, x)) > 0 else 0 for x in Xte]
tp = sum(p and y for p, y in zip(pred, yte)); fp = sum(p and not y for p, y in zip(pred, yte)); fn = sum((not p) and y for p, y in zip(pred, yte))
fpr = fp / max(sum(1 for y in yte if not y), 1)
print(f"held-out n={len(yte)} false-positive-rate={fpr:.3f} accuracy={sum(p==y for p,y in zip(pred,yte))/len(yte):.3f} precision={tp/max(tp+fp,1):.3f} recall={tp/max(tp+fn,1):.3f}")
json.dump({"weights": w, "bias": b, "names": ml.NAMES}, open(ml.MODEL, "w"), indent=1)
print("saved", ml.MODEL)
