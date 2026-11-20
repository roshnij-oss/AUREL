"""Measure AUREL on a labelled CSV (columns: url,label; 1 = phishing).  python -m tools.evaluate data/test.csv
Reports rules-only and full-engine metrics. Suspicious and High Risk count as 'flagged'. Local threat feeds are
disabled so results reflect detection logic, not list look-ups. Use data the ML model was NOT trained on."""
import csv, json, os, sys
from aurel.engine import analyze


def metrics(rows, **kw):
    tp = fp = tn = fn = skipped = 0
    for r in rows:
        res = analyze(r["url"], online=False, use_feeds=False, **kw)
        if not res["valid"]:
            skipped += 1
            continue
        flagged, bad = res["level"] != "low", int(r["label"]) == 1
        tp += flagged and bad; fp += flagged and not bad; tn += (not flagged) and (not bad); fn += (not flagged) and bad
    div = lambda a, b: round(a / b, 3) if b else None
    return {"n": tp + fp + tn + fn, "skipped_invalid": skipped, "tp": tp, "fp": fp, "tn": tn, "fn": fn, "precision": div(tp, tp + fp),
            "recall": div(tp, tp + fn), "false_positive_rate": div(fp, fp + tn), "false_negative_rate": div(fn, fn + tp)}


if __name__ == "__main__":
    rows = list(csv.DictReader(open(sys.argv[1])))
    out = {"dataset": sys.argv[1], "rules_only": metrics(rows, use_ml=False), "full_engine": metrics(rows, use_ml=True)}
    print(json.dumps(out, indent=1))
    json.dump(out, open(os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "docs", "evaluation.json"), "w"), indent=1)
