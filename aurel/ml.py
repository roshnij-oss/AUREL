"""Explainable ML signal: pure-Python logistic regression over URL features.
Each prediction reports per-feature contributions (weight x value, in log-odds)."""
import json, math, os
from urllib.parse import urlparse
from aurel.engine import KEYWORDS

MODEL = os.path.join(os.path.dirname(__file__), "model.json")
FLAGS = {"no_https": "No HTTPS", "ip_host": "IP address", "at_symbol": "@ symbol", "many_subdomains": "Excessive subdomains",
         "punycode": "Punycode", "risky_tld": "Frequently abused TLD", "shortener": "URL shortener",
         "brand_spoof": "Possible impersonation", "odd_port": "Non-standard port"}
LABELS = {"url_length": "URL length", "host_length": "Hostname length", "dots": "Number of dots", "hyphens": "Hyphens in hostname",
          "digit_ratio": "Digits in hostname", "host_entropy": "Hostname randomness", "path_depth": "Path depth",
          "query_params": "Query parameters", "keyword_hits": "Suspicious keywords",
          **{k: v for k, v in FLAGS.items()}}
NAMES = ["url_length", "host_length", "dots", "hyphens", "digit_ratio", "host_entropy", "path_depth", "query_params", "keyword_hits"] + list(FLAGS)


def entropy(s):
    return -sum((s.count(c) / len(s)) * math.log2(s.count(c) / len(s)) for c in set(s)) if s else 0.0


def vector(url, findings):
    p = urlparse(url); host = p.hostname or ""
    low = url.lower()
    names = [f["indicator"] for f in findings]
    num = [min(len(url) / 100, 2), min(len(host) / 50, 2), min(host.count(".") / 5, 2), min(host.count("-") / 3, 2),
           sum(c.isdigit() for c in host) / max(len(host), 1), entropy(host.replace(".", "")) / 4.5,
           min(len([x for x in p.path.split("/") if x]) / 5, 2), min(len(p.query.split("&")) / 5 if p.query else 0, 2),
           min(sum(k in low for k in KEYWORDS) / 4, 2)]
    flags = [1.0 if any(n.startswith(v) for n in names) else 0.0 for v in FLAGS.values()]
    return num + flags


def predict(url, findings):
    if not os.path.exists(MODEL):
        return None
    m = json.load(open(MODEL))
    x = vector(url, findings)
    contrib = [w * v for w, v in zip(m["weights"], x)]
    z = m["bias"] + sum(contrib)
    top = sorted(zip(NAMES, contrib), key=lambda t: -abs(t[1]))[:5]
    return {"probability": round(1 / (1 + math.exp(-z)), 3),
            "contributions": [{"label": LABELS[n], "value": round(c, 2)} for n, c in top if abs(c) > 0.05]}


def train(X, y, epochs=400, lr=0.3, l2=1e-3):
    w, b = [0.0] * len(X[0]), 0.0
    for _ in range(epochs):
        gw, gb = [0.0] * len(w), 0.0
        for xi, yi in zip(X, y):
            err = 1 / (1 + math.exp(-(b + sum(a * c for a, c in zip(w, xi))))) - yi
            gb += err
            for j, v in enumerate(xi):
                gw[j] += err * v
        n = len(X)
        w = [wj - lr * (g / n + l2 * wj) for wj, g in zip(w, gw)]
        b -= lr * gb / n
    return w, b
