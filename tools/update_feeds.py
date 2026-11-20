"""Download public threat feeds into data/blocklist.txt (used for offline confirmed-threat matching).
    python -m tools.update_feeds
Sources: OpenPhish community feed and URLhaus online URLs. Check each provider's terms and rate limits.
Feeds are lists of known-bad URLs; AUREL only compares your scans against them, nothing is visited."""
import os, urllib.request
from datetime import datetime, timezone

OUT = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "data", "blocklist.txt")
FEEDS = {"OpenPhish": "https://openphish.com/feed.txt", "URLhaus": "https://urlhaus.abuse.ch/downloads/text_online/"}

lines, ok = [], 0
for name, url in FEEDS.items():
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "AUREL/1.0"})
        with urllib.request.urlopen(req, timeout=30) as r:
            got = [l.strip() for l in r.read().decode("utf-8", "ignore").splitlines() if l.strip() and not l.startswith("#")]
        lines += got; ok += 1
        print(f"{name}: {len(got)} entries")
    except Exception as e:
        print(f"{name}: failed ({type(e).__name__}: {e})")
if ok:
    os.makedirs(os.path.dirname(OUT), exist_ok=True)
    with open(OUT, "w") as f:
        f.write(f"# AUREL local threat feed, updated {datetime.now(timezone.utc).isoformat(timespec='seconds')}\n")
        f.write("\n".join(sorted(set(lines))) + "\n")
    print("Wrote", OUT)
else:
    print("No feed could be downloaded; the existing blocklist (if any) was left unchanged.")
