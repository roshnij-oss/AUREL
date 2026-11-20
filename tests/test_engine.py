import csv, os, socket, tempfile, unittest, urllib.error, urllib.request
from unittest import mock
from aurel import engine
from aurel.engine import analyze

a = lambda u, **k: analyze(u, online=False, use_ml=False, use_feeds=False, **k)
names = lambda r: [f["indicator"] for f in r["findings"]]


class Validation(unittest.TestCase):
    def test_rejects_bad_input(self):
        for bad in ["", "   ", None, 5, "not a url", "javascript:alert(1)", "data:text/html,x", "ftp://example.com", "http://", "a" * 3000, "http://exa mple.com", "http://x\x00.com"]:
            self.assertFalse(a(bad)["valid"], bad)
            self.assertTrue(a(bad)["error"])

    def test_normalises_and_extracts_parts(self):
        r = a("Example.com/login")
        self.assertTrue(r["normalised"]); self.assertEqual(r["scheme"], "http")
        r = a("https://mail.sub.example.co.uk:8443/x")
        self.assertEqual((r["registered_domain"], r["subdomain"], r["tld"]), ("example.co.uk", "mail.sub", "co.uk"))
        self.assertIn("Non-standard port", names(r))


class Detection(unittest.TestCase):
    def test_ip_forms(self):
        self.assertIn("IP address as host", names(a("http://185.4.9.2/")))
        self.assertIn("IP address obfuscation", names(a("http://3232235777/")))
        self.assertIn("IP address obfuscation", names(a("http://0xC0A80001/")))
        self.assertIn("Malformed IP-like hostname", names(a("http://999.1.1.1/")))
        self.assertIn("Malformed IP-like hostname", names(a("http://1.2.3.4.5/")))

    def test_homograph_and_punycode(self):
        r = a("https://аpple.com")                        # Cyrillic 'а'
        self.assertIn("Homograph risk (mixed scripts)", names(r)); self.assertIn("Possible impersonation of 'apple'", names(r))
        self.assertIn("Punycode domain", names(a("https://xn--pple-43d.com")))

    def test_typosquat_leet_brand(self):
        for u in ["https://paypa1.com/login", "https://gooogle.com", "https://g00gle-help.top", "http://amazon.com.verify-account.top/", "https://secure-paypal-login.net"]:
            self.assertTrue(any(n.startswith("Possible impersonation") for n in names(a(u))), u)

    def test_legitimate_brand_domains_not_flagged(self):
        for u in ["https://www.paypal.com/signin", "https://accounts.google.com/signin", "https://login.microsoftonline.com/", "https://applebees.com", "https://www.amazon.co.uk/", "https://aws.amazon.com/", "https://docs.github.com"]:
            self.assertFalse(any(n.startswith("Possible impersonation") for n in names(a(u))), u)
            self.assertEqual(a(u)["level"], "low", u)

    def test_entropy_and_tld(self):
        self.assertIn("Random-looking domain name", names(a("https://xk2jd8qp3vz9wq.top")))
        self.assertTrue(any(n.startswith("Frequently abused TLD") for n in names(a("https://example.xyz"))))

    def test_https_is_not_proof(self):
        r = a("https://paypal-secure-login.verify-account.xyz/update")
        self.assertNotEqual(r["level"], "low")
        self.assertIn("does not prove", [c for c in r["checks"] if c["name"] == "HTTPS"][0]["detail"])

    def test_redirects(self):
        self.assertIn("Redirect parameter to another site", names(a("https://example.com/go?next=http://other-site.top/x")))
        self.assertIn("Embedded URL in path", names(a("https://example.com/http://evil.top/")))
        self.assertIn("URL shortener", names(a("https://bit.ly/abc")))


class Scoring(unittest.TestCase):
    def test_related_indicators_not_double_counted(self):
        r = a("http://paypal-secure-login-verify-account-update.xyz/signin/verify/confirm/password")
        self.assertLessEqual(r["score"], 100)
        self.assertAlmostEqual(sum(f["impact"] for f in r["findings"]), r["rule_score"], delta=3)
        self.assertEqual(r["findings"][0]["impact"], max(f["impact"] for f in r["findings"]))

    def test_every_finding_is_explained(self):
        for f in a("http://paypa1-secure-login.verify-account.xyz/update")["findings"]:
            self.assertTrue(f["explanation"] and f["evidence"] and f["severity"] in ("info", "caution", "danger"))

    def test_ml_never_lowers_rules(self):
        r = analyze("http://185.4.9.2/login", use_feeds=False)
        self.assertGreaterEqual(r["score"], r["rule_score"])

    def test_verdicts_and_confidence(self):
        self.assertEqual(a("https://www.wikipedia.org")["verdict"], "Low Risk")
        self.assertEqual(a("http://paypa1-secure-login.verify-account.xyz/update")["verdict"], "High Risk")
        self.assertIn(a("https://example.com")["confidence"]["level"], ("Limited", "Low"))   # never 'High' on heuristics alone
        self.assertTrue(a("https://www.wikipedia.org")["verdict_note"])

    def test_reports_unavailable_checks(self):
        r = a("https://example.com")
        self.assertIn("Threat-intelligence APIs", r["incomplete"]); self.assertIn("Local threat feed", r["incomplete"])
        self.assertEqual({d["name"] for d in r["by_design"]}, {"Certificate inspection", "Page content analysis"})


class ThreatIntel(unittest.TestCase):
    def test_local_feed_confirms_threat(self):
        with tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False) as f:
            f.write("# feed\nhttp://bad-example.top/phish/login\nevil-domain.example\n")
        try:
            with mock.patch.object(engine, "BLOCKLIST_PATH", f.name):
                engine._feed.update(mtime=None)
                r = analyze("http://bad-example.top/phish/login", use_ml=False)
                self.assertEqual((r["score"], r["level"], r["confidence"]["level"]), (100, "high", "High"))
                self.assertEqual(analyze("https://sub.evil-domain.example/", use_ml=False)["score"], 100)
                self.assertNotEqual(analyze("http://bad-example.top/other", use_ml=False)["score"], 100)   # exact URL, not whole host
                self.assertEqual(analyze("http://bad-example.top/phish/login", use_ml=False, use_feeds=False)["score"] < 100, True)
        finally:
            os.unlink(f.name); engine._feed.update(mtime=None)

    def test_domain_age_online(self):
        with mock.patch.object(engine, "domain_age_days", return_value=5):
            r = analyze("https://example-new.com", online=True, use_ml=False, use_feeds=False)
            self.assertIn("Very new domain", names(r)); self.assertEqual(r["domain_age_days"], 5)

    def test_api_failure_is_reported_not_fatal(self):
        with mock.patch.dict(os.environ, {"GSB_API_KEY": "x"}), mock.patch("urllib.request.urlopen", side_effect=TimeoutError()):
            r = analyze("https://example.com", online=True, use_ml=False, use_feeds=False)
            self.assertTrue(r["valid"]); self.assertIn("Threat-intelligence APIs", r["incomplete"])


class Safety(unittest.TestCase):
    def test_offline_analysis_never_touches_network(self):
        boom = mock.Mock(side_effect=AssertionError("network used"))
        with mock.patch("urllib.request.urlopen", boom), mock.patch("socket.getaddrinfo", boom), mock.patch("socket.socket", boom):
            for u in ["http://evil.top/go?next=http://a.top", "https://bit.ly/x", "http://185.4.9.2/"]:
                self.assertTrue(analyze(u, online=False)["valid"])

    def test_shortener_resolver_ssrf_guards(self):
        opener = mock.Mock(side_effect=AssertionError("must not connect"))
        with mock.patch("urllib.request.build_opener", opener):
            self.assertEqual(engine.resolve_shortener("http://169.254.169.254/latest")[0], ["http://169.254.169.254/latest"])      # not a shortener
            self.assertEqual(len(engine.resolve_shortener("http://localhost:8080/")[0]), 1)
            with mock.patch("socket.getaddrinfo", return_value=[(2, 1, 6, "", ("127.0.0.1", 443))]):                                 # shortener resolving to loopback
                self.assertEqual(len(engine.resolve_shortener("https://bit.ly/x")[0]), 1)

    def test_shortener_chain_reads_header_without_visiting_destination(self):
        calls = []
        def fake_open(req, timeout=0):
            calls.append(req.full_url)
            raise urllib.error.HTTPError(req.full_url, 301, "", {"Location": "https://evil-destination.top/login"}, None)
        with mock.patch("socket.getaddrinfo", return_value=[(2, 1, 6, "", ("93.184.216.34", 443))]), \
             mock.patch("urllib.request.build_opener", return_value=mock.Mock(open=fake_open)):
            chain, err = engine.resolve_shortener("https://bit.ly/abc")
        self.assertEqual(chain[-1], "https://evil-destination.top/login"); self.assertEqual(len(calls), 1)   # destination never contacted


class Dataset(unittest.TestCase):
    def test_sample_dataset_metrics(self):
        with open(os.path.join(os.path.dirname(__file__), "..", "data", "sample_labelled.csv"), encoding="utf-8") as fh:
            rows = list(csv.DictReader(fh))
        tp = fp = tn = fn = 0
        for r in rows:
            flagged, bad = a(r["url"])["level"] != "low", r["label"] == "1"
            tp += flagged and bad; fp += flagged and not bad; tn += (not flagged) and (not bad); fn += (not flagged) and bad
        print(f"\n  sample set n={len(rows)} precision={tp/max(tp+fp,1):.2f} recall={tp/max(tp+fn,1):.2f} FPR={fp/max(fp+tn,1):.2f} FNR={fn/max(fn+tp,1):.2f}")
        self.assertLessEqual(fp / (fp + tn), 0.10); self.assertGreaterEqual(tp / (tp + fn), 0.85)


if __name__ == "__main__":
    unittest.main()
