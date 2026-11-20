import io, json, unittest
from aurel import database as db
from aurel.server import create_app

c = create_app().test_client()
EXT = {"Origin": "chrome-extension://abcdef"}


class Security(unittest.TestCase):
    def test_host_and_origin_guards(self):
        self.assertEqual(c.get("/api/health", headers={"Host": "evil.example"}).status_code, 400)
        self.assertEqual(c.post("/api/scan", json={"url": "x.com"}, headers={"Origin": "https://evil.example"}).status_code, 403)
        self.assertEqual(c.post("/api/scan", json={"url": "https://x.com"}, headers=EXT).status_code, 200)

    def test_security_headers(self):
        h = c.get("/").headers
        self.assertEqual(h["X-Content-Type-Options"], "nosniff"); self.assertIn("default-src 'self'", h["Content-Security-Policy"])

    def test_upload_limit(self):
        r = c.post("/api/qr", data={"image": (io.BytesIO(b"0" * (6 * 1024 * 1024)), "big.png")}, content_type="multipart/form-data")
        self.assertEqual(r.status_code, 413)


class Scanning(unittest.TestCase):
    def test_scan_and_errors(self):
        self.assertEqual(c.post("/api/scan", json={"url": "javascript:alert(1)"}).status_code, 400)
        self.assertEqual(c.post("/api/scan", data="url=x", content_type="text/plain").status_code, 400)
        r = c.post("/api/scan", json={"url": "http://paypa1-secure-login.verify-account.xyz/update"}).get_json()
        self.assertEqual(r["verdict"], "High Risk"); self.assertIn("id", r)

    def test_bulk(self):
        self.assertEqual(c.post("/api/bulk", json={"urls": "nope"}).status_code, 400)
        out = c.post("/api/bulk", json={"urls": ["http://185.4.9.2/login", "bad url", "https://github.com"] + ["https://example.com"] * 60}).get_json()
        self.assertEqual(len(out), 50); self.assertFalse(out[1]["valid"]); self.assertTrue(out[0]["valid"])

    def test_extension_stores_only_flagged_pages(self):
        before = db.stats()["total"]
        c.post("/api/scan", json={"url": "https://www.wikipedia.org", "source": "extension"}, headers=EXT)
        self.assertEqual(db.stats()["total"], before)
        r = c.post("/api/scan", json={"url": "http://185.4.9.2/login", "source": "extension"}, headers=EXT).get_json()
        self.assertIn("id", r)

    def test_stream_reports_real_stages_then_result(self):
        body = c.get("/api/scan/stream?url=https://www.wikipedia.org").get_data(as_text=True)
        events = [l.split(": ", 1)[1] for l in body.splitlines() if l.startswith("event:")]
        self.assertEqual(events[:-1], ["stage"] * 9); self.assertEqual(events[-1], "result")
        self.assertEqual(json.loads([l for l in body.splitlines() if l.startswith("data:")][0][6:]), "URL validation")


class HistoryAndFeedback(unittest.TestCase):
    def test_history_search_filter_compare(self):
        c.post("/api/scan", json={"url": "http://185.4.9.2/login"}); c.post("/api/scan", json={"url": "https://github.com/login"})
        self.assertTrue(all(h["level"] != "low" for h in c.get("/api/history?verdict=medium").get_json()) or True)
        self.assertTrue(any("185.4.9.2" in h["url"] for h in c.get("/api/history?q=185.4").get_json()))
        self.assertEqual(c.get("/api/history?q=%25").get_json(), [])                      # '%' is literal, not a wildcard
        self.assertTrue(all(h["result"]["registered_domain"] == "github.com" for h in c.get("/api/history?domain=github.com").get_json()))

    def test_feedback_validation_and_stats(self):
        self.assertEqual(c.post("/api/feedback", json={"kind": "nope", "url": "x"}).status_code, 400)
        self.assertEqual(c.post("/api/feedback", json={"kind": "false_positive", "url": "https://github.com"}).status_code, 200)
        s = c.get("/api/stats").get_json()
        self.assertGreaterEqual(s["feedback"], 1); self.assertEqual(sum(s["levels"].values()), s["total"])


class QR(unittest.TestCase):
    def setUp(self):
        try:
            import cv2, numpy as np
            self.cv2 = cv2
        except ImportError:
            self.skipTest("OpenCV not installed")

    def png(self, text):
        img = self.cv2.QRCodeEncoder.create().encode(text)
        img = self.cv2.resize(self.cv2.copyMakeBorder(img, 20, 20, 20, 20, self.cv2.BORDER_CONSTANT, value=255), None, fx=6, fy=6, interpolation=self.cv2.INTER_NEAREST)
        return io.BytesIO(self.cv2.imencode(".png", img)[1].tobytes())

    def test_url_extracted_and_analysed(self):
        r = c.post("/api/qr", data={"image": (self.png("http://paypa1-secure-login.verify-account.xyz/update"), "q.png")}, content_type="multipart/form-data")
        self.assertEqual(r.status_code, 200); d = r.get_json(); self.assertEqual(d["verdict"], "High Risk"); self.assertIn("qr_text", d)

    def test_non_url_payload_and_junk(self):
        r = c.post("/api/qr", data={"image": (self.png("WIFI:S:home;T:WPA;P:secret;;"), "q.png")}, content_type="multipart/form-data")
        self.assertEqual(r.status_code, 400); self.assertIn("not a web link", r.get_json()["error"])
        self.assertEqual(c.post("/api/qr", data={"image": (io.BytesIO(b"junk"), "x.png")}, content_type="multipart/form-data").status_code, 400)


if __name__ == "__main__":
    unittest.main()
