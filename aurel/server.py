"""Flask API and UI. Binds to localhost only; rejects foreign Host and Origin headers."""
import json, os, queue, threading
from urllib.parse import urlparse
from flask import Flask, Response, abort, jsonify, request, send_file

from aurel import database as db
from aurel.engine import MAX_URL, analyze

ALLOWED_HOSTS = {"127.0.0.1", "localhost"}
CSP = ("default-src 'self'; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src https://fonts.gstatic.com; "
       "script-src 'self' 'unsafe-inline'; img-src 'self' data: blob:; media-src 'self' blob:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'")


def run_scan(raw, online=False, source="web", progress=None, save=True):
    r = analyze(raw, online=online, progress=progress)
    if r["valid"] and save and not (source == "extension" and r["level"] == "low"):   # extension never logs ordinary browsing
        r["id"] = db.save_scan(r, source)
    return r


def create_app():
    app = Flask(__name__)
    app.config["MAX_CONTENT_LENGTH"] = 5 * 1024 * 1024

    @app.before_request
    def guard():
        if (request.host or "").rsplit(":", 1)[0].strip("[]").lower() not in ALLOWED_HOSTS:
            abort(400)
        o = request.headers.get("Origin")
        if o:
            ext = os.environ.get("AUREL_EXTENSION_ID")
            ok = (o == f"chrome-extension://{ext}") if ext and o.startswith("chrome-extension://") else o.startswith("chrome-extension://")
            if not (ok or (urlparse(o).hostname or "") in ALLOWED_HOSTS):
                abort(403)

    @app.after_request
    def headers(r):
        r.headers.update({"X-Content-Type-Options": "nosniff", "Referrer-Policy": "no-referrer", "Content-Security-Policy": CSP})
        if request.path.startswith("/api/"):
            r.headers["Cache-Control"] = "no-store"
        return r

    @app.errorhandler(Exception)
    def fail(e):
        code = getattr(e, "code", 500) if hasattr(e, "code") and isinstance(e.code, int) else 500
        msg = {400: "Bad request.", 403: "Request origin not allowed.", 404: "Not found.", 405: "Method not allowed.", 413: "Upload too large (5 MB limit)."}.get(code, "Unexpected error. Check the AUREL terminal for details.")
        if code == 500:
            app.logger.exception(e)
        return (jsonify({"valid": False, "error": msg}) if request.path.startswith("/api/") else (msg, code)), code

    @app.get("/")
    def index():
        return send_file(os.path.join(app.root_path, "templates", "index.html"))

    @app.get("/api/health")
    def health():
        return jsonify({"ok": True, "app": "AUREL"})

    @app.post("/api/scan")
    def scan():
        d = request.get_json(silent=True) or {}
        r = run_scan(d.get("url"), bool(d.get("online")), d.get("source") if d.get("source") in ("extension", "qr") else "web", save=d.get("save", True))
        return jsonify(r), (200 if r["valid"] else 400)

    @app.get("/api/scan/stream")
    def stream():
        """Server-sent events: one event per real analysis stage, then the result."""
        url, online, q = request.args.get("url", "")[:MAX_URL + 1], request.args.get("online") == "true", queue.Queue()

        def work():
            try:
                q.put(("result", run_scan(url, online, "web", lambda name: q.put(("stage", name)))))
            except Exception as e:
                q.put(("result", {"valid": False, "error": "Unexpected error: " + type(e).__name__}))
        threading.Thread(target=work, daemon=True).start()

        def gen():
            while True:
                kind, val = q.get()
                yield f"event: {kind}\ndata: {json.dumps(val)}\n\n"
                if kind == "result":
                    break
        return Response(gen(), mimetype="text/event-stream", headers={"Cache-Control": "no-cache"})

    @app.post("/api/bulk")
    def bulk():
        d = request.get_json(silent=True) or {}
        urls = d.get("urls")
        if not isinstance(urls, list):
            return jsonify({"error": "Send a list of URLs."}), 400
        urls = [u.strip() for u in urls if isinstance(u, str) and u.strip()][:50]
        return jsonify([{"input": u[:120], **run_scan(u, bool(d.get("online")), "web")} for u in urls])

    @app.post("/api/qr")
    def qr():
        """Decode a QR image and analyse the URL inside. The URL is never opened."""
        f = request.files.get("image")
        if not f:
            return jsonify({"valid": False, "error": "Choose an image containing a QR code."}), 400
        try:
            import cv2, numpy as np
        except ImportError:
            return jsonify({"valid": False, "error": "QR decoding needs OpenCV. Run: pip install opencv-python-headless"}), 501
        data = f.read()
        if data[:8] == b"\x89PNG\r\n\x1a\n" and int.from_bytes(data[16:20], "big") * int.from_bytes(data[20:24], "big") > 40_000_000:
            return jsonify({"valid": False, "error": "Image dimensions are too large."}), 400
        img = cv2.imdecode(np.frombuffer(data, np.uint8), cv2.IMREAD_COLOR)
        if img is None:
            return jsonify({"valid": False, "error": "That file is not a readable image."}), 400
        det, text = cv2.QRCodeDetector(), ""
        for variant in (img, cv2.cvtColor(img, cv2.COLOR_BGR2GRAY), cv2.resize(img, None, fx=2, fy=2, interpolation=cv2.INTER_CUBIC)):
            text = det.detectAndDecode(variant)[0]
            if text:
                break
        if not text:
            return jsonify({"valid": False, "error": "No QR code found. Try a sharper, closer image."}), 400
        if not text.lower().startswith(("http://", "https://")) and ":" in text.split("/")[0] and "." not in text.split(":")[0]:
            return jsonify({"valid": False, "qr_text": text[:200], "error": f"This QR code holds '{text.split(':')[0]}' data, not a web link."}), 400
        r = run_scan(text, request.form.get("online") == "true", "qr")
        r["qr_text"] = text[:MAX_URL]
        return jsonify(r), (200 if r["valid"] else 400)

    @app.get("/api/history")
    def history():
        return jsonify(db.history(request.args.get("q"), request.args.get("verdict"), request.args.get("domain"), request.args.get("limit", 100)))

    @app.delete("/api/history")
    def clear():
        db.clear()
        return "", 204

    @app.get("/api/stats")
    def stats():
        return jsonify(db.stats())

    @app.post("/api/feedback")
    def feedback():
        d = request.get_json(silent=True) or {}
        if d.get("kind") not in ("false_positive", "missed_threat") or not isinstance(d.get("url"), str) or not d["url"]:
            return jsonify({"error": "Invalid feedback."}), 400
        db.add_feedback(d["url"][:MAX_URL], d.get("scan_id") if isinstance(d.get("scan_id"), int) else None, d["kind"])
        return jsonify({"saved": True})

    return app
