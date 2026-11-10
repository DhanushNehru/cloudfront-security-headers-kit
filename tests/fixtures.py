#!/usr/bin/env python3
"""Serve a controlled fixture site for the offline tests.

Usage: python3 tests/fixtures.py <bad|good|spa> <port>

  bad  - no security headers, real /.git/HEAD and /.env files exposed
  good - all six headers set
  spa  - no security headers, and every path returns index.html with a 200
         (soft-200 fallback, like a single-page-app host)
"""
import http.server, sys, os, tempfile, pathlib

mode = sys.argv[1]
port = int(sys.argv[2])

root = pathlib.Path(tempfile.mkdtemp(prefix=f"fixture_{mode}_"))
(root / "index.html").write_text("<h1>demo</h1>\n")
if mode == "bad":
    (root / ".git").mkdir()
    (root / ".git" / "HEAD").write_text("ref: refs/heads/main\n")
    (root / ".env").write_text("AWS_SECRET=AKIAEXAMPLE123\n")

os.chdir(root)

class H(http.server.SimpleHTTPRequestHandler):
    def end_headers(self):
        if mode == "good":
            self.send_header("Strict-Transport-Security", "max-age=31536000")
            self.send_header("Content-Security-Policy", "default-src 'self'")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("X-Frame-Options", "SAMEORIGIN")
            self.send_header("Referrer-Policy", "strict-origin-when-cross-origin")
            self.send_header("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
        super().end_headers()
    def send_head(self):
        if mode == "spa":  # soft-200: every path returns index.html with 200
            self.path = "/index.html"
        return super().send_head()
    def log_message(self, *a): pass

http.server.ThreadingHTTPServer(("127.0.0.1", port), H).serve_forever()
