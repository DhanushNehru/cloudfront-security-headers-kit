#!/usr/bin/env python3
"""sitecheck - one-command security audit for a deployed site.
Stdlib only. Usage: python3 sitecheck.py https://example.com
Scores are a heuristic checklist, not a security guarantee."""
import sys, ssl, socket, urllib.request, urllib.error, json, re, secrets
from urllib.parse import urlparse

CHECKS = []
def check(name, ok, detail, fix, info=False):
    # info=True: informational observation, reported but excluded from the score
    CHECKS.append({"check": name, "pass": bool(ok) if ok is not None else None,
                   "detail": str(detail)[:120], "aws_fix": fix,
                   **({"info": True} if info else {})})

class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *a, **k): return None

def fetch(url, timeout=15, follow=True):
    req = urllib.request.Request(url, headers={"User-Agent": "sitecheck/0.2"})
    opener = urllib.request.build_opener() if follow else urllib.request.build_opener(NoRedirect)
    try:
        with opener.open(req, timeout=timeout) as r:
            return r.status, dict(r.headers), r.read(4096)
    except urllib.error.HTTPError as e:
        return e.code, dict(e.headers), e.read(4096) if e.fp else b""
    except Exception as e:
        return None, {}, str(e).encode()

def main(url):
    if not url.startswith("http"): url = "https://" + url
    p = urlparse(url); host = p.hostname
    local = host in ("localhost", "127.0.0.1")
    scheme = p.scheme if local else "https"
    base = "%s://%s" % (scheme, p.netloc)

    # 1. TLS (skipped for local fixtures)
    if local:
        check("TLS >= 1.2", None, "skipped (local fixture)", "")
    else:
        try:
            ctx = ssl.create_default_context()
            with socket.create_connection((host, 443), timeout=10) as sock:
                with ctx.wrap_socket(sock, server_hostname=host) as s:
                    tls = s.version(); exp = s.getpeercert().get("notAfter", "?")
            check("TLS >= 1.2", tls in ("TLSv1.2", "TLSv1.3"),
                  "negotiated %s, cert expires %s" % (tls, exp),
                  "CloudFront: use a security policy of TLSv1.2_2021 or later")
        except Exception as e:
            check("TLS >= 1.2", False, "TLS handshake failed: %s" % e, "Attach a valid certificate")

    # 2. HTTP -> HTTPS redirect (no redirect following)
    if not local:
        st, hd, _ = fetch("http://%s%s" % (p.netloc, p.path or "/"), follow=False)
        loc = hd.get("Location") or hd.get("location") or ""
        check("HTTP redirects to HTTPS",
              st in (301, 302, 307, 308) and loc.startswith("https"),
              "HTTP returned %s%s" % (st, (" -> " + loc) if loc else " (no redirect)"),
              "CloudFront: set Viewer Protocol Policy to 'Redirect HTTP to HTTPS'")

    # 3. Baseline for soft-200 detection: random path that should 404
    bst, _, bbody = fetch(base + "/sitecheck-probe-" + secrets.token_hex(8))

    # 4. Security headers
    target = base + (p.path or "/")
    st, hd, _ = fetch(target)
    if st is None:
        print(json.dumps({"error": "could not fetch " + target})); return
    h = {k.lower(): v for k, v in hd.items()}
    sec = [
        ("strict-transport-security", "HSTS",
         "CloudFront response headers policy: Strict-Transport-Security (in managed SecurityHeadersPolicy)"),
        ("content-security-policy", "CSP",
         "Custom CloudFront response headers policy: Content-Security-Policy (NOT in the managed policy; start with default-src 'self')"),
        ("x-content-type-options", "X-Content-Type-Options",
         "Managed SecurityHeadersPolicy includes X-Content-Type-Options: nosniff"),
        ("x-frame-options", "X-Frame-Options / frame-ancestors",
         "Managed SecurityHeadersPolicy includes X-Frame-Options: SAMEORIGIN"),
        ("referrer-policy", "Referrer-Policy",
         "Managed SecurityHeadersPolicy includes Referrer-Policy: strict-origin-when-cross-origin"),
        ("permissions-policy", "Permissions-Policy",
         "Custom CloudFront response headers policy: Permissions-Policy (NOT in the managed policy)"),
    ]
    for key, label, fix in sec:
        present = key in h or (key == "x-frame-options" and "frame-ancestors" in h.get("content-security-policy", ""))
        check(label, present, (h.get(key, "missing")[:90] if present else "header missing"), fix)
    srv = h.get("server", "")
    check("Server header not verbose (informational)", not any(c.isdigit() for c in srv),
          "Server: %s (informational: not a vulnerability by itself)" % (srv or "absent"),
          "Strip version-leaking Server header", info=True)

    # 5. Cookies
    setc = h.get("set-cookie", "")
    if setc:
        low = setc.lower()
        check("Cookies Secure+HttpOnly+SameSite",
              all(x in low for x in ("secure", "httponly", "samesite")), setc[:90],
              "Set Secure; HttpOnly; SameSite on cookies at the origin")
    else:
        check("Cookies Secure+HttpOnly+SameSite", True, "no cookies set", "")

    # 6. Exposed files with content validation (soft-200 aware)
    probes = [
        ("/.git/HEAD", ".git exposed", lambda b: b.strip().startswith(b"ref:")),
        ("/.env", ".env exposed", lambda b: re.match(rb"^[A-Z_][A-Z0-9_]*=", b.strip() or b" ") is not None),
    ]
    for path, label, is_real in probes:
        st2, _, body = fetch(base + path)
        soft200 = (st2 == 200 and st2 == bst and body == bbody)
        exposed = bool(st2 == 200 and body.strip() and not soft200 and is_real(body))
        if soft200:
            detail = "%s -> HTTP %s (soft-200 SPA fallback, content not real)" % (path, st2)
        elif exposed:
            detail = "%s -> HTTP %s (content validated)" % (path, st2)
        else:
            detail = "%s -> HTTP %s" % (path, st2)
        check(label, not exposed, detail,
              "Block dotfile paths at the CDN and never deploy them to the bucket")

    done = [c for c in CHECKS if c["pass"] is not None and not c.get("info")]
    score = sum(1 for c in done if c["pass"])
    print(json.dumps({"url": target, "score": "%d/%d" % (score, len(done)),
                      "note": "heuristic checklist, not a security guarantee",
                      "checks": CHECKS}, indent=2))

if __name__ == "__main__":
    main(sys.argv[1] if len(sys.argv) > 1 else "example.com")
