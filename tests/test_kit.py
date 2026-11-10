#!/usr/bin/env python3
"""Offline tests for the kit. No AWS calls, no network beyond localhost.

  python3 tests/test_kit.py

Covers: policy template contents, script syntax, and the verifier's behavior
against controlled good/bad/soft-200 fixtures."""
import json, py_compile, subprocess, sys, time, os

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
fails = []

def ok(name, cond, extra=""):
    print(("PASS" if cond else "FAIL"), "-", name, extra)
    if not cond:
        fails.append(name)

# --- policy templates -------------------------------------------------------
full = json.load(open(os.path.join(ROOT, "policies", "security-headers-full.json")))
parity = json.load(open(os.path.join(ROOT, "policies", "security-headers-parity.json")))
shc_f = full["SecurityHeadersConfig"]

ok("full policy sets CSP", shc_f.get("ContentSecurityPolicy", {}).get("ContentSecurityPolicy") == "default-src 'self'")
ok("full policy sets Permissions-Policy",
   any(i["Header"] == "Permissions-Policy" for i in full["CustomHeadersConfig"]["Items"]))
ok("full policy HSTS one year + subdomains",
   shc_f["StrictTransportSecurity"]["AccessControlMaxAgeSec"] == 31536000
   and shc_f["StrictTransportSecurity"]["IncludeSubdomains"])
ok("full policy has all five managed-policy headers",
   all(k in shc_f for k in ("XSSProtection", "FrameOptions", "ReferrerPolicy",
                            "ContentTypeOptions", "StrictTransportSecurity")))
ok("parity policy is exactly the five managed headers",
   len(parity["SecurityHeadersConfig"]) == 5 and "CustomHeadersConfig" not in parity)

# --- scripts compile --------------------------------------------------------
for f in ("scripts/deploy.py", "scripts/teardown.py", "scripts/verify.py"):
    try:
        py_compile.compile(os.path.join(ROOT, f), doraise=True)
        ok(f"compiles: {f}", True)
    except Exception as e:
        ok(f"compiles: {f}", False, str(e))

# --- verifier against controlled fixtures -----------------------------------
procs = []
for mode, port in (("bad", 8391), ("good", 8392), ("spa", 8393)):
    procs.append(subprocess.Popen(
        [sys.executable, os.path.join(ROOT, "tests", "fixtures.py"), mode, str(port)],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL))
time.sleep(1.5)

def run_verify(port):
    out = subprocess.run(
        [sys.executable, os.path.join(ROOT, "scripts", "verify.py"),
         f"http://127.0.0.1:{port}"], capture_output=True, text=True)
    return json.loads(out.stdout)

try:
    rb, rg, rs = run_verify(8391), run_verify(8392), run_verify(8393)
    ok("bad fixture scores low", rb["score"].startswith(("1/", "2/")), rb["score"])
    ok("bad fixture: .git exposure detected (content-validated)",
       any(c["check"] == ".git exposed" and not c["pass"] and "validated" in c["detail"]
           for c in rb["checks"]))
    ok("bad fixture: .env exposure detected (content-validated)",
       any(c["check"] == ".env exposed" and not c["pass"] and "validated" in c["detail"]
           for c in rb["checks"]))
    ok("good fixture passes every scored check",
       rg["score"].split("/")[0] == rg["score"].split("/")[1], rg["score"])
    ok("spa fixture: soft-200 not flagged as exposure",
       all(c["pass"] for c in rs["checks"] if c["check"] in (".git exposed", ".env exposed")))
    scored = [c for c in rg["checks"] if not c.get("info") and c["pass"] is not None]
    ok("Server header is informational and unscored",
       all("Server header" in c["check"] for c in rg["checks"] if c.get("info"))
       and len(scored) == int(rg["score"].split("/")[1]))
finally:
    for p in procs:
        p.terminate()

print()
print(f"{len(fails)} failure(s)")
sys.exit(1 if fails else 0)
