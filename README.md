# cloudfront-security-headers-kit

Response headers policy templates and deploy/verify/teardown scripts for a static site on S3 + CloudFront.

A stock S3 + CloudFront deploy ships with no security headers. AWS's managed
`SecurityHeadersPolicy` covers five of them (HSTS, X-Content-Type-Options,
X-Frame-Options, Referrer-Policy, X-XSS-Protection) but not
Content-Security-Policy or Permissions-Policy. This kit is the custom policy
that adds those two, plus the scripts to stand a demo site up, check the
result, and tear everything down.

Measured on a fresh S3 + CloudFront distribution (audit script in
`scripts/verify.py`): 5/11 checks passed before attaching the full policy,
11/11 after. See `evidence/`.

## What's here

- `policies/security-headers-full.json` - the seven-header policy (verified against a live distribution)
- `policies/security-headers-parity.json` - the same five headers as the AWS managed policy, as a custom policy you can extend
- `scripts/deploy.py` - bucket + OAC + distribution with the full policy attached
- `scripts/verify.py` - header and exposure checks against any URL (stdlib Python, JSON output)
- `scripts/teardown.py` - disable, delete, empty, remove everything deploy.py created
- `site/index.html` - the placeholder page the demo serves
- `evidence/` - the before/after audit output from the run this kit was built on

## Read this before attaching the full policy to a real site

These headers change browser behavior. None of this is one-size-fits-all:

- `Content-Security-Policy: default-src 'self'` blocks inline scripts, inline
  styles, and third-party assets. Plenty of real sites need `script-src` with
  specific origins, nonces, or hashes. For an existing site, deploy first with
  `Content-Security-Policy-Report-Only` (swap the header name in the policy),
  watch what would break, then enforce.
- `Permissions-Policy: camera=(), microphone=(), geolocation=()` denies those
  features outright. Keep only the denials your site can live with; drop or
  loosen the rest.
- `X-Frame-Options: SAMEORIGIN` breaks legitimate embedding of your pages on
  other sites. Use `frame-ancestors` in CSP if you need finer control.
- `X-XSS-Protection` is a legacy header for browsers that no longer exist; the
  managed policy still sets it, so the parity template does too. It is not a
  substitute for CSP.
- HSTS with `includeSubDomains` affects every subdomain. Make sure they all
  serve HTTPS before turning it on, and leave `preload` off unless you mean it.

Headers are baseline hygiene, not a security guarantee. They do nothing for
application logic, dependencies, IAM, or bucket permissions. (The bucket side
matters more: keep it private, serve only through CloudFront with OAC - the
deploy script does exactly that.)

## Usage

```bash
export AWS_REGION=ap-south-1        # any region; CloudFront is global
./scripts/deploy.py                 # prints your dXXXX.cloudfront.net domain
python3 scripts/verify.py https://dXXXX.cloudfront.net
./scripts/teardown.py               # removes every resource it created
```

Cost: the demo runs on pay-as-you-go pennies-to-nothing at this scale
(~80 requests, ~1 KB stored). teardown.py returns the account to zero
resources. Don't skip it.

## Scoring notes

verify.py reports 11 scored checks (TLS, HTTPS redirect, six headers, cookie
flags, .git/.env exposure with content validation so SPA soft-200s don't cry
wolf) plus one informational observation (the `Server` header - cosmetic, not
a vulnerability). A passing score means the cheap misconfigurations are gone,
nothing more.
