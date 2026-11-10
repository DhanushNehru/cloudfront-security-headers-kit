# cloudfront-security-headers-kit

Response headers policy templates and deploy/verify/teardown scripts for a static site on S3 + CloudFront.

The fresh S3 + CloudFront distribution I tested sent none of the six security headers this kit checks - a stock deploy only returns what you configure, and the tutorials I followed never configured headers. AWS's managed `SecurityHeadersPolicy` covers five of them (HSTS, X-Content-Type-Options, X-Frame-Options, Referrer-Policy, X-XSS-Protection) but not Content-Security-Policy or Permissions-Policy. This kit is the custom policy that adds those two, plus the scripts to stand a demo site up, check the result, and tear everything down.

Measured on that distribution (audit script in `scripts/verify.py`): 5/11 checks passed before attaching the full policy, 11/11 after. See `evidence/`.

## Status

The policy JSON and the before/after evidence come from a real distribution I built, audited, and tore down manually (console + CLI). `deploy.py` and `teardown.py` codify that same sequence as scripts; the scripts themselves have not had their own end-to-end run yet. `verify.py` and the test suite (`python3 tests/test_kit.py`) run offline against local fixtures. If you run deploy.py end to end, an issue or PR with the result is welcome.

## Requirements

- Python 3.9+; `pip install boto3` for deploy/teardown. `verify.py` is stdlib-only.
- AWS credentials configured for your own account (environment variables or `~/.aws/`). The credentials need `sts:GetCallerIdentity`, `s3:CreateBucket`, `s3:PutPublicAccessBlock`, `s3:PutBucketPolicy`, `s3:PutObject`, `s3:ListBucket`, `s3:DeleteObject`, `s3:DeleteBucket`, and CloudFront `CreateOriginAccessControl`, `CreateResponseHeadersPolicy`, `CreateDistributionWithTags`, `GetDistribution`, `GetDistributionConfig`, `UpdateDistribution`, `DeleteDistribution`, `GetOriginAccessControl`, `DeleteOriginAccessControl`, `GetResponseHeadersPolicy`, `DeleteResponseHeadersPolicy`.
- Nothing here touches resources it didn't create. deploy.py records every resource ID it creates in `.kit-state.json`; teardown.py deletes exactly those, by ID. Bucket names include your account ID plus a random suffix, and teardown is safe to re-run - anything already gone is reported, not an error.

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
  specific origins, nonces, or hashes. The kit sets CSP through CloudFront's
  dedicated `ContentSecurityPolicy` field, which always sends the enforcing
  header - to test-drive a policy on an existing site, remove that block and
  add a custom header named `Content-Security-Policy-Report-Only` with the
  same value under `CustomHeadersConfig`, deploy, watch what would break,
  then move the value back to the dedicated field to enforce.
- `Permissions-Policy: camera=(), microphone=(), geolocation=()` denies those
  features outright. Keep only the denials your site can live with; drop or
  loosen the rest.
- `X-Frame-Options: SAMEORIGIN` breaks legitimate embedding of your pages on
  other sites. Use `frame-ancestors` in CSP if you need finer control.
- `X-XSS-Protection` is deprecated and current browsers ignore it; the managed
  policy still sets it, so the parity template does too. It is not a
  substitute for CSP.
- HSTS with `includeSubDomains` affects every subdomain. Make sure they all
  serve HTTPS before turning it on, and leave `preload` off unless you mean it.

Headers are baseline hygiene, not a security guarantee. Header presence is not
correctness: a header can be present with a value that is wrong for your site,
and headers do nothing for application logic, dependencies, IAM, or bucket
permissions. (The bucket side matters more: keep it private, serve only
through CloudFront with OAC - the deploy script does exactly that.)

## Usage

```bash
pip install boto3
export AWS_REGION=ap-south-1        # any region; CloudFront is global
python3 scripts/deploy.py           # prints your dXXXX.cloudfront.net domain
python3 scripts/verify.py https://dXXXX.cloudfront.net
python3 scripts/teardown.py         # removes every resource deploy.py created
```

Cost: a short demo run is a handful of CloudFront and S3 requests at
pay-as-you-go rates - my run worked out to well under a cent on the public
pricing for my region at the time. Estimate your own from current pricing
before running, and run teardown.py when you're done so nothing keeps
billing. Don't skip it.

## Scoring notes

verify.py reports 11 scored checks (TLS, HTTPS redirect, six headers, cookie
flags, .git/.env exposure with content validation so SPA soft-200s don't cry
wolf) plus one informational observation (the `Server` header - cosmetic, not
scored). A passing score means the specific misconfigurations this audit
checks for are absent - nothing more.
