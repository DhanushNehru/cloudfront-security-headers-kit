#!/usr/bin/env python3
"""Deploy a private S3 bucket fronted by CloudFront with the full security
headers policy attached. Prints the distribution domain when done.

Usage: AWS_REGION=ap-south-1 python3 scripts/deploy.py
State is written to .kit-state.json - teardown.py reads it. Don't delete it
until after teardown."""
import boto3, json, time, secrets, os, sys

REGION = os.environ.get("AWS_REGION", "ap-south-1")
HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)

s = boto3.session.Session(region_name=REGION)
s3 = s.client("s3")
cf = s.client("cloudfront")
acct = s.client("sts").get_caller_identity()["Account"]
suffix = secrets.token_hex(3)
bucket = f"headers-kit-demo-{acct}-{suffix}"

# 1. private bucket (no public access, no ACLs, default encryption)
kw = {} if REGION == "us-east-1" else {"CreateBucketConfiguration": {"LocationConstraint": REGION}}
s3.create_bucket(Bucket=bucket, **kw)
s3.put_public_access_block(Bucket=bucket, PublicAccessBlockConfiguration={
    "BlockPublicAcls": True, "IgnorePublicAcls": True,
    "BlockPublicPolicy": True, "RestrictPublicBuckets": True})

# 2. demo page
s3.upload_file(os.path.join(ROOT, "site", "index.html"), bucket, "index.html",
               ExtraArgs={"ContentType": "text/html"})

# 3. origin access control - CloudFront signs requests, bucket stays private
oac = cf.create_origin_access_control(OriginAccessControlConfig={
    "Name": f"headers-kit-oac-{suffix}",
    "Description": "headers kit demo",
    "SigningProtocol": "sigv4", "SigningBehavior": "always",
    "OriginAccessControlOriginType": "s3"})["OriginAccessControl"]

# 4. custom response headers policy from the template
policy_cfg = json.load(open(os.path.join(ROOT, "policies", "security-headers-full.json")))
policy_cfg["Name"] = f"security-headers-full-{suffix}"
rhp = cf.create_response_headers_policy(ResponseHeadersPolicyConfig=policy_cfg)["ResponseHeadersPolicy"]

# 5. distribution with the policy attached from the start
dist = cf.create_distribution_with_tags(DistributionConfigWithTags={
    "Tags": {"Items": [{"Key": "project", "Value": "headers-kit-demo"}]},
    "DistributionConfig": {
        "CallerReference": f"headers-kit-{suffix}-{int(time.time())}",
        "Comment": "headers kit demo",
        "Enabled": True,
        "DefaultRootObject": "index.html",
        "PriceClass": "PriceClass_100",
        "Origins": {"Quantity": 1, "Items": [{
            "Id": "s3-origin",
            "DomainName": f"{bucket}.s3.{REGION}.amazonaws.com",
            "S3OriginConfig": {"OriginAccessIdentity": ""},
            "OriginAccessControlId": oac["Id"],
        }]},
        "DefaultCacheBehavior": {
            "TargetOriginId": "s3-origin",
            "ViewerProtocolPolicy": "redirect-to-https",
            "AllowedMethods": {"Quantity": 2, "Items": ["GET", "HEAD"],
                               "CachedMethods": {"Quantity": 2, "Items": ["GET", "HEAD"]}},
            "CachePolicyId": "658327ea-f89d-4fab-a63d-7e88639e58f6",  # managed CachingOptimized
            "ResponseHeadersPolicyId": rhp["Id"],
            "Compress": True,
        },
        "Restrictions": {"GeoRestriction": {"RestrictionType": "none", "Quantity": 0}},
        "ViewerCertificate": {"CloudFrontDefaultCertificate": True},
    }})["Distribution"]

# 6. bucket policy: only this distribution may read
policy = {"Version": "2012-10-17", "Statement": [{
    "Sid": "AllowCloudFrontOAC", "Effect": "Allow",
    "Principal": {"Service": "cloudfront.amazonaws.com"},
    "Action": "s3:GetObject", "Resource": f"arn:aws:s3:::{bucket}/*",
    "Condition": {"StringEquals": {
        "AWS:SourceArn": f"arn:aws:cloudfront::{acct}:distribution/{dist['Id']}"}}}]}
s3.put_bucket_policy(Bucket=bucket, Policy=json.dumps(policy))

state = {"bucket": bucket, "oac_id": oac["Id"], "rhp_id": rhp["Id"],
         "dist_id": dist["Id"], "domain": dist["DomainName"], "region": REGION}
json.dump(state, open(os.path.join(ROOT, ".kit-state.json"), "w"), indent=2)
print("deploying (takes a few minutes):", dist["DomainName"])
print("state saved to .kit-state.json - keep it for teardown.py")
