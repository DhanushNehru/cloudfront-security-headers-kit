#!/usr/bin/env python3
"""Remove everything deploy.py created. Reads .kit-state.json.
CloudFront only lets you delete a disabled distribution once the disable has
deployed everywhere, so this waits for that (usually 5-15 minutes).

Usage: python3 scripts/teardown.py"""
import boto3, json, os, sys, time

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
st = json.load(open(os.path.join(ROOT, ".kit-state.json")))

s = boto3.session.Session(region_name=st.get("region", "ap-south-1"))
s3 = s.client("s3")
cf = s.client("cloudfront")

# 1. disable the distribution
r = cf.get_distribution_config(Id=st["dist_id"])
cfg, etag = r["DistributionConfig"], r["ETag"]
if cfg["Enabled"]:
    cfg["Enabled"] = False
    cf.update_distribution(Id=st["dist_id"], IfMatch=etag, DistributionConfig=cfg)
    print("distribution disabling, waiting for propagation...")

# 2. empty and delete the bucket while that propagates
try:
    objs = s3.list_objects_v2(Bucket=st["bucket"]).get("Contents", [])
    for o in objs:
        s3.delete_object(Bucket=st["bucket"], Key=o["Key"])
    s3.delete_bucket(Bucket=st["bucket"])
    print("bucket deleted:", st["bucket"])
except s3.exceptions.NoSuchBucket:
    print("bucket already gone")

# 3. wait for the disable to reach every edge, then delete
while True:
    d = cf.get_distribution(Id=st["dist_id"])["Distribution"]
    if d["Status"] == "Deployed":
        break
    print("  status:", d["Status"], "- checking again in 60s")
    time.sleep(60)
etag = cf.get_distribution_config(Id=st["dist_id"])["ETag"]
cf.delete_distribution(Id=st["dist_id"], IfMatch=etag)
print("distribution deleted:", st["dist_id"])

cf.delete_origin_access_control(Id=st["oac_id"], IfMatch=cf.get_origin_access_control(Id=st["oac_id"])["ETag"])
print("origin access control deleted:", st["oac_id"])

cf.delete_response_headers_policy(Id=st["rhp_id"], IfMatch=cf.get_response_headers_policy(Id=st["rhp_id"])["ETag"])
print("response headers policy deleted:", st["rhp_id"])

os.remove(os.path.join(ROOT, ".kit-state.json"))
print("done - account is back to zero kit resources")
