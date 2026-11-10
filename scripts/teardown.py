#!/usr/bin/env python3
"""Remove everything deploy.py created - and only that.

Reads .kit-state.json for the resource IDs, then re-checks that each resource
still carries the kit's markers (the project=headers-kit-demo tag, or a kit
name prefix) before deleting it. If a check fails - say the state file is
stale or was hand-edited to point at something else - that resource is
reported and left alone, and the state file is kept so you can investigate.

CloudFront only lets you delete a disabled distribution once the disable has
deployed everywhere, so this waits for that (usually 5-15 minutes).

Safe to re-run: anything already gone is reported, not an error.

Usage: python3 scripts/teardown.py"""
import boto3, json, os, sys, time

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
STATE = os.path.join(ROOT, ".kit-state.json")
TAG = ("project", "headers-kit-demo")


def cf_has_kit_tag(cf, arn):
    items = cf.list_tags_for_resource(Resource=arn)["Tags"].get("Items", [])
    return any(t.get("Key") == TAG[0] and t.get("Value") == TAG[1] for t in items)


def s3_has_kit_tag(s3, bucket):
    try:
        tags = s3.get_bucket_tagging(Bucket=bucket)["TagSet"]
    except Exception:
        return False  # no tagset (or no permission to read it): not provably ours
    return any(t.get("Key") == TAG[0] and t.get("Value") == TAG[1] for t in tags)


def main():
    try:
        st = json.load(open(STATE))
    except FileNotFoundError:
        sys.exit("no .kit-state.json - nothing to tear down (or teardown already finished)")

    s = boto3.session.Session(region_name=st.get("region", "ap-south-1"))
    s3 = s.client("s3")
    cf = s.client("cloudfront")
    leftovers = []

    # 1. distribution: verify the kit tag, disable, delete once propagated
    dist_arn = f"arn:aws:cloudfront::{st.get('acct', '')}:distribution/{st['dist_id']}"
    dist_owned = False
    try:
        r = cf.get_distribution_config(Id=st["dist_id"])
        cfg, etag = r["DistributionConfig"], r["ETag"]
        if not cf_has_kit_tag(cf, dist_arn):
            print("distribution", st["dist_id"], "is missing the kit tag - leaving it alone")
            leftovers.append("distribution")
        else:
            dist_owned = True
            if cfg["Enabled"]:
                cfg["Enabled"] = False
                cf.update_distribution(Id=st["dist_id"], IfMatch=etag, DistributionConfig=cfg)
                print("distribution disabling, waiting for propagation...")
    except cf.exceptions.NoSuchDistribution:
        print("distribution already gone")

    # 2. bucket: verify the kit tag, then empty and delete
    try:
        if not st["bucket"].startswith("headers-kit-demo-") or not s3_has_kit_tag(s3, st["bucket"]):
            print("bucket", st["bucket"], "does not carry the kit tag - leaving it alone")
            leftovers.append("bucket")
        else:
            objs = s3.list_objects_v2(Bucket=st["bucket"]).get("Contents", [])
            for o in objs:
                s3.delete_object(Bucket=st["bucket"], Key=o["Key"])
            s3.delete_bucket(Bucket=st["bucket"])
            print("bucket deleted:", st["bucket"])
    except s3.exceptions.NoSuchBucket:
        print("bucket already gone")

    # 3. wait for the disable to reach every edge, then delete
    if dist_owned:
        while True:
            d = cf.get_distribution(Id=st["dist_id"])["Distribution"]
            if d["Status"] == "Deployed":
                break
            print("  status:", d["Status"], "- checking again in 60s")
            time.sleep(60)
        etag = cf.get_distribution_config(Id=st["dist_id"])["ETag"]
        cf.delete_distribution(Id=st["dist_id"], IfMatch=etag)
        print("distribution deleted:", st["dist_id"])

    # 4. OAC and response headers policy: verify the kit name prefix
    try:
        oac = cf.get_origin_access_control(Id=st["oac_id"])
        if not oac["OriginAccessControl"]["Name"].startswith("headers-kit-oac-"):
            print("origin access control", st["oac_id"], "is not kit-named - leaving it alone")
            leftovers.append("oac")
        else:
            cf.delete_origin_access_control(Id=st["oac_id"], IfMatch=oac["ETag"])
            print("origin access control deleted:", st["oac_id"])
    except cf.exceptions.NoSuchOriginAccessControl:
        print("origin access control already gone")

    try:
        rhp = cf.get_response_headers_policy(Id=st["rhp_id"])
        name = rhp["ResponseHeadersPolicy"]["ResponseHeadersPolicyConfig"]["Name"]
        if not (name.startswith("security-headers-full-") or name.startswith("security-headers-parity-")):
            print("response headers policy", st["rhp_id"], "is not kit-named - leaving it alone")
            leftovers.append("rhp")
        else:
            cf.delete_response_headers_policy(Id=st["rhp_id"], IfMatch=rhp["ETag"])
            print("response headers policy deleted:", st["rhp_id"])
    except cf.exceptions.NoSuchResponseHeadersPolicy:
        print("response headers policy already gone")

    if leftovers:
        print("left in place (failed the kit-marker check):", ", ".join(leftovers))
        print("state file kept at", STATE)
        sys.exit(1)
    os.remove(STATE)
    print("done - every resource deploy.py created is gone")


if __name__ == "__main__":
    main()
