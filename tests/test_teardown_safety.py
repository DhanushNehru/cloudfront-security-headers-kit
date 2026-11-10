#!/usr/bin/env python3
"""Mocked safety tests for teardown.py and deploy.py. No AWS, no network.

  python3 -m unittest tests.test_teardown_safety -v   (from the repo root)

Covers the failure paths that matter for a cleanup script: partial progress,
stale or tampered state files, and resources that fail the kit-marker check.
"""
import contextlib, io, json, os, sys, tempfile, unittest
from unittest import mock

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "scripts"))
sys.path.insert(0, ROOT)

import boto3
import teardown
import deploy

KIT_TAG = {"Key": "project", "Value": "headers-kit-demo"}
ACCT = "123456789012"
STATE = {"region": "ap-south-1", "acct": ACCT, "bucket": f"headers-kit-demo-{ACCT}-a1b2c3",
         "oac_id": "OACID1", "rhp_id": "RHPID1", "dist_id": "EDFDVBD6EXAMPLE",
         "domain": "d111111abcdef8.cloudfront.net"}


class CFExc:
    class NoSuchDistribution(Exception): pass
    class NoSuchOriginAccessControl(Exception): pass
    class NoSuchResponseHeadersPolicy(Exception): pass


class S3Exc:
    class NoSuchBucket(Exception): pass


class FakeCF:
    exceptions = CFExc

    def __init__(self, kit_tags=True, oac_name="headers-kit-oac-a1b2c3",
                 rhp_name="security-headers-full-a1b2c3", dist_gone=False):
        self.kit_tags = kit_tags
        self.oac_name = oac_name
        self.rhp_name = rhp_name
        self.dist_gone = dist_gone
        self.deleted = []
        self.updated = []

    def get_distribution_config(self, Id, **kw):
        if self.dist_gone:
            raise CFExc.NoSuchDistribution("gone")
        return {"DistributionConfig": {"Enabled": False, "Comment": "headers kit demo"}, "ETag": "e1"}

    def list_tags_for_resource(self, Resource):
        return {"Tags": {"Items": [KIT_TAG] if self.kit_tags else []}}

    def get_distribution(self, Id):
        return {"Distribution": {"Status": "Deployed"}}

    def update_distribution(self, Id, **kw):
        self.updated.append(Id)

    def delete_distribution(self, Id, **kw):
        self.deleted.append(("dist", Id))

    def get_origin_access_control(self, Id):
        return {"OriginAccessControl": {"Name": self.oac_name}, "ETag": "e2"}

    def delete_origin_access_control(self, Id, **kw):
        self.deleted.append(("oac", Id))

    def get_response_headers_policy(self, Id):
        return {"ResponseHeadersPolicy": {"ResponseHeadersPolicyConfig": {"Name": self.rhp_name}}, "ETag": "e3"}

    def delete_response_headers_policy(self, Id, **kw):
        self.deleted.append(("rhp", Id))


class FakeS3:
    exceptions = S3Exc

    def __init__(self, kit_tags=True, bucket_gone=False):
        self.kit_tags = kit_tags
        self.bucket_gone = bucket_gone
        self.deleted = []

    def get_bucket_tagging(self, Bucket):
        if not self.kit_tags:
            raise Exception("NoSuchTagSet")
        return {"TagSet": [KIT_TAG]}

    def list_objects_v2(self, Bucket):
        if self.bucket_gone:
            raise S3Exc.NoSuchBucket("gone")
        return {"Contents": [{"Key": "index.html"}]}

    def delete_object(self, Bucket, Key):
        self.deleted.append(("object", Bucket, Key))

    def delete_bucket(self, Bucket):
        self.deleted.append(("bucket", Bucket))


class FakeSession:
    def __init__(self, clients):
        self.clients = clients

    def client(self, name, **kw):
        return self.clients[name]


class TeardownCase(unittest.TestCase):
    def run_teardown(self, cf, s3, state=STATE):
        tmp = tempfile.NamedTemporaryFile("w", suffix=".json", delete=False)
        json.dump(state, tmp)
        tmp.close()
        session = FakeSession({"s3": s3, "cloudfront": cf})
        out = io.StringIO()
        code = None
        with mock.patch.object(boto3.session, "Session", return_value=session), \
             mock.patch.object(teardown, "STATE", tmp.name), \
             contextlib.redirect_stdout(out):
            try:
                teardown.main()
            except SystemExit as e:
                code = e.code if e.code is not None else 0
        return code, out.getvalue(), tmp.name

    def test_full_teardown_deletes_all_kit_resources(self):
        cf, s3 = FakeCF(), FakeS3()
        code, out, state_path = self.run_teardown(cf, s3)
        self.assertIsNone(code)  # clean return
        self.assertIn(("dist", STATE["dist_id"]), cf.deleted)
        self.assertIn(("oac", STATE["oac_id"]), cf.deleted)
        self.assertIn(("rhp", STATE["rhp_id"]), cf.deleted)
        self.assertIn(("bucket", STATE["bucket"]), s3.deleted)
        self.assertIn(("object", STATE["bucket"], "index.html"), s3.deleted)
        self.assertFalse(os.path.exists(state_path))  # state removed when done

    def test_teardown_tolerates_already_deleted_resources(self):
        cf, s3 = FakeCF(dist_gone=True), FakeS3(bucket_gone=True)
        code, out, state_path = self.run_teardown(cf, s3)
        self.assertIsNone(code)
        self.assertIn("already gone", out)
        self.assertIn(("oac", STATE["oac_id"]), cf.deleted)  # remaining work still done
        self.assertFalse(os.path.exists(state_path))

    def test_missing_state_file_exits_cleanly(self):
        session = FakeSession({"s3": FakeS3(), "cloudfront": FakeCF()})
        with mock.patch.object(boto3.session, "Session", return_value=session), \
             mock.patch.object(teardown, "STATE", "/nonexistent/.kit-state.json"):
            with self.assertRaises(SystemExit) as cm:
                teardown.main()
        self.assertIn("nothing to tear down", str(cm.exception.code))

    def test_untagged_distribution_is_left_alone(self):
        cf, s3 = FakeCF(kit_tags=False), FakeS3()
        code, out, state_path = self.run_teardown(cf, s3)
        self.assertEqual(code, 1)
        self.assertNotIn(("dist", STATE["dist_id"]), cf.deleted)
        self.assertEqual(cf.updated, [])
        self.assertIn("leaving it alone", out)
        self.assertTrue(os.path.exists(state_path))  # state kept for investigation
        os.unlink(state_path)

    def test_untagged_bucket_is_left_alone(self):
        cf, s3 = FakeCF(), FakeS3(kit_tags=False)
        code, out, state_path = self.run_teardown(cf, s3)
        self.assertEqual(code, 1)
        self.assertEqual(s3.deleted, [])
        self.assertIn("leaving it alone", out)
        os.unlink(state_path)

    def test_foreign_named_policy_is_left_alone(self):
        cf, s3 = FakeCF(rhp_name="someone-elses-policy"), FakeS3()
        code, out, state_path = self.run_teardown(cf, s3)
        self.assertEqual(code, 1)
        self.assertNotIn(("rhp", STATE["rhp_id"]), cf.deleted)
        self.assertIn("not kit-named", out)
        os.unlink(state_path)


class FakeDeployCF(FakeCF):
    def __init__(self, crash_at_distribution=True):
        super().__init__()
        self.crash = crash_at_distribution

    def create_origin_access_control(self, OriginAccessControlConfig):
        return {"OriginAccessControl": {"Id": "OACID1"}}

    def create_response_headers_policy(self, ResponseHeadersPolicyConfig):
        return {"ResponseHeadersPolicy": {"Id": "RHPID1"}}

    def create_distribution_with_tags(self, DistributionConfigWithTags):
        if self.crash:
            raise RuntimeError("simulated outage at distribution creation")
        return {"Distribution": {"Id": "EDFDVBD6EXAMPLE", "DomainName": "d111111abcdef8.cloudfront.net"}}


class FakeDeployS3:
    exceptions = S3Exc

    def __init__(self):
        self.tag_calls = []

    def create_bucket(self, Bucket, **kw): pass
    def put_public_access_block(self, Bucket, **kw): pass

    def put_bucket_tagging(self, Bucket, Tagging):
        self.tag_calls.append((Bucket, Tagging))

    def upload_file(self, *a, **kw): pass
    def put_bucket_policy(self, Bucket, Policy): pass


class FakeSTS:
    def get_caller_identity(self):
        return {"Account": ACCT}


class DeployCase(unittest.TestCase):
    def run_deploy(self, cf, s3):
        tmp = tempfile.NamedTemporaryFile("w", suffix=".json", delete=False)
        tmp.close()
        os.unlink(tmp.name)  # deploy should create it fresh
        session = FakeSession({"s3": s3, "cloudfront": cf, "sts": FakeSTS()})
        err = None
        with mock.patch.object(boto3.session, "Session", return_value=session), \
             mock.patch.object(deploy, "STATE_PATH", tmp.name), \
             contextlib.redirect_stdout(io.StringIO()):
            try:
                deploy.main()
            except Exception as e:
                err = e
        state = json.load(open(tmp.name)) if os.path.exists(tmp.name) else None
        os.unlink(tmp.name) if os.path.exists(tmp.name) else None
        return err, state

    def test_crash_mid_deploy_leaves_resumable_state(self):
        cf, s3 = FakeDeployCF(crash_at_distribution=True), FakeDeployS3()
        err, state = self.run_deploy(cf, s3)
        self.assertIsInstance(err, RuntimeError)
        self.assertIsNotNone(state)
        self.assertEqual(state["bucket"], f"headers-kit-demo-{ACCT}-" + state["bucket"].rsplit("-", 1)[-1])
        self.assertIn("oac_id", state)
        self.assertIn("rhp_id", state)
        self.assertNotIn("dist_id", state)  # not created yet - teardown won't chase a phantom

    def test_deploy_tags_every_resource_it_creates(self):
        cf, s3 = FakeDeployCF(crash_at_distribution=False), FakeDeployS3()
        err, state = self.run_deploy(cf, s3)
        self.assertIsNone(err)
        self.assertEqual(len(s3.tag_calls), 1)
        self.assertEqual(s3.tag_calls[0][1]["TagSet"], [KIT_TAG])
        self.assertIn("dist_id", state)


if __name__ == "__main__":
    unittest.main()
