"""Milestone-4 acceptance tests: evidence retention/export controls and
conservative cross-tool grouping (plan §11.10/§11.11)."""
from __future__ import annotations

import json
import os
import sys
import tempfile
import time
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))


class RetentionCase(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
        self.ws = Path(self._tmp.name) / "lab"
        self.ws.mkdir(parents=True)
        self.cfg = {"retention": {"enabled": True, "logs_days": 1, "traces_days": 1,
                                  "bundles_days": 1, "lifecycle_days": 1}}

    def tearDown(self):
        self._tmp.cleanup()

    def _old_file(self, rel: str, body: str = "x") -> Path:
        path = self.ws / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(body, encoding="utf-8")
        old = time.time() - 10 * 86400
        os.utime(path, (old, old))
        return path

    def test_classification(self):
        from core.retention import classify
        self.assertEqual(classify(self.ws / "recon" / "a.txt", self.ws), "traces")
        self.assertEqual(classify(self.ws / "evidence" / "b.json", self.ws), "bundles")
        self.assertEqual(classify(self.ws / "reports" / "report.md", self.ws), "lifecycle")
        self.assertEqual(classify(self.ws / "scan.log", self.ws), "logs")
        self.assertEqual(classify(self.ws / "run_manifest.json", self.ws), "lifecycle")
        self.assertIsNone(classify(self.ws / "misc.dat", self.ws))

    def test_dry_run_changes_nothing(self):
        from core.retention import plan, apply
        paths = [self._old_file("scan.log"), self._old_file("recon/live.json"),
                 self._old_file("evidence/deadbeef.json"), self._old_file("reports/report.md")]
        result = plan(self.ws, self.cfg, target="lab")
        classes = {a["class"] for a in result["actions"]}
        self.assertTrue({"logs", "traces", "bundles", "lifecycle"} <= classes)
        self.assertTrue(all(p.exists() for p in paths))          # untouched
        refused = apply(result, confirm=False)
        self.assertFalse(refused["applied"])
        disabled = plan(self.ws, {"retention": {"enabled": False}}, target="lab")
        self.assertFalse(apply(disabled, confirm=True)["applied"])  # policy gate
        self.assertTrue(all(p.exists() for p in paths))

    def test_apply_removes_expired_and_records(self):
        from core.retention import plan, apply, removal_records
        self._old_file("evidence/deadbeef.json", "{}")
        result = plan(self.ws, self.cfg, target="lab")
        out = apply(result, confirm=True)
        self.assertTrue(out["applied"])
        self.assertEqual(len(out["deleted"]), len(result["actions"]))
        self.assertFalse((self.ws / "evidence" / "deadbeef.json").exists())
        records = removal_records(self.ws)
        self.assertEqual(len(records), len(result["actions"]))
        self.assertEqual(records[0]["class"], "bundles")
        self.assertEqual(len(records[0]["sha256"]), 64)

    def test_removed_evidence_cannot_prove_a_fix(self):
        from core.evidence import write_bundle
        from core.memory import Memory
        from core.retention import plan, apply
        from core.proof_gate import poc_status, is_verified
        memory = Memory(self.ws / "memory.db")
        finding = {"target": "lab", "category": "xss", "title": "lab xss", "url": "http://lab/",
                   "parameter": "q", "response": "captured",
                   "metadata": {"poc": {"verified": True, "response_excerpt": "proof-body"}}}
        artifact = write_bundle(self.ws / "evidence", finding)
        finding["metadata"]["evidence_bundle"] = artifact
        fid = memory.record_finding(finding)
        self.assertTrue(is_verified(memory.list_findings("lab")[0]))

        old = time.time() - 10 * 86400
        os.utime(artifact["file"], (old, old))
        result = plan(self.ws, self.cfg, target="lab")
        out = apply(result, confirm=True, memory=memory)
        self.assertEqual(out["findings_marked"], 1)
        stored = {f["id"]: f for f in memory.list_findings("lab")}[fid]
        self.assertTrue(stored["metadata"]["evidence_removed"])
        status, reason = poc_status(stored)
        self.assertEqual(status, "candidate")
        self.assertIn("retention", reason)
        self.assertFalse(is_verified(stored))


class ExportCase(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
        self.out = Path(self._tmp.name) / "pkg"
        self.secrets = ["super-secret-cookie-value"]

    def tearDown(self):
        self._tmp.cleanup()

    def _findings(self):
        return [{
            "id": 1, "severity": "high", "cvss": 8.1, "confidence": 0.9,
            "category": "xss", "title": "reflected xss",
            "url": "http://lab/search?q=1&token=secret-intheurl",
            "parameter": "q",
            "evidence": "cookie super-secret-cookie-value reflected; Authorization: Bearer topsecret",
            "request": "GET /search?q=1 HTTP/1.1\r\nCookie: sid=super-secret-cookie-value",
            "response": "HTTP/1.1 200 OK\r\nSet-Cookie: sid=super-secret-cookie-value",
            "metadata": {"password": "hidden", "session": "super-secret-cookie-value"},
        }]

    def test_shareable_package_has_no_secrets(self):
        from core.export_package import build_package, verify_package
        manifest = build_package(self._findings(), self.out, profile="shareable",
                                 secrets=self.secrets, target="lab")
        self.assertEqual(manifest["finding_count"], 1)
        self.assertTrue(set(manifest["files"]) == {"findings.json", "findings.csv", "findings.jsonl"})
        blob = "\n".join((self.out / name).read_text(encoding="utf-8")
                         for name in manifest["files"])
        for secret in ("super-secret-cookie-value", "topsecret", "secret-intheurl"):
            self.assertNotIn(secret, blob)
        self.assertTrue(verify_package(self.out))
        (self.out / "findings.json").write_text("tampered", encoding="utf-8")
        self.assertFalse(verify_package(self.out))

    def test_profiles_are_allowlisted_and_bounded(self):
        from core.export_package import project
        shareable = project(self._findings()[0], "shareable", secrets=self.secrets)
        self.assertNotIn("request", shareable)
        self.assertNotIn("response", shareable)
        self.assertNotIn("payload", shareable)
        internal = project(self._findings()[0], "internal")
        self.assertIn("request", internal)
        self.assertLessEqual(len(internal["request"]), 4000)

    def test_redaction_covers_nested_headers_urls_and_encodings(self):
        from urllib.parse import quote
        from core.evidence import redact
        secret = "s3cr3tvalue"
        payload = {
            "nested": {"deep": [{"password": "p"}, {"note": f"token={secret}"}]},
            "headers": "Cookie: sid=abc\r\nCookie: sid=def\r\nAuthorization: Bearer zzz",
            "url": f"http://lab/?api_key={secret}&x=1",
            "encoded": quote(secret, safe=""),
            "double": quote(quote(secret, safe=""), safe=""),
        }
        out = json.dumps(redact(payload, secrets=[secret]))
        self.assertNotIn(secret, out)
        self.assertNotIn(quote(secret, safe=""), out)


class GroupingCase(unittest.TestCase):
    def test_exact_and_suggested_groups(self):
        from core.grouping import suggest
        findings = [
            {"id": 1, "category": "xss", "url": "http://a.example/users/1?q=1",
             "parameter": "q", "metadata": {"method": "GET"}},
            {"id": 2, "category": "xss", "url": "http://a.example/users/2?q=1",
             "parameter": "q", "metadata": {"method": "GET"}},
            {"id": 3, "category": "xss", "url": "http://a.example/users/1?q=1",
             "parameter": "q", "metadata": {"method": "POST"}},
        ]
        groups = suggest(findings)
        exact = [g for g in groups if g["confidence"] == "exact"]
        suggested = [g for g in groups if g["confidence"] == "suggested"]
        self.assertEqual(exact[0]["finding_ids"], [1, 2])
        self.assertEqual(suggested[0]["ambiguous_on"], ["method"])
        self.assertEqual(suggested[0]["finding_ids"], [1, 2, 3])

    def test_identity_and_parameter_stay_distinct(self):
        from core.grouping import suggest, group_key
        a = {"id": 1, "category": "idor", "url": "http://a.example/acct", "parameter": "id",
             "metadata": {"method": "GET", "identity": "alice"}}
        b = {"id": 2, "category": "idor", "url": "http://a.example/acct", "parameter": "id",
             "metadata": {"method": "GET", "identity": "bob"}}
        c = {"id": 3, "category": "idor", "url": "http://a.example/acct", "parameter": "user_id",
             "metadata": {"method": "GET", "identity": "alice"}}
        self.assertNotEqual(group_key(a), group_key(b))   # tenant boundary preserved
        self.assertNotEqual(group_key(a), group_key(c))   # parameter name preserved
        groups = suggest([a, b, c])
        self.assertTrue(all(g["confidence"] == "suggested" for g in groups))
        self.assertTrue(all(set(g["ambiguous_on"]) & {"identity", "parameter"} for g in groups))

    def test_annotate_never_deletes(self):
        from core.grouping import suggest, annotate
        findings = [
            {"id": 1, "category": "xss", "url": "http://a/#x", "parameter": "q", "title": "t1"},
            {"id": 2, "category": "xss", "url": "http://a/#x", "parameter": "q", "title": "t2"},
        ]
        annotated = annotate(findings, suggest(findings))
        self.assertEqual(len(annotated), 2)
        self.assertNotIn("groups", findings[0].get("metadata") or {})   # originals untouched
        self.assertEqual(annotated[0]["metadata"]["groups"][0]["role"], "canonical")


class GroupStoreCase(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
        self.memory = _memory(self._tmp.name)

    def tearDown(self):
        self._tmp.cleanup()

    def test_manual_group_is_reversible_and_audited(self):
        from core.memory import Memory
        memory = self.memory
        f1 = memory.record_finding({"target": "lab", "category": "xss", "title": "a",
                                    "url": "http://lab/1", "metadata": {"poc": {}}})
        f2 = memory.record_finding({"target": "lab", "category": "xss", "title": "b",
                                    "url": "http://lab/2", "metadata": {"poc": {}}})
        group_id = memory.create_group("lab", [f2, f1], label="same root cause")
        groups = memory.list_groups("lab")
        self.assertEqual(len(groups), 1)
        self.assertEqual([m["finding_id"] for m in groups[0]["members"]], sorted([f1, f2]))
        self.assertEqual(memory.groups_for_finding(f1)[0]["label"], "same root cause")
        self.assertEqual(len(memory.list_findings("lab")), 2)      # nothing deleted

        self.assertTrue(memory.dissolve_group(group_id))
        self.assertEqual(memory.list_groups("lab"), [])
        self.assertEqual(len(memory.list_findings("lab")), 2)      # relationships restored
        actions = [h["action"] for h in memory.group_history(group_id)]
        self.assertEqual(actions, ["create", "dissolve"])

    def test_group_rejects_foreign_findings(self):
        from core.memory import Memory
        memory = self.memory
        fid = memory.record_finding({"target": "lab", "category": "xss", "title": "a",
                                     "url": "http://lab/", "metadata": {}})
        with self.assertRaises(ValueError):
            memory.create_group("lab", [fid])
        with self.assertRaises(ValueError):
            memory.create_group("other", [fid, fid + 1])


def _memory(root):
    from core.memory import Memory
    return Memory(Path(root) / "memory.db")


if __name__ == "__main__":
    unittest.main()
