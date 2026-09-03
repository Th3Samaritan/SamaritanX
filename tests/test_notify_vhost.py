"""Unit tests for notification payloads + vhost signatures."""
from __future__ import annotations

import sys
import unittest
from pathlib import Path
from types import SimpleNamespace

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))


class TestNotifyPayloads(unittest.TestCase):
    def test_slack_payload(self):
        from core.notify import _slack_payload
        p = _slack_payload("t.example.com", "scan complete", ["line1"], "critical")
        self.assertIn("SamaritanX", p["text"])
        self.assertEqual(p["attachments"][0]["color"], "danger")
        self.assertIn("line1", p["attachments"][0]["fields"][0]["value"])

    def test_discord_payload(self):
        from core.notify import _discord_payload
        p = _discord_payload("t", "new findings", ["l1", "l2"], "high")
        self.assertEqual(p["embeds"][0]["title"], "new findings")
        self.assertEqual(p["embeds"][0]["color"], 0xE67E22)
        self.assertIn("l2", p["embeds"][0]["description"])

    def test_telegram_text(self):
        from core.notify import _telegram_text
        t = _telegram_text("t", "title", ["a", "b"])
        self.assertIn("*SamaritanX*", t)
        self.assertIn("`t`", t)

    def test_wants_gate(self):
        from core.notify import _wants
        self.assertFalse(_wants({}, "scan_complete"))
        self.assertFalse(_wants({"enabled": True, "on": ["new_findings"]}, "scan_complete"))
        self.assertTrue(_wants({"enabled": True}, "scan_complete"))


class TestVhostSig(unittest.TestCase):
    def test_signature(self):
        from agents.recon_agent import ReconAgent
        ev = SimpleNamespace(status=200, response_body="<html><title>API</title>x</html>",
                             response_headers={"server": "nginx"})
        sig = ReconAgent._vhost_sig(ev)
        self.assertEqual(sig[0], 200)
        self.assertEqual(sig[2], "API")
        self.assertEqual(sig[3], "nginx")

    def test_signature_differs(self):
        from agents.recon_agent import ReconAgent
        a = SimpleNamespace(status=200, response_body="<html><title>A</title></html>",
                            response_headers={})
        b = SimpleNamespace(status=200, response_body="<html><title>B</title></html>",
                            response_headers={})
        self.assertNotEqual(ReconAgent._vhost_sig(a), ReconAgent._vhost_sig(b))


if __name__ == "__main__":
    unittest.main()
