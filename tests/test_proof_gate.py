"""Tests for the hard proof-gate: nothing reaches the report without a captured,
re-tested PoC. This is the false-positive kill-switch."""
from __future__ import annotations

import unittest

from core.proof_gate import poc_status, is_verified, partition
from scanners.request_smuggling import _same_site, _is_static, _confound_control


class TestProofGate(unittest.TestCase):
    def test_captured_response_poc_is_verified(self):
        f = {"category": "xss", "metadata": {"poc": {
            "verified": True, "response_excerpt": "<script>alert(1)</script>",
            "rationale": "reflected"}}}
        self.assertEqual(poc_status(f)[0], "verified")
        self.assertTrue(is_verified(f))

    def test_timing_only_poc_is_candidate(self):
        # a proof record with only timing samples and no captured response is NOT proof
        f = {"category": "smuggling", "metadata": {"poc": {
            "verified": True, "samples": [{"flagged_shape_s": 8.1, "inverse_shape_s": 0.2}],
            "rationale": "hung"}}}
        self.assertEqual(poc_status(f)[0], "candidate")
        self.assertFalse(is_verified(f))

    def test_reconstructed_curl_is_not_proof(self):
        # poc_curl / poc_repro are convenience repros, never accepted as proof
        f = {"category": "sqli", "metadata": {
            "poc_curl": "curl -sk 'https://x/?q=1'",
            "poc_repro": "curl ..."}}
        self.assertEqual(poc_status(f)[0], "candidate")

    def test_oob_callback_is_verified(self):
        f = {"category": "ssrf", "evidence": "interactsh callback received",
             "metadata": {"detection": "oob"}}
        self.assertTrue(is_verified(f))

    def test_validated_secret_is_verified(self):
        f = {"category": "secret_exposure", "metadata": {"validator_valid": True}}
        self.assertTrue(is_verified(f))

    def test_rejected_secret_is_candidate(self):
        f = {"category": "secret_exposure", "metadata": {"validator_valid": False}}
        self.assertFalse(is_verified(f))

    def test_takeover_is_verified(self):
        self.assertTrue(is_verified({"category": "subdomain_takeover", "metadata": {}}))

    def test_chain_needs_reproduced_escalation(self):
        self.assertTrue(is_verified({"category": "chain", "metadata": {"verified": True}}))
        self.assertFalse(is_verified({"category": "chain", "metadata": {"verified": False}}))

    def test_dropped_finding_is_candidate(self):
        f = {"category": "broken_auth", "metadata": {"revalidated": False}}
        self.assertFalse(is_verified(f))

    def test_partition_annotates_quarantine_reason(self):
        proven = {"category": "xss", "metadata": {"poc": {
            "verified": True, "response_status": 200, "rationale": "x"}}}
        junk = {"category": "smuggling", "metadata": {}}
        v, c = partition([proven, junk])
        self.assertEqual(v, [proven])
        self.assertEqual(len(c), 1)
        self.assertIn("quarantine_reason", c[0]["metadata"])


class TestSmugglingScopeHygiene(unittest.TestCase):
    def test_same_site(self):
        self.assertTrue(_same_site("www.arewagate.com", "arewagate.com"))
        self.assertTrue(_same_site("api.arewagate.com", "https://arewagate.com/x"))
        self.assertFalse(_same_site("api.segment.io", "arewagate.com"))
        self.assertFalse(_same_site("sdk-api-v1.singular.net", "https://arewagate.com"))

    def test_static_assets_skipped(self):
        self.assertTrue(_is_static("/vendor/livewire/livewire.min.js"))
        self.assertTrue(_is_static("/assets/app.css"))
        self.assertFalse(_is_static("/airtime/purchase"))

    def test_confound_control_has_no_transfer_encoding(self):
        ctrl = _confound_control("x.test", "/api")
        self.assertNotIn(b"Transfer-Encoding", ctrl)
        self.assertIn(b"Content-Length: 8", ctrl)


if __name__ == "__main__":
    unittest.main()
