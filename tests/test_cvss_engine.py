"""Unit tests for the CVSS 3.1 engine, recon permutations, fingerprints."""
from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))


class TestCVSS(unittest.TestCase):
    def test_spec_examples(self):
        from core.cvss import score_vector
        # canonical CVSS 3.1 spec example vectors
        self.assertEqual(score_vector("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"), 9.8)
        self.assertEqual(score_vector("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"), 10.0)
        self.assertEqual(score_vector("CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H"), 8.8)
        self.assertEqual(score_vector("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N"), 5.4)
        self.assertEqual(score_vector("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N"), 0.0)

    def test_parse_and_format(self):
        from core.cvss import parse_vector, format_vector
        m = parse_vector("AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N")
        self.assertEqual(m["AV"], "N")
        self.assertEqual(m["UI"], "R")
        self.assertEqual(format_vector(m),
                         "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N")

    def test_severity_band(self):
        from core.cvss import severity_band
        self.assertEqual(severity_band(9.8), "critical")
        self.assertEqual(severity_band(8.1), "high")
        self.assertEqual(severity_band(6.1), "medium")
        self.assertEqual(severity_band(3.9), "low")
        self.assertEqual(severity_band(0.0), "info")

    def test_vector_for_consistency(self):
        from core.cvss import vector_for, severity_band
        for cat, sev in [("rce", "critical"), ("sqli", "critical"),
                         ("xss", "medium"), ("open_redirect", "medium"),
                         ("idor", "high"), ("broken_auth", "high")]:
            vector, score = vector_for(cat, sev)
            self.assertTrue(vector.startswith("CVSS:3.1/"), vector)
            self.assertEqual(severity_band(score), sev,
                             f"{cat}: {vector} scored {score} not {sev}")

    def test_annotate(self):
        from core.cvss import annotate
        f = {"category": "rce", "severity": "critical", "cvss": 9.8, "metadata": {}}
        annotate(f)
        self.assertEqual(f["severity"], "critical")
        self.assertEqual(f["cvss"], 10.0)
        self.assertIn("cvss_vector", f["metadata"])


class TestPermutations(unittest.TestCase):
    def test_permutate(self):
        from agents.recon_agent import ReconAgent
        r = ReconAgent()
        subs = {"www.example.com", "example.com"}
        perms = r._permutate("example.com", subs)
        self.assertIn("api.www.example.com", perms)
        self.assertIn("www-dev.example.com", perms)
        self.assertIn("www1.example.com", perms)
        # never re-emit existing subs
        self.assertNotIn("www.example.com", perms)
        self.assertLessEqual(len(perms), 250)


class TestUrlFingerprints(unittest.TestCase):
    def test_roundtrip(self):
        import os
        from core.memory import Memory
        with tempfile.TemporaryDirectory() as td:
            m = Memory(Path(td) / "t.sqlite")
            self.assertIsNone(m.get_url_fingerprint("t", "https://a.com/"))
            m.set_url_fingerprint("t", "https://a.com/", "fp1")
            self.assertEqual(m.get_url_fingerprint("t", "https://a.com/"), "fp1")
            m.set_url_fingerprint("t", "https://a.com/", "fp2")
            self.assertEqual(m.get_url_fingerprint("t", "https://a.com/"), "fp2")


class TestCWE(unittest.TestCase):
    def test_map(self):
        from core.constants import CWE_MAP
        self.assertEqual(CWE_MAP["sqli"], ("CWE-89", "SQL Injection"))
        self.assertEqual(CWE_MAP["host_header"][0], "CWE-644")
        self.assertEqual(CWE_MAP["lfi"][0], "CWE-98")


class TestJwtConfusionHelpers(unittest.TestCase):
    def test_jwk_to_pem(self):
        from scanners.jwt_priv_esc import _rsa_pem_from_jwk, _b64u_enc
        from cryptography.hazmat.primitives.asymmetric import rsa
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        nums = key.public_key().public_numbers()
        n = _b64u_enc(nums.n.to_bytes((nums.n.bit_length() + 7) // 8, "big"))
        e = _b64u_enc(nums.e.to_bytes((nums.e.bit_length() + 7) // 8, "big"))
        pem = _rsa_pem_from_jwk(n, e)
        self.assertIsNotNone(pem)
        self.assertTrue(pem.startswith("-----BEGIN PUBLIC KEY-----"))

    def test_hs256_forge_verifies_with_pem(self):
        from scanners.jwt_priv_esc import _hs256_with_secret, _decompose
        import hashlib, hmac
        header = {"alg": "RS256", "typ": "JWT"}
        payload = {"sub": "123", "role": "admin"}
        pem = "-----BEGIN PUBLIC KEY-----\nMIIB...\n-----END PUBLIC KEY-----"
        token = _hs256_with_secret(header, payload, pem)
        h, p, sig = token.split(".")
        import json
        hdr = json.loads(__import__("scanners.jwt_priv_esc", fromlist=["_b64u_dec"])._b64u_dec(h))
        self.assertEqual(hdr["alg"], "HS256")
        import base64
        sig_b = base64.urlsafe_b64decode(sig + "=" * (-len(sig) % 4))
        expect = hmac.new(pem.encode(), f"{h}.{p}".encode(), hashlib.sha256).digest()
        self.assertEqual(sig_b, expect)


if __name__ == "__main__":
    unittest.main()
