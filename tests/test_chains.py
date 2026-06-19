"""Tests for impact escalation + the relationship-aware chaining engine."""
from __future__ import annotations

import asyncio
import types
import unittest

from core.escalation import sensitive_hits, severity_for
from core.chains import (build_chains, _origin, _ssrf_is_metadata,
                         _affinity, _candidate_score)


def _f(category, url, severity="medium", cvss=5.0, **extra):
    d = {"category": category, "url": url, "severity": severity, "cvss": cvss,
         "title": f"{category} on {url}", "_id": id((category, url))}
    d.update(extra)
    return d


def _run(coro):
    return asyncio.run(coro)


class TestEscalation(unittest.TestCase):
    def test_jwt_is_critical(self):
        body = '{"token": "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0In0.abcdefabcdefabcd"}'
        hits = sensitive_hits(body, {})
        kinds = [k for k, _ in hits]
        self.assertIn("jwt", kinds)
        self.assertEqual(severity_for(hits)[0], "critical")

    def test_pii_is_high(self):
        hits = sensitive_hits('{"email": "x@y.com", "phone": "555"}', {})
        sev, _ = severity_for(hits)
        self.assertIn(sev, ("high", "critical"))

    def test_empty(self):
        self.assertEqual(sensitive_hits("nothing here", {}), [])
        self.assertIsNone(severity_for([]))

    def test_set_cookie_session(self):
        hits = sensitive_hits("ok", {"set-cookie": "sessionid=abc123; HttpOnly"})
        self.assertIn("session_cookie", [k for k, _ in hits])


class TestChaining(unittest.TestCase):
    DUMMY = types.SimpleNamespace()

    def test_same_host_chain_forms(self):
        findings = [_f("oauth", "https://app.acme.com/oauth/authorize"),
                    _f("xss", "https://app.acme.com/search?q=1", severity="high")]
        chains = _run(build_chains(self.DUMMY, findings))
        cats = [c["metadata"]["chain"] for c in chains]
        self.assertIn("oauth_xss_token_theft", cats)
        chain = next(c for c in chains if c["metadata"]["chain"] == "oauth_xss_token_theft")
        self.assertEqual(chain["category"], "chain")
        self.assertEqual(chain["severity"], "critical")

    def test_cross_host_does_not_chain(self):
        # oauth and xss on different registered domains must not chain
        findings = [_f("oauth", "https://app.acme.com/oauth/authorize"),
                    _f("xss", "https://unrelated.evilcorp.net/x")]
        chains = _run(build_chains(self.DUMMY, findings))
        self.assertNotIn("oauth_xss_token_theft",
                         [c["metadata"]["chain"] for c in chains])

    def test_idor_massassign(self):
        findings = [_f("idor", "https://api.acme.com/v1/users/1"),
                    _f("api", "https://api.acme.com/v1/users/1", severity="critical")]
        chains = _run(build_chains(self.DUMMY, findings))
        self.assertIn("idor_massassign_priv_esc",
                      [c["metadata"]["chain"] for c in chains])

    def test_ssrf_metadata_gate(self):
        # plain SSRF (no metadata reached) should not auto-escalate to the
        # IAM-credential chain
        plain = [_f("ssrf", "https://api.acme.com/fetch", severity="high",
                    metadata={"detection": "in-band"})]
        self.assertNotIn("ssrf_metadata_rce",
                         [c["metadata"]["chain"] for c in _run(build_chains(self.DUMMY, plain))])
        # SSRF that reached cloud metadata should
        meta = [_f("ssrf", "https://api.acme.com/fetch", severity="critical",
                   metadata={"indicator": "aws_metadata"},
                   evidence="response includes ami-id")]
        self.assertIn("ssrf_metadata_rce",
                      [c["metadata"]["chain"] for c in _run(build_chains(self.DUMMY, meta))])

    def test_origin_helper(self):
        self.assertEqual(_origin("https://a.test:443/x?y=1"), "https://a.test:443")

    def test_ssrf_metadata_detect(self):
        self.assertTrue(_ssrf_is_metadata({"metadata": {"indicator": "aws_metadata"}}))
        self.assertFalse(_ssrf_is_metadata({"metadata": {"detection": "in-band"}}))


class TestCandidateSelection(unittest.TestCase):
    DUMMY = types.SimpleNamespace()

    def test_affinity_shared_prefix_and_id(self):
        a = _f("idor", "https://api.acme.com/v1/users/42")
        b = _f("api", "https://api.acme.com/v1/users/42")
        c = _f("api", "https://api.acme.com/v1/posts/9")
        self.assertGreater(_affinity(a, b), _affinity(a, c))

    def test_candidate_score_rewards_proof(self):
        leaky = _f("cors", "https://x/a", severity="medium", cvss=6.1,
                   metadata={"leaked": ["jwt"]})
        plain = _f("cors", "https://x/b", severity="medium", cvss=6.1)
        self.assertGreater(_candidate_score(leaky), _candidate_score(plain))

    def test_picks_affine_pair_among_candidates(self):
        # two IDOR endpoints; only one shares the object with the mass-assign API
        findings = [
            _f("idor", "https://api.acme.com/v1/users/42", severity="high"),
            _f("idor", "https://api.acme.com/v1/posts/9", severity="high"),
            _f("api", "https://api.acme.com/v1/users/42", severity="critical",
               title="API6 mass assignment"),
        ]
        chains = _run(build_chains(self.DUMMY, findings))
        chain = next(c for c in chains if c["metadata"]["chain"] == "idor_massassign_priv_esc")
        # the chosen idor component must be the one sharing /users/42
        self.assertIn("/users/42", chain["request"])
        self.assertNotIn("/posts/9", chain["request"])

    def test_unverified_emits_single_best(self):
        # one oauth + two xss on same host → exactly one structural chain
        findings = [
            _f("oauth", "https://app.acme.com/oauth/authorize"),
            _f("xss", "https://app.acme.com/a", severity="high"),
            _f("xss", "https://app.acme.com/b", severity="medium"),
        ]
        chains = _run(build_chains(self.DUMMY, findings))
        xss_chains = [c for c in chains if c["metadata"]["chain"] == "oauth_xss_token_theft"]
        self.assertEqual(len(xss_chains), 1)


if __name__ == "__main__":
    unittest.main()
