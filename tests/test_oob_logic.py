"""Tests for the OOB accumulation/sweep client and the business-logic engine."""
from __future__ import annotations

import asyncio
import unittest

from core.oob import OOBClient, build_oob_finding
from core.proof_gate import is_verified
from core import logic_sequences as ls


# --------------------------------------------------------------------------- #
# OOB client
# --------------------------------------------------------------------------- #
class _FakeBackend:
    """A fake interactsh backend that hands out batches of new events once."""
    def __init__(self, batches):
        self._batches = list(batches)
        self.registered = True
        self.domain = "abc.oast.fun"

    def url_for(self, t): return f"http://{t}.{self.domain}/"
    def host_for(self, t): return f"{t}.{self.domain}"

    async def poll(self):
        return self._batches.pop(0) if self._batches else []

    async def close(self): pass


def _ev(token, proto="http"):
    return {"full-id": f"{token}.abc.oast.fun", "protocol": proto,
            "remote-address": "203.0.113.9", "timestamp": "t"}


class TestOOBAccumulation(unittest.TestCase):
    def test_accumulates_and_matches_without_consuming(self):
        oob = OOBClient(_FakeBackend([[_ev("tok1")], [_ev("tok2")]]))
        # first drain gets tok1, second gets tok2; both stay queryable afterwards
        h1 = asyncio.run(oob.check("tok1"))
        self.assertTrue(h1)
        h2 = asyncio.run(oob.check("tok2"))
        self.assertTrue(h2)
        # tok1 still matches on a later query (non-consuming)
        self.assertTrue(asyncio.run(oob.check("tok1")))

    def test_no_cross_token_bleed(self):
        oob = OOBClient(_FakeBackend([[_ev("aaa")]]))
        self.assertTrue(asyncio.run(oob.check("aaa")))
        self.assertFalse(asyncio.run(oob.check("bbb")))

    def test_dedupes_repeated_events(self):
        oob = OOBClient(_FakeBackend([[_ev("dup")], [_ev("dup")]]))
        asyncio.run(oob.check("dup"))
        asyncio.run(oob.check("dup"))
        self.assertEqual(len(oob._events), 1)

    def test_pending_findings_sweep_emits_once(self):
        oob = OOBClient(_FakeBackend([[_ev("late")]]))
        oob.register("late", {"category": "ssrf", "url": "https://x/y",
                              "title": "Blind SSRF", "_detection": "oob"})
        asyncio.run(oob.check("late"))
        first = oob.pending_findings()
        self.assertEqual(len(first), 1)
        self.assertTrue(is_verified(first[0]))          # callback = verified proof
        self.assertEqual(oob.pending_findings(), [])     # not re-emitted

    def test_unfired_token_yields_no_finding(self):
        oob = OOBClient(_FakeBackend([[]]))
        oob.register("never", {"category": "rce", "url": "https://x", "_detection": "oob"})
        asyncio.run(oob.check("never"))
        self.assertEqual(oob.pending_findings(), [])

    def test_build_oob_finding_is_verified(self):
        f = build_oob_finding({"category": "xxe", "url": "https://x", "_detection": "oob"},
                              [_ev("t", "dns")])
        self.assertTrue(is_verified(f))
        self.assertEqual(f["metadata"]["detection"], "oob")


# --------------------------------------------------------------------------- #
# Business-logic oracles
# --------------------------------------------------------------------------- #
class TestLogicOracles(unittest.TestCase):
    def test_find_total(self):
        self.assertEqual(ls.find_total("Order total: 129.99 USD"), 129.99)
        self.assertEqual(ls.find_total("Grand total $1,250.00"), 1250.0)

    def test_price_tamper_proven(self):
        # legit 129.99, tampered to 0.01, server charged 0.01 -> proven
        self.assertTrue(ls.price_tamper_proven(129.99, 0.01, 0.01))

    def test_price_tamper_not_proven_when_unchanged(self):
        self.assertFalse(ls.price_tamper_proven(129.99, 0.01, 129.99))

    def test_price_tamper_not_proven_without_match(self):
        self.assertFalse(ls.price_tamper_proven(129.99, 0.01, 65.00))

    def test_coupon_reuse_proven(self):
        self.assertTrue(ls.coupon_reuse_proven("Discount applied -$10", "Discount applied -$10",
                                               200, 200))
        self.assertFalse(ls.coupon_reuse_proven("Discount applied", "Code already used", 200, 400))

    def test_step_skip_proven(self):
        self.assertTrue(ls.step_skip_proven(200, "Order confirmed, thank you"))
        self.assertFalse(ls.step_skip_proven(403, "forbidden"))

    def test_race_bypass_needs_observable_overconsumption(self):
        # balance moved by 5 across 5 successes, limit 1 -> proven
        self.assertTrue(ls.race_bypass_proven(100.0, 95.0, 5, allowed=1))
        # two 200s but no observable state change -> NOT proven (kills the FP)
        self.assertFalse(ls.race_bypass_proven(None, None, 5, allowed=1))
        # single success -> not proven
        self.assertFalse(ls.race_bypass_proven(100.0, 99.0, 1, allowed=1))


class _FakeEv:
    def __init__(self, status, body):
        self.status, self.response_body, self.error = status, body, None


class _SeqHTTP:
    """Serves scripted responses in order for POST/GET."""
    def __init__(self, responses):
        self._r = list(responses)

    async def post(self, url, data=None, **kw):
        return self._r.pop(0) if self._r else _FakeEv(200, "")

    async def get(self, url, params=None, **kw):
        return self._r.pop(0) if self._r else _FakeEv(200, "")


class _Ctx:
    def __init__(self, http):
        self.http = http


class TestLogicRunners(unittest.TestCase):
    def test_price_tamper_runner_reports_only_when_proven(self):
        http = _SeqHTTP([_FakeEv(200, "Order total: 129.99"),
                         _FakeEv(200, "Order total: 0.01")])
        form = {"action": "https://shop/checkout", "method": "POST",
                "inputs": [{"name": "price", "value": "129.99"}, {"name": "qty", "value": "1"}]}
        f = asyncio.run(ls.run_price_tamper(_Ctx(http), form))
        self.assertIsNotNone(f)
        self.assertTrue(is_verified(f))
        self.assertEqual(f["metadata"]["sequence"], "price_tamper")

    def test_price_tamper_runner_silent_when_unchanged(self):
        http = _SeqHTTP([_FakeEv(200, "Order total: 129.99"),
                         _FakeEv(200, "Order total: 129.99")])
        form = {"action": "https://shop/checkout", "method": "POST",
                "inputs": [{"name": "price", "value": "129.99"}]}
        self.assertIsNone(asyncio.run(ls.run_price_tamper(_Ctx(http), form)))


if __name__ == "__main__":
    unittest.main()
