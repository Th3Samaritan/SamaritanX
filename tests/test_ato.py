"""Tests for the OOB-backed password-reset poisoning in account_takeover."""
from __future__ import annotations

import asyncio
import unittest

from scanners import account_takeover as ato
from core.proof_gate import is_verified


class _Ev:
    def __init__(self, status, body="", headers=None):
        self.status = status
        self.response_body = body
        self.response_headers = headers or {}
        self.error = None


class _HTTP:
    def __init__(self, get_ev=None, post_ev=None):
        self._get, self._post = get_ev, post_ev
        self.sent_get_headers = None
        self.sent_post_headers = None

    async def get(self, url, headers=None, **kw):
        self.sent_get_headers = headers
        return self._get or _Ev(200, "")

    async def request(self, method, url, data=None, headers=None, **kw):
        self.sent_post_headers = headers
        return self._post or _Ev(200, "")


class _FakeOOB:
    registered = True

    def __init__(self):
        self.registered_tokens = {}
        self.checked = []

    def token(self, n=8):
        return "abcd1234"

    def host_for(self, t):
        return f"{t}.oast.fun"

    def register(self, token, template):
        self.registered_tokens[token] = template

    async def check(self, token, *, wait=0.0):
        self.checked.append(token)
        return []


class _Ctx:
    def __init__(self, http, oob=None, aggressive=False):
        self.http = http
        self.oob = oob
        self.config = {"safety": {"aggressive": aggressive}}


URL = "https://app.example.com/account/forgot-password"


class TestHostPoisoning(unittest.TestCase):
    def test_reflection_uses_oob_host_and_ships_verified_poc(self):
        oob = _FakeOOB()
        # server echoes the injected host back into the body
        http = _HTTP(get_ev=_Ev(200, "reset link: https://abcd1234.oast.fun/reset?t=x"))
        ctx = _Ctx(http, oob=oob)
        out = asyncio.run(ato._host_header_poisoning(ctx, URL, None, aggressive=False))
        self.assertEqual(len(out), 1)
        f = out[0]
        self.assertEqual(f["metadata"]["detection"], "host_reflection")
        self.assertTrue(is_verified(f))                      # reflection = captured proof
        # the poisoned host we sent was the live OOB token, not the fake .test host
        self.assertEqual(http.sent_get_headers["Host"], "abcd1234.oast.fun")
        self.assertIn("abcd1234.oast.fun", f["metadata"]["poc"]["request"])

    def test_blind_accept_registers_oob_token_for_late_callback(self):
        oob = _FakeOOB()
        http = _HTTP(get_ev=_Ev(200, "no reflection here"),
                     post_ev=_Ev(202, "check your email"))
        ctx = _Ctx(http, oob=oob, aggressive=True)
        form = {"inputs": [{"name": "email"}]}
        out = asyncio.run(ato._host_header_poisoning(ctx, URL, form, aggressive=True))
        self.assertEqual(len(out), 1)
        self.assertEqual(out[0]["metadata"]["detection"], "host_blind")
        # a token was registered so pending_findings() can upgrade it, and we
        # polled once for an immediate callback
        self.assertIn("abcd1234", oob.registered_tokens)
        self.assertIn("abcd1234", oob.checked)

    def test_falls_back_to_static_host_without_oob(self):
        http = _HTTP(get_ev=_Ev(200, f"link https://{ato.EVIL}/reset"))
        ctx = _Ctx(http, oob=None)
        out = asyncio.run(ato._host_header_poisoning(ctx, URL, None, aggressive=False))
        self.assertEqual(len(out), 1)
        self.assertEqual(http.sent_get_headers["Host"], ato.EVIL)
        self.assertTrue(is_verified(out[0]))

    def test_no_reflection_no_aggressive_is_silent(self):
        http = _HTTP(get_ev=_Ev(200, "nothing reflected"))
        ctx = _Ctx(http, oob=_FakeOOB(), aggressive=False)
        out = asyncio.run(ato._host_header_poisoning(ctx, URL, None, aggressive=False))
        self.assertEqual(out, [])


if __name__ == "__main__":
    unittest.main()
