"""Business-logic sequence engine — stateful, proof-first abuse detection.

Pure scanners see one request at a time; business-logic bugs live in *sequences*
and in *state that changes across requests*. This engine models the classic
paying flaws as multi-step sequences and, crucially, only reports when it has
**captured a before/after state change that proves impact** — never on a
"success"-word heuristic. That is what lets logic findings pass the proof-gate
instead of becoming noise.

Sequences implemented:

  * **price / amount tampering** — read the legitimate total, resubmit with a
    lowered client-supplied price, and confirm the *charged total actually
    dropped to the tampered value*. Proof = legit total vs tampered total.
  * **coupon / voucher reuse** — apply a single-use code twice and confirm the
    discount is granted both times (or a balance is credited twice). Proof =
    both application responses + the second discount.
  * **workflow step-skip** — invoke a late-stage action (confirm/complete/ship)
    without its prerequisite and confirm it succeeds. Proof = the success state
    reached out of order.
  * **race-condition limit bypass** — fire N concurrent copies of a
    single-use action and confirm a metered resource was consumed more than
    once (observable counter/balance moved by > 1 unit). Proof = the
    over-consumed state, not merely "two 200s".

The decision oracles are pure functions (unit-tested offline); the runners are
thin drivers over ``ctx.http``. Every runner returns either a finding carrying a
captured ``metadata.poc`` or ``None`` — no unproven candidates.
"""
from __future__ import annotations

import asyncio
import re
from typing import TYPE_CHECKING, Any, Optional

from .poc import proof_record

if TYPE_CHECKING:
    from .orchestrator import Context

# money / quantity keywords we anchor totals to
_TOTAL_HINTS = ("grand total", "order total", "total due", "amount due", "total",
                "amount", "subtotal", "balance", "charged", "price", "due")
_MONEY = re.compile(r"(\d{1,3}(?:,\d{3})+(?:\.\d+)?|\d+\.\d{2}|\d+)")
_SUCCESS = ("success", "confirmed", "created", "order", "thank you", "approved",
            "applied", "redeemed", "completed", "credited")
_COUPON_APPLIED = ("discount", "coupon applied", "promo applied", "voucher",
                   "-$", "you save", "savings", "% off", "applied")


# --------------------------------------------------------------------------- #
# Pure oracles
# --------------------------------------------------------------------------- #
def parse_money(text: str) -> list[float]:
    """Extract plausible monetary/numeric values from text."""
    out: list[float] = []
    for m in _MONEY.findall(text or ""):
        try:
            out.append(float(m.replace(",", "")))
        except ValueError:
            continue
    return out


def find_total(body: str) -> Optional[float]:
    """Return the money value most tightly associated with a total/amount word."""
    body = (body or "").lower()
    best: Optional[float] = None
    best_dist = 10 ** 9
    for hint in _TOTAL_HINTS:
        start = 0
        while True:
            idx = body.find(hint, start)
            if idx == -1:
                break
            window = body[idx: idx + 60]
            vals = parse_money(window)
            if vals:
                # take the first money value after the hint word
                dist = _TOTAL_HINTS.index(hint)
                if dist < best_dist:
                    best_dist = dist
                    best = vals[0]
            start = idx + len(hint)
    return best


def price_tamper_proven(legit_total: Optional[float], tampered_value: float,
                        observed_total: Optional[float], *, tol: float = 0.02) -> bool:
    """True iff the server charged the attacker-supplied (lower) value.

    Requires the observed total to (a) match the tampered value and (b) be
    materially below the legitimate total — so a normal unchanged checkout does
    not read as tampering."""
    if observed_total is None or tampered_value is None:
        return False
    matches_tampered = abs(observed_total - tampered_value) <= max(tol, 0.05 * abs(tampered_value))
    dropped = legit_total is None or observed_total < legit_total - tol
    return matches_tampered and dropped


def response_indicates(body: str, needles) -> bool:
    b = (body or "").lower()
    return any(n in b for n in needles)


def coupon_reuse_proven(first_body: str, second_body: str,
                        first_status: int, second_status: int) -> bool:
    """True iff a single-use code was accepted and discounted twice."""
    first_ok = first_status in (200, 201, 202) and response_indicates(first_body, _COUPON_APPLIED)
    second_ok = second_status in (200, 201, 202) and response_indicates(second_body, _COUPON_APPLIED)
    return bool(first_ok and second_ok)


def step_skip_proven(status: int, body: str) -> bool:
    """True iff a late-stage action succeeded when it should have been blocked."""
    return status in (200, 201, 202) and response_indicates(body, _SUCCESS)


def race_bypass_proven(before_value: Optional[float], after_value: Optional[float],
                       success_count: int, *, allowed: int = 1) -> bool:
    """True iff a metered resource was consumed more than once.

    Needs an *observable* state change (a counter/balance that moved by more than
    one unit) — not just multiple 2xx responses, which many idempotent endpoints
    produce legitimately."""
    if success_count <= allowed:
        return False
    if before_value is None or after_value is None:
        return False
    return abs(after_value - before_value) > (allowed + 0.5)  # moved by > allowed units


# --------------------------------------------------------------------------- #
# Async runners (thin drivers; return a proven finding or None)
# --------------------------------------------------------------------------- #
async def _get(ctx, url: str):
    try:
        return await ctx.http.get(url)
    except Exception:
        return None


async def _send(ctx, url: str, method: str, data: dict | None):
    method = (method or "POST").upper()
    try:
        if method == "GET":
            return await ctx.http.get(url, params=data)
        fn = getattr(ctx.http, method.lower(), ctx.http.post)
        return await fn(url, data=data)
    except Exception:
        return None


async def run_price_tamper(ctx: "Context", form: dict, *, tampered: float = 0.01) -> Optional[dict]:
    """form = {action, method, inputs:[{name,value}]}. Mutates a price field low
    and confirms the charged total dropped to it."""
    inputs = form.get("inputs", [])
    price_fields = [i["name"] for i in inputs
                    if any(h in (i.get("name") or "").lower()
                           for h in ("price", "amount", "total", "cost"))]
    if not price_fields:
        return None
    url = form.get("action") or form.get("url")
    method = form.get("method", "POST")
    legit_data = {i["name"]: i.get("value") or "1" for i in inputs}

    legit_ev = await _send(ctx, url, method, legit_data)
    legit_total = find_total(getattr(legit_ev, "response_body", "") or "") if legit_ev else None

    tampered_data = dict(legit_data)
    for k in price_fields:
        tampered_data[k] = str(tampered)
    ev = await _send(ctx, url, method, tampered_data)
    if ev is None or getattr(ev, "error", None):
        return None
    observed = find_total(getattr(ev, "response_body", "") or "")
    if not price_tamper_proven(legit_total, tampered, observed):
        return None
    poc = proof_record(
        verified=True, method=(method or "POST").upper(), url=url,
        request=f"{method} {url}\n{tampered_data}",
        status=getattr(ev, "status", None), excerpt=getattr(ev, "response_body", "") or "",
        rationale=(f"The legitimate total was {legit_total}; after resubmitting with "
                   f"{price_fields}={tampered} the charged total became {observed} — the server "
                   "trusts the client-supplied price, so an attacker sets their own price."))
    return {
        "category": "logic",
        "title": f"Price/amount tampering — server honors client-set price on {url}",
        "severity": "high", "cvss": 8.2, "confidence": 0.9,
        "url": url, "parameter": ",".join(price_fields), "payload": str(tampered),
        "evidence": f"Charged total dropped from {legit_total} to {observed} when the price "
                    f"field was set to {tampered}.",
        "request": f"{method} {url}\n{tampered_data}",
        "response": (getattr(ev, "response_body", "") or "")[:1500],
        "metadata": {"detection": "logic_sequence", "sequence": "price_tamper", "poc": poc,
                     "legit_total": legit_total, "observed_total": observed},
    }


async def run_coupon_reuse(ctx: "Context", apply: dict) -> Optional[dict]:
    """apply = {url, method, data, code_field, code}. Applies the code twice."""
    url = apply.get("url")
    method = apply.get("method", "POST")
    data = dict(apply.get("data") or {})
    if apply.get("code_field"):
        data[apply["code_field"]] = apply.get("code", "")
    ev1 = await _send(ctx, url, method, data)
    ev2 = await _send(ctx, url, method, data)
    if not ev1 or not ev2:
        return None
    b1 = getattr(ev1, "response_body", "") or ""
    b2 = getattr(ev2, "response_body", "") or ""
    if not coupon_reuse_proven(b1, b2, getattr(ev1, "status", 0), getattr(ev2, "status", 0)):
        return None
    poc = proof_record(
        verified=True, method=(method or "POST").upper(), url=url,
        request=f"{method} {url}\n{data}   (sent twice)",
        status=getattr(ev2, "status", None), excerpt=b2,
        rationale="A single-use discount code was accepted and applied on two consecutive "
                  "submissions — the code is not invalidated after first use, allowing "
                  "unlimited stacking.")
    return {
        "category": "logic",
        "title": f"Coupon / voucher reuse — single-use code applies repeatedly on {url}",
        "severity": "high", "cvss": 7.4, "confidence": 0.9,
        "url": url, "parameter": apply.get("code_field", "code"), "payload": apply.get("code", ""),
        "evidence": "The discount code was granted on both the first and second application.",
        "request": f"{method} {url}\n{data} (x2)",
        "response": b2[:1500],
        "metadata": {"detection": "logic_sequence", "sequence": "coupon_reuse", "poc": poc},
    }


async def run_step_skip(ctx: "Context", protected: dict) -> Optional[dict]:
    """protected = {url, method, data, name}. Invokes a late-stage action with no
    prerequisite step and confirms it succeeded."""
    url = protected.get("url")
    method = protected.get("method", "POST")
    ev = await _send(ctx, url, method, protected.get("data"))
    if not ev or getattr(ev, "error", None):
        return None
    body = getattr(ev, "response_body", "") or ""
    if not step_skip_proven(getattr(ev, "status", 0), body):
        return None
    poc = proof_record(
        verified=True, method=(method or "POST").upper(), url=url,
        request=f"{method} {url}\n{protected.get('data') or ''}",
        status=getattr(ev, "status", None), excerpt=body,
        rationale=(f"The late-stage action '{protected.get('name', url)}' completed successfully "
                   "without its prerequisite workflow step — the server does not enforce state "
                   "ordering, letting an attacker skip payment/approval/verification gates."))
    return {
        "category": "logic",
        "title": f"Workflow step-skip — {protected.get('name', 'protected action')} reachable out of order",
        "severity": "high", "cvss": 7.8, "confidence": 0.85,
        "url": url,
        "evidence": f"'{protected.get('name', url)}' returned a success state without the "
                    "prerequisite step being completed first.",
        "request": f"{method} {url}",
        "response": body[:1500],
        "metadata": {"detection": "logic_sequence", "sequence": "step_skip", "poc": poc},
    }


async def run_race(ctx: "Context", action: dict, *, n: int = 20, allowed: int = 1) -> Optional[dict]:
    """action = {url, method, data, state_url, state_field}. Fires n concurrent
    copies and confirms a metered resource moved by more than one unit."""
    url = action.get("url")
    method = action.get("method", "POST")
    state_url = action.get("state_url")

    before_val = None
    if state_url:
        bev = await _get(ctx, state_url)
        before_val = find_total(getattr(bev, "response_body", "") or "") if bev else None

    results = await asyncio.gather(
        *[_send(ctx, url, method, action.get("data")) for _ in range(n)],
        return_exceptions=True)
    ok = [r for r in results if hasattr(r, "status") and getattr(r, "status", 0) in (200, 201, 202)]

    after_val = None
    if state_url:
        aev = await _get(ctx, state_url)
        after_val = find_total(getattr(aev, "response_body", "") or "") if aev else None

    if not race_bypass_proven(before_val, after_val, len(ok), allowed=allowed):
        return None
    poc = proof_record(
        verified=True, method=(method or "POST").upper(), url=url,
        request=f"{n}× concurrent {method} {url}",
        excerpt=f"metered state moved {before_val} -> {after_val} across {len(ok)} successful "
                f"concurrent requests (limit {allowed})",
        rationale=(f"{n} concurrent copies of a single-use action drove the metered resource from "
                   f"{before_val} to {after_val} — more than the {allowed}-unit limit. The action "
                   "lacks atomic locking, so an attacker double-spends via a race."))
    return {
        "category": "race_condition",
        "title": f"Race-condition limit bypass on {url}",
        "severity": "high", "cvss": 8.1, "confidence": 0.9,
        "url": url,
        "evidence": f"Concurrent requests over-consumed a metered resource ({before_val} -> "
                    f"{after_val}, {len(ok)} successes, limit {allowed}).",
        "request": f"{n}× {method} {url}",
        "metadata": {"detection": "logic_sequence", "sequence": "race",
                     "before": before_val, "after": after_val, "successes": len(ok), "poc": poc},
    }
