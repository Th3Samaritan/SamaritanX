"""Insecure file upload detector.

Looks for forms with an enctype of multipart/form-data and at least one
file input. Submits a benign .svg payload (containing an inert script tag
that would only execute if the file is rendered as HTML) and checks for:
    * mime-type confusion (image/svg+xml served as text/html)
    * the upload endpoint returning a public URL we can fetch back
"""
from __future__ import annotations

import io
from typing import TYPE_CHECKING
from urllib.parse import urljoin

from core.utils import random_token

if TYPE_CHECKING:
    from core.orchestrator import Context

SVG_PAYLOAD = (
    '<?xml version="1.0" standalone="no"?>'
    '<svg xmlns="http://www.w3.org/2000/svg" onload="alert(1)">'
    '<text x="10" y="20">SamaritanX</text></svg>'
)


async def scan(ctx: "Context", url: str, params: list[str], method: str = "GET", form=None):
    findings: list[dict] = []
    if form is None:
        return findings
    file_inputs = [i for i in form.get("inputs", []) if i.get("type") == "file"]
    if not file_inputs:
        return findings

    fname = f"sx_{random_token(6)}.svg"
    files = {file_inputs[0]["name"]: (fname, SVG_PAYLOAD, "image/svg+xml")}
    data = {i["name"]: i.get("value") or random_token(4)
            for i in form["inputs"] if i.get("type") not in ("file", "submit")}

    # httpx accepts files via the request body — we use the underlying client
    try:
        resp = await ctx.http._client.post(form["action"], data=data, files=files,
                                           headers={"User-Agent": "SamaritanX/1.0"})
    except Exception as exc:
        return findings

    body = resp.text
    findings_added = False
    # See if the server publishes a URL to the uploaded file
    candidate = None
    for token in (fname, fname.rsplit(".", 1)[0]):
        idx = body.find(token)
        if idx != -1:
            start = body.rfind('"', 0, idx)
            end = body.find('"', idx)
            if start != -1 and end != -1:
                candidate = body[start + 1 : end]
                break
    if candidate:
        public = urljoin(form["action"], candidate)
        ev = await ctx.http.get(public)
        ctype = ev.response_headers.get("content-type", "").lower()
        if ev.status == 200 and ("html" in ctype or "svg" in ctype):
            findings.append({
                "category": "upload",
                "title": f"Insecure file upload accepts executable SVG ({form.get('action')})",
                "severity": "high", "cvss": 7.4,
                "url": form["action"],
                "evidence": f"Uploaded file fetched back from {public} with content-type {ctype}",
                "payload": fname,
                "request": f"POST {form['action']}",
                "response": body[:1500],
                "metadata": {"public_url": public, "ctype": ctype},
            })
            findings_added = True
    if not findings_added and resp.status_code in (200, 201):
        findings.append({
            "category": "upload",
            "title": f"File upload endpoint accepted SVG without rejection ({form.get('action')})",
            "severity": "low", "cvss": 3.1,
            "url": form["action"],
            "evidence": f"Status {resp.status_code} returned for SVG payload — "
                        "manual verification of MIME / extension policy recommended.",
            "metadata": {"status": resp.status_code},
        })
    return findings
