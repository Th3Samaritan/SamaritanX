"""Walkthrough generator.

For each finding, attaches three plain-English paragraphs answering:
    * What did the scanner do, step by step?
    * Why does this vulnerability exist (root cause class)?
    * How was it discovered (which signal triggered the detection)?

These paragraphs are merged into the Markdown report when the operator
runs in walkthrough mode. The agent is also useful standalone — it
populates `walkthrough`, `impact`, and `remediation` fields on findings
so reports always contain a complete narrative even without an LLM.
"""
from __future__ import annotations

from typing import Any


CATEGORY_NARRATIVE = {
    "sqli": {
        "what": (
            "SamaritanX injected each candidate parameter with a curated set of SQL "
            "tautologies, error-triggering quotes, UNION skeletons, and time-delay "
            "payloads. Each request was sent twice — once as a 'true' branch "
            "(`AND 1=1`) and once as a 'false' branch (`AND 1=2`) — to compare "
            "response sizes. For blind targets it then fired sleep-based payloads "
            "tuned to MySQL, Postgres, and MSSQL syntax."
        ),
        "why": (
            "User-controlled data is being concatenated directly into a SQL query "
            "without parameterization. The database engine cannot tell the supplied "
            "value from the surrounding query, so attacker syntax becomes part of "
            "the executed statement."
        ),
        "how": (
            "Detection fired on one of three signals: (a) a known DBMS error "
            "string in the body, (b) a measurable response-length delta between "
            "the true/false branches, or (c) a server-side delay that matched the "
            "injected SLEEP / WAITFOR interval within ±0.5s."
        ),
        "impact": (
            "Full read/write access to the application database is plausible. An "
            "attacker can dump credentials, modify business records, escalate to "
            "the host via UDFs / xp_cmdshell, or pivot to other services that "
            "trust the database account."
        ),
        "remediation": (
            "Migrate every query that touches user data to parameterized prepared "
            "statements. Reject input that doesn't match a strict allow-list when "
            "an identifier (table/column) must be dynamic. Apply a least-privilege "
            "DB role for the application — no DDL, no FILE / xp_cmdshell. Add a "
            "WAF rule as defence-in-depth, never as the primary control."
        ),
    },
    "xss": {
        "what": "A token-bearing marker was first injected to confirm reflection. "
                "If it surfaced unencoded, the scanner escalated to active payloads "
                "covering script tags, event handlers, and template-engine syntax.",
        "why": "Untrusted input is being emitted into HTML / JS context without "
               "context-appropriate encoding.",
        "how": "Detection asserts the literal payload appears in the response body "
               "without HTML-entity encoding, ruling out the safe path.",
        "impact": "An attacker can run JavaScript in the victim's authenticated "
                  "browser — read cookies (when not HttpOnly), make requests as "
                  "the user, or stage social-engineering UI overlays.",
        "remediation": "Use a templating engine that auto-escapes by default. Set "
                       "Content-Security-Policy with no `unsafe-inline`. HttpOnly "
                       "+ Secure on session cookies. Validate input as data, "
                       "encode at output by context (HTML, JS, URL, CSS).",
    },
    "ssrf": {
        "what": "URL-shaped parameters were swapped for internal addresses, "
                "decimal/hex IP encodings, cloud metadata endpoints, and gopher/"
                "file/dict schemes.",
        "why": "Server-side fetcher accepts and dereferences attacker-controlled "
               "URLs without an allow-list of permitted destinations.",
        "how": "The response contained an indicator unique to the requested "
               "internal resource (e.g. AWS `ami-id`, `/etc/passwd` first line, "
               "Redis `redis_version`).",
        "impact": "Attacker can reach internal-only services, exfiltrate cloud "
                  "IAM credentials from the metadata endpoint, and pivot through "
                  "the application's network position.",
        "remediation": "Disable redirect following inside server-side fetchers. "
                       "Resolve the hostname yourself and reject RFC1918 / link-"
                       "local / loopback. Disable unused URL schemes. On AWS, "
                       "enforce IMDSv2.",
    },
    "rce": {
        "what": "Each parameter received OS-command separators (`;`, `|`, `` ` ``, "
                "`$()`) followed by an `echo` of a unique marker. A blind branch "
                "then fired `;sleep 5;` and measured response time.",
        "why": "User input is being concatenated into a shell invocation rather "
               "than passed as positional arguments to `execve`.",
        "how": "Either the marker echoed back in-band, or the response was "
               "delayed by ≥4.5s after the sleep payload.",
        "impact": "Full host compromise within the application's process — read "
                  "files, exfiltrate environment secrets, lateral movement.",
        "remediation": "Stop shelling out. Use language-native APIs (e.g. "
                       "`subprocess.run([...], shell=False)`). When you must, "
                       "use a strict allow-list of binaries and pass arguments "
                       "as a list, never via string concatenation.",
    },
    "ssti": {
        "what": "Template metacharacters (`{{ }}`, `${ }`, `<%= %>`, `#{ }`) "
                "carrying `7*7` were injected into reflective parameters.",
        "why": "User input is passed through the template renderer instead of "
               "being treated as data inside an already-compiled template.",
        "how": "The arithmetic product (49 / 7777777) appeared in the response "
               "while the unevaluated expression did not.",
        "impact": "Template engines expose access to host objects — most lead to "
                  "RCE within a few payload iterations.",
        "remediation": "Never call `render_string(user_input)` — render only "
                       "pre-defined templates and pass user data as the "
                       "context dict.",
    },
    "idor": {
        "what": "Numeric / UUID identifiers in URL parameters were swapped to "
                "neighbouring values and the responses were compared.",
        "why": "Authorization is enforced at the route level only, not at the "
               "object level — any authenticated user can address any object.",
        "how": "The altered identifier produced a response of similar size and "
               "200 status to the original — strong signal of leaked data.",
        "impact": "Cross-tenant data access. Severity depends on what the object "
                  "represents (PII, payment, internal admin).",
        "remediation": "Enforce object-ownership checks server-side on every "
                       "request. Use unguessable identifiers (UUIDv4) as a "
                       "speed bump, not as the security boundary.",
    },
    "csrf": {
        "what": "State-changing forms were inspected for anti-CSRF tokens; the "
                "Set-Cookie headers were checked for SameSite hardening.",
        "why": "Browsers happily attach the user's session cookie to any cross-"
               "site request — without a token or SameSite, attacker pages can "
               "trigger authenticated actions.",
        "how": "No token-shaped field was present and cookies lacked SameSite=Strict/Lax.",
        "impact": "Attacker can perform any state-changing action the victim "
                  "could — change email, transfer funds, etc.",
        "remediation": "SameSite=Lax (or Strict) on session cookies. Add a per-"
                       "session synchronizer token to every state-changing form. "
                       "Verify Origin / Referer for sensitive endpoints.",
    },
    "upload": {
        "what": "An SVG file containing an `onload` handler was uploaded; the "
                "returned URL (when present) was fetched back to inspect Content-"
                "Type.",
        "why": "Upload pipeline trusts the client-supplied MIME / extension and "
               "serves the file with executable rendering rules.",
        "how": "Either the response advertised the upload URL and it was served "
               "as text/html or image/svg+xml on a content origin shared with the "
               "app.",
        "impact": "Stored XSS at minimum, RCE if the application supports server-"
                  "side handlers (.phtml, .htaccess, .jsp).",
        "remediation": "Re-encode images via a server-side library and discard "
                       "metadata. Serve uploads from a separate sandbox origin "
                       "(e.g. usercontent.example.com). Strict MIME / extension "
                       "allow-list, never deny-list.",
    },
    "open_redirect": {
        "what": "Redirect-style parameters were replaced with attacker-host URLs "
                "(scheme tricks, double-slashes, @-injection).",
        "why": "Application performs `Location: $param` without normalizing or "
               "matching against an allow-list of hosts.",
        "how": "A 30x response carried `Location:` pointing to the attacker-"
               "controlled host.",
        "impact": "Phishing, OAuth code theft when the open redirect is on a "
                  "trusted `redirect_uri`, bypass of SSO link checks.",
        "remediation": "Always redirect to a server-side allow-list of paths or "
                       "hosts; reject anything else.",
    },
    "cors": {
        "what": "Requests with a forged `Origin` header were sent and the ACAO "
                "/ ACA-Credentials response headers were inspected.",
        "why": "CORS policy reflects the request Origin instead of validating "
               "against an allow-list.",
        "how": "ACAO echoed `https://evil.samaritanx.test`, often together with "
               "`Access-Control-Allow-Credentials: true`.",
        "impact": "Any origin can read the response body in the victim's "
                  "browser — full session-bound data leakage.",
        "remediation": "Hard-code the allow-list of origins. Never reflect the "
                       "request Origin without validation. Don't combine `*` "
                       "with credentials.",
    },
    "cache_poisoning": {
        "what": "Unkeyed headers (X-Forwarded-Host, X-Host, Forwarded) were "
                "sent with an attacker marker; the URL was then re-fetched "
                "clean to see if the poisoned value persisted.",
        "why": "The cache key omits a header that the application reflects into "
               "the response, so the poisoned response is served to other users.",
        "how": "The attacker marker survived in a clean response — confirming "
               "the cached entry was poisoned.",
        "impact": "Stored XSS at scale, mass redirects, or denial-of-service via "
                  "cache pollution.",
        "remediation": "Add reflected headers to the cache key (Vary or upstream "
                       "config). Strip or normalize untrusted headers at the "
                       "edge. Don't reflect request headers into responses.",
    },
    "api": {
        "what": "Endpoints were probed for OWASP API Top-10 issues — excessive "
                "data exposure, mass assignment, missing rate limits, JWT "
                "weakness, and sibling-version sprawl.",
        "why": "API designers often expose entire model instances and trust "
               "client-supplied fields without per-route filtering.",
        "how": "JSON responses contained sensitive keys, privileged fields were "
               "honored on POST, JWTs accepted alg=none / weak HMAC, or auth "
               "endpoints lacked 429 backoff.",
        "impact": "Account takeover, privilege escalation, and credential "
                  "stuffing — the highest-impact class of API bugs.",
        "remediation": "Use response DTOs (allow-list) instead of model "
                       "serialization. Strip privileged fields server-side. "
                       "Enforce JWT alg pinning and short expiry. Apply rate "
                       "limits to authentication endpoints.",
    },
    "prompt_injection": {
        "what": "LLM-shaped endpoints received jailbreak / system-prompt-"
                "override payloads carrying a unique sentinel, plus a direct "
                "system-prompt exfiltration request.",
        "why": "User input shares a single instruction channel with the system "
               "prompt — the model cannot reliably distinguish them.",
        "how": "The sentinel string surfaced verbatim in the model's reply, "
               "or the model emitted text shaped like its hidden system prompt.",
        "impact": "Bypass of all model-side guardrails — includes harmful "
                  "content generation, exfiltration of internal context, and "
                  "abuse of any tools the agent can call (SSRF, file read, "
                  "purchase actions).",
        "remediation": "Treat prompts as untrusted input. Use structured tool "
                       "calling with server-side validation of every argument. "
                       "Don't grant the agent the ability to fetch arbitrary "
                       "URLs. Filter outputs as well as inputs. Adopt a "
                       "defence-in-depth posture (constitutional rules, "
                       "external classifiers, human-in-the-loop for high-impact "
                       "actions).",
    },
    "race_condition": {
        "what": "25 concurrent POSTs were fired at endpoints whose names "
                "suggested one-shot operations (transfer, redeem, vote).",
        "why": "Server lacks transactional or distributed locking around the "
               "state change, so multiple workers complete the action before "
               "uniqueness is enforced.",
        "how": "More than one of the concurrent requests succeeded with a 2xx.",
        "impact": "Duplicate spend, double-redemption of one-time tokens, "
                  "balance inflation.",
        "remediation": "Wrap the critical section in a database transaction "
                       "with row-level locking, or use a Redis lock keyed on "
                       "(user_id, action). Make the action idempotent with a "
                       "client-supplied request id.",
    },
    "logic": {
        "what": "Form fields named `price`, `amount`, `total` etc. were "
                "rewritten to a trivially-low value before submission.",
        "why": "Pricing is being sourced from the client request rather than "
               "looked up server-side from a trusted catalogue.",
        "how": "The mutated request returned a success-shaped response.",
        "impact": "Direct financial loss — orders placed at attacker prices.",
        "remediation": "Compute prices on the server from authoritative data; "
                       "never trust client-supplied amounts.",
    },
    "exposure": {
        "what": "A list of sensitive paths (`.env`, `.git/config`, "
                "`/actuator/heapdump`, etc.) was probed anonymously.",
        "why": "The path is reachable because the deployment ships build / "
               "operational artefacts to the production webroot.",
        "how": "HTTP 200 returned with a substantive body for a path that "
               "should not exist publicly.",
        "impact": "Source code, secrets, or internal state are exposed.",
        "remediation": "Remove operational endpoints from production. Block "
                       "dotfiles at the reverse proxy. Rotate any secrets that "
                       "may have been read.",
    },
    "broken_auth": {
        "what": "Admin-shaped URLs were re-issued with no session header.",
        "why": "Authorization is enforced only on the navigation surface "
               "(menu visibility) rather than the endpoint itself.",
        "how": "The endpoint returned 200 with a substantive body anonymously.",
        "impact": "Full administrative access without credentials.",
        "remediation": "Enforce authorization in middleware. Default-deny.",
    },
    "secret_exposure": {
        "what": "Static response bodies were scanned with regex rules for "
                "AWS / GCP / Slack / Stripe / GitHub tokens, JWTs, private "
                "keys, and Mongo URIs.",
        "why": "A build step shipped a credential into the response payload "
               "(JS bundle, sourcemap, config endpoint).",
        "how": "A regex matched the response body.",
        "impact": "The credential should be considered compromised — anyone "
                  "browsing the page sees it.",
        "remediation": "Rotate immediately. Move secrets to server-side "
                       "config. Add a CI pipeline secret scanner.",
    },
    "graphql_introspection": {
        "what": "An introspection query (`{__schema{types{name}}}`) was sent "
                "to common GraphQL paths.",
        "why": "Introspection was left enabled in production.",
        "how": "The server returned a `__schema` object.",
        "impact": "Maps the entire API surface for the attacker — "
                  "accelerates discovery of mass-assignment / IDOR mutations.",
        "remediation": "Disable introspection in production. Apply field-level "
                       "authorization. Persisted-queries-only when possible.",
    },
    "graphql": {
        "what": "Five focused checks were fired at the discovered GraphQL "
                "endpoint: alias-batched single request (100 aliases), "
                "10-level nested self-referencing query, mutation enumeration "
                "without auth, query via GET / form-encoded body, and a "
                "typo-suggestion probe to leak schema info even when "
                "introspection is disabled.",
        "why": "GraphQL servers expose a single endpoint that runs arbitrary "
               "operations. Without alias / depth limits, per-mutation "
               "authorization, and content-type pinning, the surface is "
               "wider than a comparable REST API.",
        "how": "The detection rule that fired is in the finding title — "
               "`100 aliases resolved`, `nested 10 levels`, `mutation "
               "accessible anonymously`, `query accepted via GET`, or "
               "`'Did you mean ...' suggestion leak`.",
        "impact": "Brute force / DoS amplification, stealth schema discovery, "
                  "or unauthenticated state changes depending on the rule.",
        "remediation": "Enforce a maximum query depth and complexity. Cap "
                       "aliases per request. Apply per-mutation authorization "
                       "middleware. Reject GET / form-encoded GraphQL requests "
                       "(JSON-only). Disable typo-suggestions in production. "
                       "Adopt persisted queries when the client list is closed.",
    },
    "oauth": {
        "what": "The OAuth / OIDC authorize endpoint (or a discovered "
                "`/.well-known/openid-configuration`) was probed for the "
                "common high-payout bug classes: open redirect via "
                "`redirect_uri`, missing `state`, response_type=token "
                "(implicit) acceptance, missing PKCE on code flow, scope "
                "escalation, and JWKS hygiene.",
        "why": "OAuth flows pre-authorize a user-controlled redirect target, "
               "so any laxness in redirect_uri matching, CSRF defences, or "
               "PKCE enforcement directly translates into account takeover.",
        "how": "Each rule asserts a specific server response — Location "
               "pointing at attacker host, code= without state= , #access_token= "
               "in the fragment, consent UI for excessive scopes, etc.",
        "impact": "Account takeover via authorization-code / token theft, "
                  "login CSRF, or scope-escalation depending on the rule.",
        "remediation": "Match `redirect_uri` exactly (no prefix matching, no "
                       "wildcard subdomains, no path traversal). Require "
                       "`state` for every authorize request. Disable implicit "
                       "flow. Require PKCE for public clients. Whitelist "
                       "scopes per client. Rotate JWKS keys, never ship empty.",
    },
    "smuggling": {
        "what": "Two raw HTTP/1.1 payloads were sent over a TCP socket — "
                "one CL.TE-shaped, one TE.CL-shaped — and the time taken "
                "for each was compared.",
        "why": "When the front-end proxy and back-end app server disagree "
               "on whether to use Content-Length or Transfer-Encoding, an "
               "attacker can prepend a hidden second request to the next "
               "client's connection.",
        "how": "One of the two payload shapes hung for ≥5s while the other "
               "returned promptly — a strong timing oracle for the disagreement.",
        "impact": "Cache poisoning, request hijacking, credential theft, or "
                  "internal route reach depending on the architecture.",
        "remediation": "Reject ambiguous requests at the front-end (both "
                       "CL and TE present, or chunked + CL). Use HTTP/2 end-"
                       "to-end where possible. Patch front-end to strict-parse.",
    },
    "websocket": {
        "what": "A WebSocket Upgrade request was sent with a forged Origin "
                "header (`https://evil.samaritanx.test`).",
        "why": "WebSocket handshakes are HTTP requests — browsers send the "
               "user's session cookie automatically. Without an Origin check, "
               "any third-party page can open an authenticated socket on "
               "behalf of the user.",
        "how": "The server returned HTTP 101 + Sec-WebSocket-Accept despite "
               "the attacker Origin.",
        "impact": "Cross-Site WebSocket Hijacking — attacker reads / writes "
                  "the session-bound stream.",
        "remediation": "Validate Origin on every WebSocket handshake. Use a "
                       "per-session anti-CSRF token in the first message.",
    },
    "takeover": {
        "what": "Each subdomain's CNAME was resolved and matched against a "
                "list of 25 SaaS services with known unclaimed-subdomain "
                "fingerprints (GitHub Pages, Heroku, S3, Azure, Shopify, "
                "Netlify, Vercel, Fastly, etc.).",
        "why": "When a subdomain CNAMEs to a SaaS provider but the SaaS-side "
               "resource is no longer claimed, an attacker can claim it and "
               "serve content under the victim's domain.",
        "how": "DNS resolution returned a CNAME to a known service AND the "
               "live response carried the service's unclaimed fingerprint.",
        "impact": "Stored XSS at scale, OAuth bypass, cookie theft, brand "
                  "impersonation — all on a real domain owned by the target.",
        "remediation": "Remove dangling CNAMEs immediately. Audit DNS exports "
                       "monthly. Where SaaS providers support it, claim the "
                       "subdomain back and disable.",
    },
    "nuclei": {
        "what": "Nuclei was run with the configured severity floor against "
                "the host root.",
        "why": "Templates encode known CVEs / misconfigurations published by "
               "the community.",
        "how": "Nuclei reported a match — see the linked template.",
        "impact": "See the template metadata.",
        "remediation": "See the template-specific guidance and patch the "
                       "underlying component.",
    },
}

DEFAULT = {
    "what": "Recorded request was issued with a category-specific payload.",
    "why": "Application failed an input/output handling invariant.",
    "how": "Detection rule for this scanner triggered on the response.",
    "impact": "See finding evidence — assess based on data exposed.",
    "remediation": "Review owning team's input validation and authorization model.",
}


def annotate(finding: dict[str, Any], playbook: list[str] | None) -> None:
    """Mutate *finding* in-place adding walkthrough / impact / remediation / playbook."""
    cat = finding.get("category", "")
    n = CATEGORY_NARRATIVE.get(cat, DEFAULT)
    finding.setdefault("playbook", playbook or [])
    finding["walkthrough"] = (
        "**What the scanner did:** " + n["what"] + "\n\n"
        "**Why this vulnerability exists:** " + n["why"] + "\n\n"
        "**How it was discovered:** " + n["how"]
    )
    finding["impact"] = n["impact"]
    finding["remediation"] = n["remediation"]
