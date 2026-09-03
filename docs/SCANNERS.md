# Scanner reference

Every scanner is a pure async function `scan(ctx, url, params, method, form)`
registered in `scanners/__init__.py::REGISTRY` and enabled in
`config/config.yaml`. A finding only reaches `report.md` when it passes the
proof-gate (`core/proof_gate.py`): captured PoC, OOB/marker hard proof, or a
successful fresh revalidation. Everything else lands in `candidates.json`.

| Category | Detection | Proof | Aggressive-gated parts |
| --- | --- | --- | --- |
| `sqli` | error signatures, boolean length-delta vs median/MAD baseline, time-based (statistical outlier + ≥3s over baseline + double confirm) | captured error/boolean response (revalidated) | — |
| `lfi` | in-band `/etc/passwd` / `win.ini` / base64 php://filter decode | captured file content (`detection: marker`) | — |
| `xss` | context-aware breakouts; sent variant must carry HTML-active chars and survive unencoded | captured reflection (revalidated; browser upgrade when Playwright present) | — |
| `stored_xss` | multi-step: inject token → crawl → reflect → browser sink hooks | browser-fired sink (critical) or reflection candidate (quarantined) | — |
| `dom_xss` | Playwright sink hooks (eval/innerHTML/location/on* setAttribute/postMessage) | browser hit record | — |
| `ssrf` | in-band metadata indicators (baseline + echo-guarded), OOB interactsh | captured indicator response / OOB callback | — |
| `idor` | identifier flip → same-status similar-length response | candidate (stateful) | — |
| `idor_deep` | cross-session replay with 2nd identity; public-baseline subtraction; email/UUID-only markers | captured cross-identity leak (`poc`) | — |
| `csrf` | token-less state-changing form + no observed SameSite | candidate (heuristic) | — |
| `upload` | .phtml/.phar/.htaccess/double-ext/null-byte/polyglot; execution proven by bare marker output with source gone | captured executed marker | file writes happen on the target |
| `open_redirect` | Location header points at attacker host; payload must appear in redirect | captured 30x + Location (revalidated) | — |
| `cors` | Origin reflection ± credentials | captured headers (revalidated) | — |
| `cache_poisoning` | unkeyed header / unkeyed query; poisoned value persists on clean fetch | captured clean-fetch poisoning | — |
| `host_header` | Host/X-Forwarded-Host reflection absent from baseline | captured poisoned response (revalidated) | — |
| `hpp` | duplicate-param parsing change / array reflection | candidate | — |
| `path_normalization` | 401/403 → 2xx via parser-confusion variants; auth-wall/static guards | captured bypass response + no-session revalidation | — |
| `security_headers` | missing HSTS/CSP/XFO/nosniff/Permissions/Referrer + banner disclosure | captured response headers (static artifact) | — |
| `rce` | in-band echo marker; time-based (baseline + no-sleep control + double confirm); OOB | marker/OOB | — |
| `ssti` | product/hint NEW vs baseline (49, 7777777, engine hints) | captured evaluation (revalidated) | — |
| `api` | BOLA swap, excessive exposure, versioning, JWT weakness (alg=none/weak HMAC), mass assignment | mass-assignment captured echo | mass assignment |
| `jwt_priv_esc` | alg=none, kid traversal, claim tampering, **RS256→HS256 JWKS confusion** | captured 200-with-forged-token (poc) | — |
| `nosqli` | operator errors, boolean vs baseline, auth bypass (control-first), `$where` time | captured bypass/error | `$where` sleep |
| `oauth` | redirect_uri, state, PKCE, implicit flow, scope escalation, OIDC/JWKS audit | candidate-level (flow-specific) | — |
| `graphql` | introspection, alias bomb, depth bomb, anonymous mutations, CSRF-via-GET, suggestions | schema dump / response artifacts | anonymous mutations |
| `smuggling` / `h2_smuggling` | raw-socket timing oracles + downgrade artifact capture | captured artifact (reprobe) | — |
| `websocket` | CSWH handshake; message-level SQLi/RCE/SSTI with control-latency baseline | in-band marker / OOB callback | — |
| `xxe` | in-band /etc/passwd, OOB DTD fetch | captured content / OOB | — |
| `deserialization` | serialized-blob classification (PHP/Java/pickle/Ruby/.NET/YAML/phar) | candidate (no gadget fired) | — |
| `version_bypass` | sibling-version 2xx with identity/sensitive markers (auth-wall guarded) | captured response + revalidation | — |
| `web_cache_deception` | private page served anonymously via cacheable URL | captured anonymous private response | — |
| `account_takeover` | Host-reflection reset poisoning (OOB-upgraded), token Referer leak, user enumeration | captured reflection / OOB | reset submission, enumeration |
| `param_miner` | hidden parameter discovery (status/length anomalies) | candidate | — |
| `prototype_pollution` | browser-confirmed `Object.prototype` mutation; server-side 500 twice | browser hit (`client_proto`) | — |
| `crlf` | injected header surfaced in response header map | captured header (revalidated) | — |
| `subdomain_takeover` | dangling CNAME + service fingerprint (25 services) | hard proof by construction | — |

Shared accuracy machinery: `core/baseline.py` (median/MAD timing + response-shape
baselines), `core/revalidate.py` (fresh re-fire per category before reporting),
`core/proof_gate.py` (the report gate), `core/cvss.py` (spec CVSS 3.1).
