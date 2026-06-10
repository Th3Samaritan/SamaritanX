# SamaritanX — Code Audit

> **Update (this session):** the high-priority items below have now been implemented and verified by the self-test (88 checks / 29 unit tests, 0 failures). See "Implemented upgrades" immediately below.

## Implemented upgrades

**Injection surface (was the #1 limiter).** A new `core/injection.py` routes every param-injecting scanner (SQLi, XSS, RCE, SSRF, CRLF, IDOR) through one builder that can place a payload in a query param, **form field, URL path segment (`/users/123`), JSON body field, request header, or cookie**. The crawler now also emits scan tasks for id-shaped path segments on parameterless REST endpoints — so modern API/SPA targets get tested instead of skipped. IDOR specifically now flips path-segment identifiers, where it most often lives.

**Confidence scoring (credibility).** New `core/confidence.py` scores every finding 0–1 and labels it confirmed / firm / tentative / speculative, based on proof strength (OOB callback, reflected marker, DBMS error, validated credential → high; response-size IDOR, "admin 200", race heuristics → low). The score is persisted in SQLite (`confidence` column + migration) and the report now leads with high-confidence findings and flags low-confidence ones as **"manual verification required before submitting."** This directly addresses false-positive triage.

**Fully self-contained recon.** Bundled a 300-label DNS-brute wordlist (`config/payloads/subdomains.txt`), added two more keyless passive sources (AnubisDB, RapidDNS — now 5 total), and pinned `tldextract` to its offline snapshot. No external CLI tool or paid API is required; subfinder/amass/ffuf/nuclei are used only if already installed.

**Correctness + safety fixes.** WebSocket blind-RCE OOB path now actually fires (`oob_tokens` populated); form-login cookie capture reads httpx's jar instead of naive Set-Cookie comma-splitting; anonymous-admin probe now blanks the loaded session's cookies; destructive checks (auth lockout probe, 25× race POSTs, pricing-tamper submits) are gated behind a new `--aggressive` flag (off by default).

---



**Date:** 2026-06-10
**Scope:** Every module in `core/`, `agents/`, `scanners/`, `reporting/`, the CLI entrypoint, config, and tests.
**Method:** Static source review of the complete codebase, **plus a dynamic structural test run** via the shipped `selftest.py`. Result: **86 structural checks passed, 0 failed** — every module imports cleanly, all 25 scanners have the correct async signature, config/registry are consistent, all 11 task kinds are routed, and the 19 unit tests pass. The full end-to-end `--live` scan could not be run here because the sandbox's network is allow-listed (arbitrary outbound is blocked); run `python3 selftest.py --live` on your Kali box to confirm the scan-to-report path.

---

## Verdict

This is a genuinely well-architected framework, not broken software. The agent/queue design is clean, scanners are isolated and crash-contained, the memory layer is correct, and detection logic across the 24 scanners is thoughtful (baseline-variance SQLi, context-aware XSS, OOB callbacks, raw-socket smuggling, real-browser DOM XSS). The problems you hit were a small number of concrete, fixable issues — chiefly in recon — rather than a fundamentally bad tool.

One **blocker** (recon hang) has already been fixed in this session. The remaining items are one architectural limitation and a handful of medium/low bugs. None of them prevent the tool from running.

---

## Findings by severity

### BLOCKER — fixed this session

**B1. Recon ran unbounded and emitted work only at the very end.**
The recon agent enumerated *and* HTTP-probed every subdomain (often thousands of dead crt.sh/certspotter hosts, no DNS pre-check), throttled to ~6 req/s with 20s timeouts, and only queued live hosts to the crawler after the entire sweep finished. Combined with the orchestrator's 60s per-task cap killing recon before it reached that final emit, the result was exactly what you saw: "only recon runs, for hours, no results."

*Fix applied* (in `agents/recon_agent.py`, `core/orchestrator.py`, `config/config.yaml`):
probe the target host first and emit it immediately; run collectors concurrently; DNS-resolve and cap candidates *before* probing; emit each live host as it's found; per-host probe timeout; kill timed-out subfinder/amass processes; give recon/crawl/discover a real time budget (`long_phase_timeout_seconds`).

### HIGH — architectural limitation (no crash, but caps results)

**H1. Scanners only test discovered query params, form inputs, and OpenAPI-declared params.**
There is no fuzzing of REST path segments (`/users/123`), JSON request-body fields (beyond OpenAPI), headers, or cookies as general injection points. On a modern SPA/API target whose landing page has no `?param=` links, no classic `<form>`, and no exposed `/openapi.json`, the crawler finds endpoints but emits few or zero `scan` tasks — so the 24 scanners have nothing to inject into and the report is thin or empty even though everything "worked." This is the most likely reason for low yield once recon is healthy. Recommended next enhancement: synthesize candidate params for parameterless endpoints and inject into path segments + JSON bodies.

**H2. The global 6 req/s rate limit is shared across recon, crawl, and scan.**
Stealthy by design, but it makes large scans slow and amplifies the perception of hanging. Consider raising `stealth.rate_limit_rps` for authorized targets, or giving recon probing its own budget.

### MEDIUM

**M1. `core/auth.py` — fragile Set-Cookie parsing (form login).**
`_refresh()` splits the combined `Set-Cookie` header on `,`. Cookie attributes like `Expires=Wed, 09 Jun ...` contain commas, so this can capture malformed cookies and break authenticated scans. Prefer reading cookies from the httpx client's own cookie jar (`http._client.cookies`) after the login request instead of hand-parsing the header.

**M2. `scanners/websocket.py` — blind WS RCE via OOB never fires.**
`oob_tokens` is declared but never populated (the token is pushed into the `payloads` list instead), so the final `for label, tok in oob_tokens.items()` loop always iterates an empty dict. The out-of-band WebSocket RCE detection path is dead code. Populate `oob_tokens[label] = tok` when building payloads.

**M3. `agents/logic_agent.py::_admin_anon` isn't truly anonymous.**
It blanks `Authorization`/`Cookie` via request *headers*, but session cookies are still attached through httpx's `cookies` kwarg in the client. When a `--auth` session is loaded, the "unauthenticated admin page" probe is actually authenticated, which can both miss real bugs and misreport. Pass an explicit empty cookie jar for this check.

**M4. Several scanners perform real, stateful actions.**
`api.py::_missing_rate_limit` fires 20 login POSTs (can lock accounts); `logic_agent::_race_conditions` fires 25 concurrent POSTs to any endpoint matching `transfer/redeem/checkout/...` (performs the action up to 25×); `logic_agent::_pricing_tamper` submits forms. These are legitimate for *authorized* offensive testing but dangerous if misaimed. Recommend gating them behind an explicit `--aggressive` flag and always requiring `--scope`.

### LOW / cosmetic

**L1. Dead constant.** `core/constants.py::FindingCategory.SUBDOMAIN_TAKEOVER = "subdomain_takeover"` is never used; the takeover scanner, walkthrough narratives, CWE map, and chain rules all consistently use `"takeover"`. Either align the constant or delete it. (Note: the takeover detection itself works — the strings match end to end.)

**L2. Test never awaited.** `tests/test_core.py::TestTaskQueue.test_put_get_join` is an `async def` collected by `unittest`; unittest calls it, gets an un-awaited coroutine, and reports a pass without testing anything (real coverage comes from `test_sync`). Rename it to `_put_get_join` so only the sync wrapper runs it.

**L3. Tight coupling.** `agents/reporting_agent.py` reads `ctx.dashboard._counters` (a private attribute) to populate report stats. Works, but expose a public accessor instead.

**L4. Dead import.** `scanners/subdomain_takeover.py` does `from agents.base import BaseAgent  # noqa` inside `check()` and never uses it.

**L5. Noisy `tldextract` first-run on offline/proxied hosts.** On a box without direct internet, `tldextract` prints multi-screen tracebacks while it tries (and fails) to fetch the public-suffix list, before silently falling back to its bundled snapshot. It still works, but the output is alarming. Pin it to the offline snapshot to silence it: construct `tldextract.TLDExtract(suffix_list_urls=())` once in `core/utils.py` and reuse it, instead of calling the module-level `tldextract.extract`. (Observed live during the self-test run.)

---

## What is solid (spot-checked and correct)

- **Task queue / orchestrator:** priority queue, per-kind routing, sentinel-based graceful shutdown, deadline handling, and `queue.join()` accounting are all correct.
- **Memory (SQLite):** finding dedup by stable fingerprint, asset/URL tracking, payload Wilson-score learning, scan-state resume — all sound; unit tests cover the core paths.
- **HTTP client:** scope enforcement before egress, token-bucket rate limiting with reactive 429/503 backoff, session injection, evidence capture — correct.
- **Scanner isolation:** every scanner is wrapped in `_safe()` with a per-scanner timeout, so one crash never sinks the run.
- **Scanner signatures:** all 24 conform to `async def scan(ctx, url, params, method, form)`; `selftest.py` asserts this automatically.
- **Scope policy, payload engine, WAF evasion, OOB client, browser pool:** reviewed, no functional defects found.

---

## How to confirm it actually works (dynamic verification)

Because this audit is static, run the shipped harness on your Kali box:

```bash
# offline structural checks — imports, scanner signatures, config/registry, unit tests
python3 selftest.py

# full end-to-end smoke scan against an authorized vulnerable test site
python3 selftest.py --live
```

`--live` points the pipeline at `testphp.vulnweb.com` (Acunetix's public test target) and asserts: recon emits a live host → crawler discovers parameters → scanners produce ≥1 finding → `report.md` is written. If all four pass, the tool is working end to end. If `--live` finds 0 parameters or 0 findings there, that isolates H1 (surface generation) as the next thing to fix.

---

## Suggested fix order

1. ✅ Recon hang (B1) — done.
2. Verify end to end with `selftest.py --live`.
3. H1 — extend injection surface to path segments + JSON bodies (biggest yield improvement).
4. M1, M2, M3 — small correctness fixes.
5. M4 — add an `--aggressive` gate for destructive checks.
6. L1–L4 — cleanup.
