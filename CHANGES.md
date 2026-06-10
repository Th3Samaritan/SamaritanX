# Changelog

## Unreleased — reliability, coverage, and credibility pass

### Fixed
- **Recon hang (blocker).** Recon used to enumerate and HTTP-probe every
  subdomain (thousands of dead crt.sh/certspotter hosts, no DNS pre-check) and
  emit work only at the very end, so the pipeline starved and the 60s per-task
  cap killed it first — the "only recon runs for hours, no results" symptom.
  Now: probe the target first and emit it immediately, run collectors
  concurrently, DNS-resolve and cap candidates before probing, emit each live
  host as found, per-host probe timeout, kill timed-out subfinder/amass, and a
  dedicated long-phase timeout budget for recon/crawl/discover.
- WebSocket blind-RCE OOB poll never fired (`oob_tokens` was never populated).
- Form-login cookie capture now reads httpx's cookie jar instead of naive
  `Set-Cookie` comma-splitting (which broke on `Expires=...` commas).
- Anonymous-admin probe now blanks the loaded session's cookies, so it is
  actually unauthenticated.

### Added
- **Injection surface (`core/injection.py`).** One shared builder injects a
  payload into query params, form fields, **URL path segments (`/users/123`),
  JSON body fields, request headers, and cookies**. SQLi/XSS/RCE/SSRF/CRLF/IDOR
  and the crawler now test REST path segments and JSON bodies, not just query
  strings — closing the biggest "finds nothing on modern APIs" gap.
- **Confidence scoring (`core/confidence.py`).** Every finding gets a 0–1 score
  and a confirmed/firm/tentative/speculative label based on proof strength,
  persisted in SQLite. Reports lead with high-confidence findings and flag the
  rest as "manual verification required before submitting."
- **Self-contained recon.** Bundled a 303-label subdomain wordlist
  (`config/payloads/subdomains.txt`), added AnubisDB + RapidDNS keyless passive
  sources (5 total), and pinned `tldextract` to its offline snapshot. No
  external CLI tool or paid API required.
- `--aggressive` flag gating destructive checks (auth-lockout probe, 25x race
  POSTs, pricing-tamper submits); off by default.
- `selftest.py` harness (offline structural checks + `--live` smoke scan) and
  `tests/test_improvements.py`. Suite is now 29 unit tests / 88 self-test checks.
- `AUDIT.md` — full code audit of every module.

### Notes
- Self-test status: **88 passed, 0 failed**. End-to-end `--live` scan is
  unverified in CI (network-restricted) — run `python3 selftest.py --live`
  against an authorized target to confirm the scan-to-report path.
