# Changelog

## 1.0.0 — the accuracy + automation release

### Fixed
- `crlf` scanner missing `return findings` crashed every vuln task and silently
  discarded ALL findings from every scanner in the batch.
- Orchestrator task-timeout caps killed the scan/exploit/report phases mid-run —
  scans ended with no report at all; report now always renders (emergency path).
- Crawler followed redirects with no scope check, lost 302 endpoints, and — via
  the registrable-root comparison — could crawl an entire parent domain
  (scanme.nmap.org → all of nmap.org). Now seed-host + subdomains only.
- Dead detectors: time-based SQLi (7s floor vs 5s payloads), WebSocket SQLi
  (3s window vs 4.5s threshold), nosqli boolean (inverted condition) and auth
  bypass (self-defeating status check).
- False-positive generators: SSTI on static "49"/"Werkzeug" pages, upload
  "execution" on raw-served files, version_bypass on any 200, CSRF SameSite read
  from the wrong cookie, BOLA on public footer markers, h2 CONTINUATION on any
  frame, XSS via fully-encoded variants, SSRF via echoed URLs.
- Proof-gate honored stale poc after a failed re-test; revalidation re-fired
  reflected XSS against the payload-less URL; revalidation now bounded
  (cap + smuggling reprobe budget) so phase 2 always finishes.
- Token bucket auto-scale fought the 429 cooldown; scope CIDR checks blocked the
  event loop; httpx sync response hook broke every request; host filenames with
  ':' became NTFS alternate data streams; secret validator demoted live
  credentials on transport errors; Slack `"ok": true` never matched; Zero-finding
  scans produced no report.

### Added
- **Detectors**: LFI, host-header injection, HPP, path-normalization auth bypass,
  security headers, JWT RS256→HS256 JWKS confusion, unkeyed-query cache
  poisoning, SSRF echo guard, OAuth/GraphQL depth coverage.
- **Accuracy engine**: spec-compliant CVSS 3.1 calculator (vector/score/band
  always agree), baseline-gated detectors, per-category revalidators,
  proof-gate, mock-server regression suite (210+ unit tests, 136 self-checks).
- **Recon**: wildcard-DNS detection, alt-dns permutations, vhost brute force,
  TCP port scan with Redis/Mongo/ES/Docker classification, DNS zone transfer,
  keyed sources (Shodan/VirusTotal/SecurityTrails).
- **Program automation**: platform scope import + live fetch (HackerOne /
  Bugcrowd / Intigriti), `scan --program`, `--targets`, `--scan-scope-roots`,
  parallel roots, HackerOne draft auto-creation (CWE + program linkage).
- **Persistence**: session cookie/header save-restore, phase checkpoints,
  incremental rescan by content hash, shared baseline request cache.
- **Workflow**: `retest`, `triage`, `diff`, `auth-check`, config profiles
  (fast/deep/stealth), custom headers, proxy rotation pool, sqlmap/Burp handoff
  files, SARIF/CSV/JSONL exports, Slack/Discord/Telegram alerts, LLM impact
  triage (Anthropic/OpenAI/DeepSeek/OpenAI-compatible), 20+ secret validators.
- **Benchmark**: `bench.runner` end-to-end against the lab answer key —
  recall 1.00, precision 0.67, F1 0.80; CI (unit tests + coverage + selftest),
  Dockerfile, AGENTS.md, scanner + escalation docs.

## Unreleased — proof, credibility & new surface

### Added
- **Auto-revalidation / false-positive killer (`core/revalidate.py`).** Before
  the report is written, every finding is re-fired fresh with a category-specific
  reproduce check: reproduced → confidence nudged up + flagged `revalidated`;
  not reproduced → confidence cut ×0.4 and relabelled so it sinks below the firm
  line; hard-proof/oracle-only/stateful → skipped with a reason. Read-only, so
  it always runs. Summary → `reports/revalidation.json`.
- **Active exploitation (`core/exploitation.py`, `--aggressive`).** Proves impact
  on confirmed high/critical bugs: SQLi → extracts the DBMS version via the
  boolean/length oracle (bounded, read-only `SELECT`); SSRF → follows the
  confirmed SSRF to the cloud metadata IAM endpoint and captures redacted
  credential material. Proof is appended to the finding evidence.
- **PoC automation (`core/poc.py`).** Every finding now ships a copy-paste
  `curl` (and an HTML repro for client-side classes), persisted in metadata and
  rendered in the HackerOne report template.
- **Hidden parameter discovery (`scanners/param_miner.py`).** Arjun-style:
  probes a bundled 130-name wordlist, isolates accepted params by binary-split
  (reflection / length / status), reports them, and re-queues them as scan tasks
  so the injection scanners test them.
- **Prototype pollution (`scanners/prototype_pollution.py`).** Client-side
  confirmed in a real browser (`Object.prototype` mutation via `__proto__` /
  `constructor.prototype` in the query) + a conservative server-side JSON probe.
- CWE entries, confidence scoring, and report narratives for the new categories;
  new offline unit tests (`tests/test_proof.py`).
- Self-test: **107 passed, 0 failed** (84 unit tests, 30 scanners, 12 task kinds).

## Unreleased — multi-identity authz + monitor retention

### Added
- **Arbitrary-N labeled sessions (`--session label=recipe.yaml[:rank]`).**
  Repeatable flag that loads extra identities (each its own session client) with
  a privilege rank — admin-ish labels auto-infer rank 2. The authorization
  matrix now tests anon + userA + userB **+ admin** and does **rank-aware
  BFLA/privilege-escalation**: it establishes the privilege level that
  legitimately reaches an endpoint (highest rank with a substantive 2xx) and
  flags any strictly-lower identity that also gets in, gated on a
  privileged-shaped path or a real admin baseline so public pages don't trip it.
  BOLA detection is now generalised to all pairs of regular-user identities.

### Changed
- **Monitor diff retention.** `monitor.keep_diffs` (default 30) prunes old
  `diff_*.json` artifacts so scheduled `--monitor` runs don't accumulate them.

### Notes
- Self-test: **100 passed, 0 failed** (76 unit tests, 28 scanners, 12 task kinds).

## Unreleased — hunter-grade coverage (scale, surface, ATO, monitoring)

### Added
- **Authorization matrix engine (`agents/authz_agent.py`).** New `authz` task,
  emitted once per host. Collapses endpoints to path templates and tests each
  across every identity we hold (anon / userA / userB), building a
  role×endpoint matrix and flagging three families of broken access control:
  unauthenticated access to private data, BOLA/cross-tenant (userB sees userA's
  markers), and BFLA (non-privileged identity reaches an admin endpoint). Matrix
  written to `workspace/<target>/authz/matrix.json`.
- **JS intelligence (`core/js_intel.py`).** Reconstructs original source from
  exposed `.map` files (and re-mines it for endpoints/secrets), extracts
  hardcoded secrets (Google/Stripe/Slack/AWS keys, JWTs, private-key blocks),
  embedded GraphQL operations, and privileged route literals. Wired into the
  crawler — reports `secret_exposure` and source-map-exposure findings.
- **Account-takeover scanner (`scanners/account_takeover.py`).** Self-filters to
  auth-flow URLs and runs password-reset poisoning (Host / X-Forwarded-Host
  reflection — read-only probe always, email submission behind `--aggressive`),
  reset-token Referer leakage, and user-enumeration checks.
- **Monitoring + diff (`core/monitor.py`, `--monitor`).** Baselines the attack
  surface each run and diffs against the previous one, reporting new
  subdomains/endpoints/params; writes a diff artifact, emits new-surface events,
  and POSTs an optional webhook alert. Pair with cron / `--resume` for
  continuous monitoring.
- Confidence scoring + report narratives for `account_takeover`; `authz` and
  `monitor` config sections; new offline unit tests (`tests/test_intel.py`).
- Self-test now: **100 passed, 0 failed** (69 unit tests, 28 scanners, 12 task
  kinds).

## Unreleased — escalation & chaining (turn primitives into payouts)

### Added
- **Impact escalation (`core/escalation.py`).** Shared detector for
  exfiltratable sensitive data (JWT/bearer/API keys, session + CSRF tokens,
  PII). Severity is now set by *proven impact*, not just the existence of a
  misconfig.
- **CORS escalation (`scanners/cors.py`).** Reads the credentialed cross-origin
  body and grades the finding by what actually leaks (session token → critical,
  nothing sensitive → medium). Adds null-origin / suffix / prefix / subdomain
  bypass probes and ships a ready HTML PoC.
- **Web cache deception scanner (`scanners/web_cache_deception.py`).** Crafts
  `/path/x.css`-style URLs, fetches authenticated then anonymous, and only
  reports when the victim's private data is genuinely served from cache to an
  anonymous request — self-escalating by design.
- **Blind NoSQL injection scanner (`scanners/nosqli.py`).** Operator injection
  (`$ne/$gt/$regex/$where`), MongoDB-style auth bypass, boolean + time blind
  confirmation, and driver-error signatures. `$where` time oracle gated behind
  `--aggressive`.
- **Relationship-aware chaining engine (`core/chains.py`).** Replaces the old
  "two categories exist somewhere → print a sentence" logic. Correlates findings
  by origin/host, **actively verifies** the money chains (open-redirect→OAuth
  takeover, CORS→token theft, SSRF→metadata→IAM, cache-deception→session theft,
  IDOR+mass-assignment, NoSQLi-authbypass+IDOR, upload→RCE, smuggling→auth
  bypass), and emits a single **escalated `chain` finding** with combined CVSS,
  component ids, verification evidence, and a PoC. Read-only verification always
  runs; state-changing steps require `--aggressive`.
- `no_session` flag on the HTTP client for explicit anonymous probes; confidence
  scoring + report narratives for the `nosqli`, `web_cache_deception`, and
  `chain` categories; new offline unit tests (`tests/test_chains.py`).

### Changed
- **Chain engine now multi-candidate + affinity-scored.** Instead of collapsing
  each category to one top-severity representative per host, it ranks up to 5
  endpoint candidates per category, scores pairings by **affinity** (shared path
  prefix / shared object id) plus proof strength, and — for verified recipes —
  probes several candidates until one reproduces (so a lower-severity-but-leaky
  CORS endpoint is found, not skipped). Verifier results are memoized; emits up
  to 2 distinct verified chains per group, else the single best-scored pairing.
- Self-test now: **95 passed, 0 failed** (56 unit tests, 27 scanners).

## Unreleased — reach for high/critical findings

### Added
- **API surface discovery (`core/surface.py`).** Closes the dominant yield
  limiter: on JSON-API / SPA targets the crawler used to find endpoints but no
  injection points, so the SSRF/SQLi/RCE/BOLA logic never fired. Now the
  crawler:
  - probes well-known **OpenAPI/Swagger** spec locations and parses them
    (v3 + v2) into typed injection points — query params, `path:N` segments,
    and `json:field` request-body points;
  - **mines JavaScript bundles** for endpoint paths and query params, filtering
    static assets and off-domain URLs;
  - **synthesizes `json:` body points from JSON responses** (a model a REST
    endpoint returns is usually one it accepts on write).
- **Authenticated deep crawl.** The Playwright render now injects the primary
  session's cookies + headers, so the browser crawls *post-login*, and captures
  authenticated XHR/fetch calls (incl. JSON request bodies) into `json:`
  injection points — reaching the BOLA / priv-esc / admin surface where
  critical bugs live.
- **Real BOLA/IDOR proof (`scanners/idor_deep.py`).** Replaced the ±10%-length
  heuristic with: (1) cross-session **identity-marker leak** — replay A's URL as
  B and confirm A's email/UUID/token appears in B's response; (2) **id
  enumeration** — flip numeric/UUID path & query ids to a neighbour as B and
  detect distinct PII across the auth boundary. Old shape match retained as a
  low-confidence fallback flagged for manual review.
- New crawler toggles `crawler.api_discovery` and `crawler.mine_javascript`
  (both default on). 13 new offline unit tests (`tests/test_surface.py`).

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
