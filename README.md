# SamaritanX

> Agentic bug-bounty framework for **th3Samaritan**.
> Recon → Crawl → Vulnerability scan (12 categories) → Logic abuse → Exploit synthesis → Report (MD + PDF).

```
   ____                              _ __              _  __
  / __/__ ___ _  ___ _____ ___  ___ (_) /____ ____    | |/_/
 _\ \/ _ `/  ' \/ _ `/ __// _ \/ _ \/ / __/ -_) __/   _>  <
/___/\_,_/_/_/_/\_,_/_/   \___/\___/_/\__/\__/_/     /_/|_|
                                                  operator: th3Samaritan
```

**Use only against assets where you have explicit written authorization** — your own infrastructure, a CTF, or a target whose bug-bounty scope covers what you are about to do.

---

## Why agents?

Each layer of work is isolated as an asynchronous agent that consumes and produces typed tasks on a shared priority queue. Agents never call each other directly — they only ever publish tasks. That means:

- new scanner? drop a file in `scanners/`, register it in `scanners/__init__.py`, done.
- new agent (e.g. cloud-asset enumerator, mobile-API harness)? subclass `agents.base.BaseAgent`, declare which `kinds` it handles, register it in `samaritanx.py`.
- the dashboard, memory layer, payload engine, and stealth HTTP client are shared services — agents receive them via `Context`.

```
                          ┌──────────────┐
                          │  Orchestrator│  ← config, workspace, dashboard
                          └─────┬────────┘
              priority queue ↑  │  ↓ shared services
       ┌───────────┬───────────┴──────────┬────────────┬────────────┐
       │  Recon    │   Crawler            │ Vulnerability │ Logic   │ Exploit │ Report
       │ (passive  │ (BFS + Playwright    │ (12 scanners  │ (auth,  │ (chain  │ (MD/PDF
       │  + active)│  + GraphQL probe)    │  + nuclei)    │  race…) │  rules) │  walkthrough)
```

## Capabilities

| Layer | What it does |
| ----- | ------------ |
| **Recon** | subfinder, amass-passive, crt.sh / certspotter / hackertarget, DNS brute force, live HTTP probe with tech fingerprint |
| **Discovery** | content discovery (ffuf or async wordlist), Wayback / URLScan / OTX historical URLs, JS LinkFinder regex sweep, OpenAPI/Swagger ingestion (auto-emits scan tasks per operation), cloud-bucket enumeration (S3/GCS/Azure), GitHub dorks |
| **Crawler** | depth-bounded BFS, Playwright-driven JS render, GraphQL `__schema` probe, 13 secret regex rules |
| **Authentication** | static / form-login / bearer-from-JSON recipes, env-var expansion for credentials, periodic token refresh, **second-session** mode for cross-tenant BOLA testing |
| **Scope enforcement** | allow/deny rules (glob, regex, CIDR) checked at the HTTP boundary — every out-of-scope request is dropped before egress |
| **Vuln scanners** | SQLi (error/boolean/time), reflected XSS, **DOM XSS via Playwright** (real browser sink hooks), SSRF (cloud metadata + **interactsh OOB**), IDOR (heuristic) + **deep IDOR/BOLA** with second session, CSRF, **hardened upload** (.phtml / .phar / .htaccess / double-extension / null-byte / GIF polyglot), Open Redirect, CORS, Cache Poisoning, RCE + SSTI (in-band, time-based, **OOB**), **HTTP request smuggling** (CL.TE / TE.CL via raw socket), **WebSocket CSWH**, API Top-10 (BOLA / Mass-assign / JWT / rate-limit / excessive exposure), LLM prompt injection, optional `nuclei` sweep |
| **Subdomain takeover** | 25-service CNAME fingerprint sweep across every collected host |
| **OOB collaborator** | interactsh client (RSA / AES decrypt of polled events) — proves blind SSRF / RCE / DNSlog with attributable callbacks |
| **Logic** | sensitive-path enumeration, anonymous admin probe, pricing tampering, race-condition probe |
| **Exploit** | per-finding playbook, 8 chain rules (SSRF→IMDS, prompt-injection→tool-call SSRF, upload→RCE, IDOR+mass-assign, etc.) |
| **Reporting** | Markdown + PDF (weasyprint) with executive summary, top-10 priority table, per-finding PoC + impact + remediation + walkthrough, **plus per-finding HackerOne-style submissions ready to paste**, plus **Playwright PoC screenshots** |
| **Memory** | SQLite store of findings (deduplicated by stable fingerprint) + payload effectiveness re-ranked by Wilson lower-bound + scan-resume cursors |
| **Stealth** | global + per-host token-bucket rate limit, **reactive 429/503 backoff with Retry-After**, jitter, UA / Referer rotation, Tor or HTTP/SOCKS proxy, six WAF evasion transforms |

## Project layout

```
SamaritanX/
├── samaritanx.py                 # CLI entry (typer)
├── setup.sh                      # Kali installer
├── requirements.txt
├── README.md
├── config/
│   ├── config.yaml               # all knobs live here
│   └── payloads/                 # per-category payload libraries
│       ├── xss.txt   sqli.txt   ssrf.txt   redirect.txt
│       ├── lfi.txt   rce.txt    ssti.txt   prompt_injection.txt
│       └── secrets_regex.txt
├── core/
│   ├── orchestrator.py           # builds context, drains queue, finalize phase
│   ├── task_queue.py             # async priority queue
│   ├── memory.py                 # SQLite memory layer
│   ├── http_client.py            # stealth httpx async client
│   ├── waf_evasion.py            # 6 transforms
│   ├── payload_engine.py         # learning-aware payload generator
│   ├── dashboard.py              # rich.Live CLI dashboard
│   ├── logger.py
│   └── utils.py
├── agents/
│   ├── base.py
│   ├── recon_agent.py
│   ├── crawler_agent.py
│   ├── vuln_agent.py             # fan-out dispatcher
│   ├── logic_agent.py
│   ├── exploit_agent.py
│   ├── walkthrough_agent.py      # finding → narrative + impact + remediation
│   └── reporting_agent.py
├── scanners/
│   ├── sqli.py xss.py ssrf.py idor.py csrf.py upload.py
│   ├── open_redirect.py cors.py cache_poisoning.py
│   └── rce.py api.py prompt_injection.py
├── reporting/
│   ├── markdown_report.py
│   ├── pdf_report.py
│   └── templates/report.md.j2
└── workspace/                    # per-target output (gitignored)
    └── <target_slug>/
        ├── recon/                # subdomains.txt, live.json
        ├── crawl/                # endpoints.json, forms.json, params.txt, secrets.json
        ├── vulns/                # raw nuclei output
        └── reports/              # report.md, report.pdf, findings.json, exploitation.json
```

## Setup (Kali Linux)

```bash
git clone <this-repo> SamaritanX && cd SamaritanX
chmod +x setup.sh
./setup.sh
source .venv/bin/activate
python samaritanx.py self-check
```

`setup.sh` installs system libraries (Pango/Cairo for PDF, Tor, Chromium), the python deps, Playwright's Chromium build, and updates Nuclei templates. On non-Kali distros it falls back to whatever apt has.

## Usage

```bash
# full scan with auto-derived scope (target's apex + all subs)
python samaritanx.py scan example.com

# real bug bounty workflow: explicit scope + authenticated session
export TARGET_USER=alice && export TARGET_PASS=hunter2
python samaritanx.py scan example.com \
    --scope config/scope.example.txt \
    --auth  config/auth.example.yaml

# cross-tenant BOLA / IDOR with two identities
export TARGET_USER=alice TARGET_PASS=... ; export USER2=bob USER2_PASS=...
python samaritanx.py scan example.com --auth alice.yaml --second-session bob.yaml

# pipe through Tor, deeper crawl, skip PDF
python samaritanx.py scan https://api.example.com --tor --depth 5 --no-pdf

# subset of scanners, Burp proxy
python samaritanx.py scan example.com \
    --only sqli,rce,prompt_injection,api,smuggling \
    --proxy http://127.0.0.1:8080 --rate 2

# passive recon only, no OOB callback host (offline-friendly)
python samaritanx.py scan example.com --passive --no-oob

# resume a long scan that was interrupted
python samaritanx.py scan example.com --resume

# rebuild reports later from memory (no network calls)
python samaritanx.py report example.com

# inspect findings + reset scan state
python samaritanx.py memory list example.com
python samaritanx.py memory reset example.com
```

## Auth recipes

`config/auth.example.yaml` ships with three template shapes — `static`,
`form`, `bearer_json`. Pick one, fill it in, point `--auth` at it. The
HTTP client attaches the resulting cookies + headers to every request and
periodically re-runs the login flow when `refresh_every` elapses.

Credentials use `{ENV:VAR_NAME}` expansion so secrets never sit in the
repo. For BOLA testing, supply a second recipe via `--second-session` —
the deep IDOR scanner will replay every recorded request with that
identity and report any responses where session B sees session A's data.

## Scope file

`config/scope.example.txt` — one rule per line:

```
*.example.com           # allow glob
api.example.com         # exact
!corp.example.com       # deny (deny rules win)
re:^https://x\.example\.com/admin/    # regex against full URL
!cidr:10.0.0.0/8        # deny CIDR (host resolved at request time)
```

Every outbound URL is checked against the policy before the request
leaves the box. Out-of-scope requests are dropped, counted on the
dashboard, and surface in the run summary. **Use this on every real bug
bounty engagement.**

## Walkthrough mode

Every finding the report emits includes three labelled paragraphs:

1. **What the scanner did** — exact payload sequence and detection fired.
2. **Why this vulnerability exists** — root cause class and why typical mitigations fail.
3. **How it was discovered** — the precise signal that proved the bug (marker echo, response delta, header reflection, time delay …).

Plus a per-category **playbook** of next-step commands ready to paste into Burp / curl / sqlmap, and the **chain detection** highlights when two findings together unlock a higher-impact attack (SSRF + cloud metadata, prompt injection + tool-calling SSRF, etc.).

Disable with `--no-walkthrough` if you want a terse executive deliverable.

## Sample run output

```
$ python samaritanx.py scan vuln.example.com

      ____                              _ __              _  __
     / __/__ ___ _  ___ _____ ___  ___ (_) /____ ____    | |/_/
    _\ \/ _ `/  ' \/ _ `/ __// _ \/ _ \/ / __/ -_) __/   _>  <
   /___/\_,_/_/_/_/\_,_/_/   \___/\___/_/\__/\__/_/     /_/|_|
                operator: th3Samaritan   target: vuln.example.com   uptime: 0s

agents                       metrics            event log
━━━━━━━━━━━━━━━━━━━━━━━━━━━ ━━━━━━━━━━━━━━━━━ ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
 recon    running  passive   subdomains   42  12:01:14 INFO  recon: 42 hosts
 crawler  running  spidering endpoints   338  12:01:23 INFO  crawler: GraphQL probe
 vuln     running  sqli      params      812  12:01:31 HIGH  Reflected XSS in `q`
 logic    idle               findings      9  12:01:34 CRIT  RCE in `cmd`
 exploit  queued             critical      2  12:01:38 HIGH  IDOR on /api/orders/123
 report   queued             high          4  12:01:42 OK    chain: SSRF + IMDS
                             medium        2  12:01:45 OK    chain: prompt-inj→SSRF
                             low           1  12:01:51 OK    report -> report.md
                             info          0

task progress
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
✔ subdomain probe   42/42   00:00:08
⠋ crawl:vuln.example.com  338/1500   00:00:15

done — workspace: workspace/vuln_example_com
   report   : workspace/vuln_example_com/reports/report.md
   pdf      : workspace/vuln_example_com/reports/report.pdf
   findings : workspace/vuln_example_com/reports/findings.json
```

Sample report excerpt (`workspace/vuln_example_com/reports/report.md`):

```markdown
# SamaritanX — Bug Bounty Report
**Target:** `vuln.example.com`
**Operator:** th3Samaritan
**Findings:** 9  (2 critical, 4 high, 2 medium, 1 low, 0 info)

## Executive summary
SamaritanX produced **9 findings** against `vuln.example.com`
(2 critical, 4 high, 2 medium, 1 low). Highest-CVSS issues:
OS command injection in `cmd`; Server-Side Request Forgery in `url`
(aws_metadata); IDOR / broken object-level authorization on `id`.

### Vulnerability chains identified
- **ssrf + exposure** — SSRF + cloud metadata exposure → IAM credential takeover
- **prompt_injection + ssrf** — Prompt injection → tool-calling SSRF / data exfiltration

## Detailed findings
### 1. OS command injection in `cmd`
- **Severity:** `CRITICAL`  (CVSS 9.8)
- **URL:** `https://vuln.example.com/diag?cmd=ping`
#### Steps to reproduce
1. Reproduce the injection by sending the recorded payload …
…
```

## Extending SamaritanX

- **Add a scanner.** Create `scanners/<name>.py` exposing `async def scan(ctx, url, params, method, form=None) -> list[dict]`. Register it in `scanners/__init__.py:REGISTRY`. Add the slug to `config.yaml:scanners.enabled`. The Vulnerability Agent will fan-out to it automatically.
- **Add an agent.** Subclass `agents.base.BaseAgent`, set `name`, `handles = ("my.kind",)`, implement `handle(task, ctx)`. Other agents reach you by `await ctx.queue.put("my.kind", payload)`. Register it in `samaritanx.py`.
- **Add a payload list.** Drop `config/payloads/<category>.txt` and call `ctx.payloads.for_category("<category>")` from the scanner.
- **Add chain rules.** Append to `agents/exploit_agent.py:CHAIN_RULES`.
- **Plug an LLM.** `core/payload_engine.py` already accepts a memory-aware feedback loop. Set `llm.enabled: true` in config and wire `anthropic` / `openai` clients into a new agent that subscribes to `kind="reason"` and emits `kind="scan"` tasks based on findings so far.
- **Mobile / cloud / mailbox surfaces.** Implement them as new agents — the queue is the only contract.

## Design notes

- **Concurrency model.** Single asyncio event loop. Workers consume `Task` objects from a shared `asyncio.PriorityQueue`. CPU-bound subprocess calls (`subfinder`, `amass`, `nuclei`) are spawned through `asyncio.create_subprocess_exec` so they never block the loop.
- **Stealth.** Two `_TokenBucket` instances per request — global + per-host. Random jitter on top. UA + Referer rotated per request. Tor support is one CLI flag.
- **WAF evasion.** Six transforms (case swap, comment injection, unicode escape, double-URL encode, parameter pollution, chunked-transfer hint) are applied on top of every payload by `core/payload_engine.py`.
- **Learning.** Every payload outcome (hit/miss) is persisted in `payload_stats`. Future runs request payloads sorted by Wilson lower-bound score so high-signal payloads run first.
- **No-LLM-by-default.** The walkthrough generator produces high-quality narratives entirely from category templates. Set `llm.enabled: true` in config to opt into model-augmented reasoning.
- **Failure isolation.** A scanner crash never sinks the run — the dispatcher logs and continues.

## Authorized use

This is offensive tooling. Only point it at:
- assets you own,
- assets covered by a public bug-bounty program whose scope and rules you have read, or
- assets where you hold explicit written authorization.

**Do not** use SamaritanX to attack third parties without permission. The author and operator (`th3Samaritan`) accept no liability for misuse.

## License

MIT — do whatever you want, attribution appreciated, no warranty.
