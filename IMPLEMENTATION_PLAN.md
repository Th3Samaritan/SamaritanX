# SamaritanX implementation plan

Updated: 2026-09-11

## 1. Objective and scope

Make scanner regression coverage explicit, make supported external tools observable through the managed transport, and enable those adapters with reproducible local validation.

This document records both the implementation already completed and the remaining work. It is a plan and status record, not a claim that every scanner branch, external provider, template, or operating system has been validated.

The current scope is:

1. Provide repeated positive/clean fixtures for every registered scanner family.
2. Install and smoke-test actual Nuclei, ffuf, and subfinder binaries locally.
3. Enable adapters with scope checks, request budgets, rate limits, cancellation, and explicit configuration.
4. Install a local Nuclei HTTP template catalog and resolve its outstanding startup-performance issue.

No third-party live scan is part of this plan. Local tests use localhost servers or in-process transport/provider replays. Operational scans remain limited to owned assets, reviewed public bug-bounty scope, or explicit written authorization.

## 2. Current status

| Workstream | Status | Evidence or limitation |
| --- | --- | --- |
| Paired scanner fixtures | Implemented | All 35 registered families have at least one repeated positive/clean detection-branch pair. |
| Local HTTP fixtures | Implemented | 16 families run through a local HTTP server. |
| Observation and response replays | Implemented | 19 families use controlled HTTP, browser, form, format, or protocol observations. |
| External gateway and adapters | Implemented | Nuclei, ffuf, and subfinder use authenticated local proxy routing. |
| Real-binary smoke tests | Passed | ffuf 2.2.1, Nuclei 3.11.1, and subfinder 2.16.0 produced expected local fixture results. |
| Adapter configuration | Enabled | Workspace-local binaries are preferred before PATH. |
| Nuclei template installation | Completed | Release 10.4.8; 11,245 HTTP YAML templates installed, plus supporting files. |
| Full Nuclei catalog startup | Resolved | Measured ~26s startup for the full catalog; the >180s symptom was execution on live targets. Catalog now runs as deterministic per-directory batches with per-group states and the shared request budget. |
| Individual installed template validation | Passed | One installed template validated successfully; this is not full-catalog validation. |
| Last full unit suite | Passed | 265 tests. |
| Last structural self-test | Passed | 141 checks. |
| Compile and whitespace checks | Passed | Recorded with the catalog-startup resolution. |

The smoke tests and full test results were recorded during the implementation. The catalog timeout and sample validation were confirmed on September 11. Runtime evidence is stored under `workspace/`, which is gitignored.

## 3. Existing foundations to preserve

Earlier implementation work provides the foundation for these changes:

- Durable queued jobs with leases and completion tracking.
- Shared transport scope, rate, cancellation, and operation-budget controls.
- Scanner execution records and coverage review.
- Bounded, redacted evidence bundles with integrity hashes.
- Fresh-client verification, evidence expiry, and finding lifecycle history.
- Offline review and workflow-policy observation checks.

Relevant modules include `core/job_store.py`, `core/task_queue.py`, `core/transport.py`, `core/scan_execution.py`, `core/evidence.py`, `core/verification.py`, `core/review.py`, and `core/workflow_policy.py`.

These foundations are not new work proposed by this document. The implementation must continue to respect the following repository rules:

- Agents communicate through `TaskQueue`.
- Scanners retain the async `scan(ctx, url, params, method, form)` interface and registry/config consistency.
- Only findings accepted as verified by the proof gate reach reports; unproven signals remain candidates.
- Static signals require a clean baseline where applicable.
- State-changing probes require `safety.aggressive`.
- CVSS vectors, scores, and severity bands must agree through `core/cvss.py`.
- Credentials and generated runtime artifacts are not committed.

## 4. Workstream A: paired scanner fixtures

### Implementation method

1. Identify a concrete detection branch in each registered scanner.
2. Supply a positive fixture that exercises that branch and a clean control that lacks its evidence.
3. Invoke the real scanner rather than returning a preconstructed finding.
4. Replace network or browser observations only where a live local implementation is impractical.
5. Assert the expected finding category or title branch. Other legitimate informational candidates must not be mistaken for failure of the selected clean control.
6. Repeat each side twice, resetting mutable fixture state between observations.
7. Keep the fixture inventory synchronized with the registry through a consistency test.

The positive side can represent a detector signal or candidate. A positive fixture does not independently prove exploitability or authorize bypassing the report proof gate.

### Fixture inventory

| Scanner family | Fixture type | Selected behavior |
| --- | --- | --- |
| sqli | Local HTTP | SQL error signal versus clean response. |
| xss | Local HTTP | Unencoded reflection versus encoded reflection. |
| lfi | Local HTTP | File-content indicator versus clean response. |
| ssrf | Local HTTP | Metadata indicator versus simple URL reflection. |
| open_redirect | Local HTTP | Controlled redirect destination versus clean response. |
| hpp | Local HTTP | Duplicate-parameter behavior versus ordinary parsing. |
| host_header | Local HTTP | Host reflection versus unchanged response. |
| cors | Local HTTP | Reflected origin with credentials versus clean response. |
| cache_poisoning | Local HTTP | Persisted header influence versus clean response. |
| path_normalization | Local HTTP | Protected-path variant versus denied/public controls. |
| version_bypass | Local HTTP | Accessible privileged version sibling versus denied control. |
| idor | Local HTTP | Object/identity-change signal versus clean response. |
| nosqli | Local HTTP | Operator-shaped login behavior versus rejected control. |
| xxe | Local HTTP | File-content response versus disabled entity expansion. |
| crlf | Local HTTP | Injected response header versus clean response. |
| security_headers | Local HTTP | Missing policies versus hardened response headers. |
| csrf | Form observation | Missing token signal versus a token-bearing form. |
| deserialization | Format observation | Serialized-format candidate versus ordinary text. |
| dom_xss | Browser observation | Token in observed sinks versus no matching sink. |
| websocket | Message transcript | SQL-error reply versus ordinary reply. |
| api | HTTP response replay | Sensitive-field exposure versus ordinary fields. |
| graphql | HTTP response replay | Sensitive schema field versus ordinary schema field. |
| oauth | HTTP response replay | Implicit-flow advertisement versus authorization-code control. |
| idor_deep | HTTP response replay | Private cross-identity markers versus denied second identity. |
| jwt_priv_esc | HTTP response replay | Forged-token acceptance versus rejection. |
| rce | HTTP response replay | Injected marker after clean baseline versus ordinary response. |
| prompt_injection | HTTP response replay | Sentinel emission versus input echo. |
| upload | HTTP response replay | Accepted and fetched upload versus rejected upload. |
| prototype_pollution | HTTP response replay | Prototype-property response signal versus unchanged response. |
| param_miner | HTTP response replay | Accepted hidden parameter versus ignored input. |
| account_takeover | HTTP response replay | Reset-flow host reflection versus fixed-host response. |
| web_cache_deception | HTTP response replay | Private content available anonymously versus denied access. |
| smuggling | Timing/HTTP transcript | Repeated differential with captured response versus prompt control. |
| h2_smuggling | Downgrade transcript | Downgrade artifact versus absent artifact. |
| stored_xss | Browser observation | Persisted token with execution observation versus reflection-only candidate. |

### Files

- `bench/coverage.py`: inventory and fixture classifications.
- `tests/test_scanner_lab.py`: local HTTP server and paired scanner execution.
- `tests/test_scanner_replays.py`: initial form, format, browser, and WebSocket pairs.
- `tests/test_remaining_fixtures.py`: remaining response/protocol pairs and registry consistency.

### Detector correction found by the fixtures

The path-normalization clean fixture exposed a false positive: a rewrite header could be ignored while the public home page was treated as bypass evidence. The scanner now compares the rewrite response with a clean request to the same destination and rejects an unchanged response.

This correction is in `scanners/path_normalization.py`.

### Acceptance criteria

- Every registered family appears in an executable fixture set.
- Both sides of each selected branch pass on repeated execution.
- Mutable state does not contaminate later cases.
- Replay results are labeled separately from local HTTP integration results.
- Fixture precision/recall values are not presented as production accuracy estimates.
- No test relaxes the proof gate to make a positive case pass.

## 5. Workstream B: managed external-tool adapters

### Architecture and implementation

`core/external_tools.py` implements an authenticated HTTP/TLS gateway and a managed process wrapper. `core/transport.py` connects these adapters to the shared controller and resolves local executable paths.

The execution flow is:

1. Resolve a supported executable from the configured binary directory or PATH.
2. Validate its command shape against a tool-specific option allowlist.
3. Start a loopback proxy with temporary credentials and certificate material.
4. Add mandatory proxy flags and an isolated configuration environment.
5. Check each proxied destination before forwarding it.
6. Apply shared rate and operation controls, plus the external request budget.
7. Block mutations unless aggressive mode is enabled.
8. Capture available HTTP evidence.
9. On completion, failure, timeout, or cancellation, release the process and proxy resources.

Tool-specific behavior:

- **ffuf:** force its forwarding proxy option; discovery falls back to native handling when the adapter fails.
- **Nuclei:** force proxy/internal proxy use, HTTP-only template selection, disabled update checks, and disabled Interactsh. Accept configured local template paths.
- **subfinder:** force proxy use and disable update checks; the smoke harness selects one passive provider for deterministic testing.
- **Amass and other unsupported executables:** remain blocked by the managed adapter.

This is cooperative routing. Trusted binaries must honor their proxy configuration. It is not an OS egress sandbox, and a smoke pass does not prove that every possible tool feature uses the proxy.

### Integration files

- `core/external_tools.py`
- `core/transport.py`
- `core/config_validator.py`
- `agents/discovery_agent.py`
- `agents/recon_agent.py`
- `agents/vuln_agent.py`
- `tests/test_external_tools.py`

### Validation already implemented

- Supported and rejected command shapes.
- Local executable resolution.
- Rejection of remote Nuclei template paths.
- Authenticated HTTP and HTTPS forwarding.
- Request-budget exhaustion before another upstream request.
- Scope denial before forwarding.
- Separate checking of redirect destinations.
- Mutation restrictions.
- Proxy authentication and Host mismatch handling.
- Process cancellation and resource cleanup.

## 6. Workstream C: reproducible binary installation and smoke tests

### Installation method

`bench/install_smoke_tools.py` downloads official Windows AMD64 release archives, verifies the published archive checksums, and extracts only the expected executables into `workspace/tools`.

It records versions, source URLs, archive hashes, and executable hashes in `workspace/tools/manifest.json`.

The template installation mode downloads the official tagged template source archive, extracts HTTP templates and supporting files within the workspace, and records its source and digest in `workspace/tools/templates-manifest.json`. The template archive digest is recorded for provenance; this is distinct from verification against a separately published archive checksum.

### Smoke method

`bench/adapter_smoke.py` launches the actual binaries through the managed adapters:

| Tool | Test destination | Required observable result | Recorded result |
| --- | --- | --- | --- |
| ffuf 2.2.1 | Local HTTP fixture | Discover the expected path and account for requests. | Passed; two operations. |
| Nuclei 3.11.1 | Local HTTP fixture and a custom fixture template | Produce the expected template match and account for its request. | Passed; one operation. |
| subfinder 2.16.0 | HTTPS provider emulator behind the proxy | Parse and return the expected fixture subdomain. | Passed; one operation. |

Subfinder's provider response is emulated; this does not establish that a real provider account, quota, or live service is operational. Nuclei's smoke uses one controlled template; it does not test the whole installed catalog.

Reproduction commands, from the repository root on Windows AMD64:

```powershell
python -m bench.install_smoke_tools
python -m bench.install_smoke_tools --templates-only
python -m bench.adapter_smoke
```

Installation requires network access to official release sources. Smoke tests do not send scan requests to third-party targets. Binaries, templates, and result files remain gitignored runtime artifacts.

## 7. Enabled configuration

The repository configuration now contains:

```yaml
external_tools:
  enabled: true
  binary_dir: ./workspace/tools
  nuclei_templates: ./workspace/tools/nuclei-templates/http
  request_budget: 250
  verify_tls: true
```

Paths are relative to the working directory; the documented commands run from the repository root. The installed binaries and template catalog exist in this workspace, but they are not included in a fresh clone.

Disabling adapters is reversible: set `external_tools.enabled` to `false`. Existing native fallbacks remain available where implemented. Do not weaken scope, proof, or mutation controls to make an adapter run succeed.

## 8. Remaining work: Nuclei catalog startup

### Resolution (measured 2026-09-12)

The investigation is complete. The recorded measurements are in
`workspace/nuclei-catalog-check.json` (progressive selections) and
`workspace/nuclei-catalog-dir-timings.json` (per-directory bisect).

**Measured facts**

- Full HTTP catalog (11,245 templates) loads and starts in ~26 seconds
  direct-invoked (closed-port target); no startup timeout is reproduced.
- Per-directory cold runs are all bounded (max 4.4s, `technologies`);
  an earlier 15s reading for the first ~100-template group was a
  cold-filesystem/antivirus transient and did not reproduce warm.
- No individual pathological template or directory was found.

**Conclusion:** the previously observed >180s was not catalog *startup* —
it was *execution*: running the full catalog against a live target spends
the wall-clock on real requests, and one unbounded subprocess consumed the
whole window while losing all coverage on timeout.

**Implemented correction (smallest evidence-backed)**

- `agents/vuln_agent._run_nuclei` now runs the catalog as deterministic
  per-directory batches, one managed adapter invocation each, with a
  per-group timeout (`external_tools.nuclei_group_timeout`, default 120s).
- Every group records its own execution state (`completed` / `timed_out` /
  `skipped` / `failed` with reason) — partial coverage is explicit, and the
  shared request budget bounds the total across groups (observed: second
  group reported `scanner request budget exhausted`, first completed).
- Per-group jsonl outputs plus an aggregated host jsonl are written.

**Revalidation performed**

- Adapter smoke (ffuf/nuclei/subfinder through the gateway): passed.
- Batched production path against the local lab: `apis` group completed,
  `backups` group bounded by the budget — both states recorded.
- Full unit suite (265), structural self-test (141), compile and
  `git diff --check` pass.

**Related fixes made during revalidation**

- `core/scan_execution.execution_key` crashed on mixed-type dict keys
  (bool vs str from merged config) — the digest now uses a canonical
  string-keyed form.
- `core/transport` gained an external-provider allowlist so credential
  validators / OSINT / notifications remain reachable in the active phase
  (previously "scope denied" in the target-scope policy). The GCP API-key
  validator now correctly confirms live keys against googleapis.

## 9. Verification and delivery checklist

Run these checks after implementation changes:

```powershell
python -m unittest discover -s tests
python selftest.py
python -m compileall -q core agents scanners reporting bench samaritanx.py
git diff --check
python -m bench.runner inventory
```

Run `python -m bench.adapter_smoke` when adapter behavior, command construction, certificate handling, or executable resolution changes. The Windows smoke result must not be generalized to other operating systems or untested versions.

Current saved evidence:

- `workspace/unit-validation.txt`
- `workspace/structural-validation.txt`
- `workspace/adapter-smoke.json`
- `workspace/nuclei-catalog-check.json`
- `workspace/tools/manifest.json`
- `workspace/tools/templates-manifest.json`

Delivery checklist:

- [x] Paired fixture coverage for all 35 registered families.
- [x] Fixture types and limitations documented.
- [x] Actual supported binaries installed and locally smoke-tested.
- [x] Adapters enabled with local executable resolution.
- [x] Local Nuclei HTTP catalog installed.
- [x] Full unit suite and structural checks passed during implementation.
- [x] Full-catalog startup delay diagnosed and resolved (execution-bound, not startup-bound — batched groups with per-group states and shared budget).
- [x] Production catalog selection revalidated after that correction (batched adapter path: completed + budget-bounded groups recorded).

## 10. Scope exclusions and honest limits

The completed implementation does not provide the following capabilities. They remain outside the current delivery unless explicitly included in the proposed roadmap below:

- OS-level isolation of external executables.
- An Amass adapter.
- Live provider-account validation or third-party scan testing.
- Real-browser integration coverage for replay-only fixtures.
- Exhaustive branch coverage for all scanners or all Nuclei templates.
- Automatic publication or external report submission.

Further improvements should be driven by measured failures and observed coverage gaps. The immediate next implementation task is the catalog startup investigation in section 8.


## 11. Additional improvement roadmap

Status update (2026-09-12): **Milestone 1 is implemented** — the four P1 items
below are done (see §11.13 for delivery evidence). P2/P3 items remain proposed.

Status update (2026-09-14): **Milestone 2 and Milestone 3 are implemented** —
see §11.14 (circuit breakers, resumable template batches, database recovery)
and §11.15 (real-browser/protocol labs, proof decision traces, resource
regression gates) for delivery evidence.

Status update (2026-09-14): **Milestone 4 is implemented** — see §11.16
(evidence retention/export controls and conservative cross-tool grouping).

| Priority | Improvement | Outcome | Dependency |
| --- | --- | --- | --- |
| P1 | Offline readiness checks | **Implemented** — `core/readiness.py` + `samaritanx.py doctor` (human + `--json`), checks cached by executable hash/config digest, zero network by design. | Catalog investigation. |
| P1 | Version pinning and run manifests | **Implemented** — `core/run_manifest.py`: run id, engine/tool/template/config(redacted)/scope digests, schema versions, comparison view; orchestrator writes the manifest and execution rows reference the run id. | Existing installer manifests. |
| P1 | Structured execution states | **Implemented** — shared states + stable reason codes in `core/scan_execution`; `scanner_executions` carries run_id/exit_code/phase/durations/diagnostics; `execution_summary` separates completed from incomplete. | Existing execution records. |
| P1 | Unified safety and credential boundaries | **Implemented** — session credentials are origin-bound (stripped crossing origins), `transport.strict_mutations` rejects unclassified mutations without `safety.aggressive` while sanctioned login flows stay allowed; external gateway mutation policy unchanged. | Shared transport. |
| P2 | Circuit breakers and fair budgets | **Implemented** — `core/circuit.py`: per-origin closed/open/half-open breakers, deterministic clock, read-only recovery probes, high-latency failure counting; wired into the HTTP client (fast rejection with `circuit_open` reason, blocked accounting) and the execution states. | Structured execution states. |
| P2 | Resumable template batches | **Implemented** — nuclei groups carry template digests; `--resume` skips completed groups only when the digest is unchanged; per-attempt output files (stale output never imported); parse failures recorded as `output_parse_error`/partial. | Measurements showing batching helps. |
| P2 | Real-browser and protocol labs | **Implemented** — `tests/test_browser_lab.py` (real headless chromium: DOM-XSS, postMessage sinks, multi-step stored XSS) and `tests/test_protocol_lab.py` (real websockets server) against local runtimes; browser launches fall back to the full chromium build when the headless shell is missing. | Existing paired fixtures. |
| P2 | Proof decision traces | **Implemented** — `core/decision_trace.py`: versioned candidate → verification-method → outcome traces with evidence hashes, attached to verified findings and rendered in review detail; secrets redacted. | Evidence bundles and proof gate. |
| P2 | Database recovery and migrations | **Implemented** — `core/migrations.py`: ordered transactional migrations with pre-upgrade SQLite backups (failed migrations preserve the old database), `PRAGMA user_version` versioning, offline `integrity_report` (recoverable vs manual), conservative job-lease recovery verified by tests. | Existing SQLite stores. |
| P3 | Evidence retention and export controls | **Implemented** — `core/retention.py`: inventory-first per-class age policy (logs/traces/bundles/lifecycle), dry-run by default, deletion only with `retention.enabled: true` + `--apply`; every removal recorded in `retention/removals.jsonl` and findings flagged `evidence_removed` so a missing artifact is never read as a fix. `core/export_package.py`: allowlisted/bounded profiles, a second redaction pass, and a per-file hash manifest. | Evidence schema and lifecycle history. |
| P3 | Cross-tool finding grouping | **Implemented** — `core/grouping.py`: conservative fingerprints over family/origin/method/path/parameter/identity/proof; exact groups vs `suggested` (ambiguous) clusters; non-destructive annotation; reversible, audited manual groups in `core/memory.py` (`finding_groups`/`group_history`, add/dissolve). | Run manifests and proof traces. |
| P3 | Resource regression gates | **Implemented** — `bench/resource_gate.py`: fixed localhost workload with deterministic assertions (SQLite leak delta, detection coverage, bounded request count), artifact written to `workspace/bench/resource-gate.json`. | Stable local workloads. |

### 11.1 Offline readiness checks

**Why:** Missing executables, catalog paths, or browser hooks should be explained before a scan is underway.

**How to implement:**

1. Add a proposed `doctor` CLI command with human-readable and JSON output.
2. Extend configuration validation with path types, positive budgets, and incompatible-option checks.
3. Separate cheap filesystem/import checks from optional bounded process checks. Default readiness must not contact providers, download dependencies, or scan targets.
4. Report capabilities separately: HTTP adapters, browser interception, catalog readability, and database access. Identify which operation an unavailable optional dependency affects.
5. Cache expensive successful checks by executable hash and relevant configuration digest, with expiry; do not cache scope or permission decisions this way.
6. Show results at startup and through offline review.

**Components:** `samaritanx.py`, `core/config_validator.py`, `core/transport.py`, and proposed `core/readiness.py`.

**Acceptance:** Missing binary, invalid path, unwritable workspace, and unavailable browser hook each produce a specific actionable result. Tests prove offline readiness makes no network requests. Catalog existence is never called full-catalog validation.

### 11.2 Version pinning and reproducible run manifests

**Why:** Automatically selecting the latest release can change results between otherwise identical runs.

**How to implement:**

1. Add explicit version arguments to `bench/install_smoke_tools.py`.
2. Install versions side by side and validate their checksums before changing the configured path. Retain the previous installation for rollback.
3. Generate a run manifest containing run ID, engine revision/content digest, runtime/platform, executable hashes, template selection digest, redacted configuration digest, scope-policy digest, timestamps, and schema versions.
4. Reference the run ID from execution rows and evidence bundles. Store identity labels and fingerprints rather than raw credentials.
5. Add a comparison view explaining changed inputs before comparing findings.

**Components:** Installer, `core/scan_execution.py`, `core/orchestrator.py`, `core/evidence.py`, and proposed `core/run_manifest.py`.

**Acceptance:** Identical pinned inputs produce identical input digests; modified binaries or templates change them. Failed installation leaves the previous configured version usable. Rollback preserves run history.

### 11.3 Structured failure and coverage states

**Why:** Empty output cannot distinguish successful clean execution from timeout, missing dependencies, budget exhaustion, or parsing failure.

**How to implement:**

1. Define shared states: completed, skipped, blocked, timed out, cancelled, failed, and partial.
2. Add stable reason codes such as `scope_denied`, `request_budget_exhausted`, `catalog_startup_timeout`, `dependency_missing`, and `output_parse_error`.
3. Store phase, exit code, request count, startup duration, execution duration, and bounded redacted diagnostics separately from narrative summaries.
4. Route adapter/scanner persistence through one helper. Treat empty output as clean only after successful execution and parsing.
5. Display attempted, completed, and incomplete work separately in review and report coverage.
6. Migrate database fields used for filtering and aggregation explicitly, preserving historical rows.

**Components:** `core/scan_execution.py`, `core/memory.py`, adapters, `agents/vuln_agent.py`, `core/review.py`, reporting.

**Acceptance:** Nonzero exit, invalid JSON, timeout, cancellation, and exhausted budgets remain distinct and cannot become “no vulnerabilities found.” Partial work is excluded from completed-coverage totals.

### 11.4 Unified safety and credential boundaries

**Why:** Independent scanner restrictions can drift, and redirects or secondary transports can accidentally carry credentials across origins.

**How to implement:**

1. Inventory state-changing operations and credential-bearing transport paths without adding new attack probes.
2. Add operation metadata identifying reads, mutations, and unclassified capabilities. HTTP method alone does not establish safety.
3. Enforce mutation policy at shared boundaries while retaining scanner-specific guards. Reject unclassified state-changing actions by default.
4. Restrict session credentials to their configured origin or explicit credential scope. Strip Authorization, Cookie, and configured secret headers when crossing that boundary.
5. Check each redirect and browser navigation against applicable scope before proceeding.
6. Record policy reason codes without including secret header values.

**Components:** `core/transport.py`, `core/http_client.py`, session handling, browser guards, scanner dispatch, adapters.

**Acceptance:** Local two-origin tests prove credentials do not reach an unauthorized second origin. Mutation tests cover aggressive mode on and off. Policy failures remain visible coverage gaps and never weaken the proof gate.

### 11.5 Circuit breakers and fair budget allocation

**Why:** Repeated endpoint failures or one expensive scanner can consume most of a run.

**How to implement:**

1. Extend existing throttling and backoff rather than creating a competing limiter.
2. Track bounded per-origin windows of failures, latency, and rate-limit responses.
3. Add closed, open, and half-open states with configurable cooldowns and a small number of read-only recovery checks.
4. Retry only explicitly retryable operations. Do not automatically retry mutations or reset budgets during retries.
5. Allocate work fairly across scanners and origins, retaining capacity for baselines and verification.
6. Persist deferred/circuit-blocked work with reason codes.

**Components:** Transport, HTTP client, task queue, execution records, configuration.

**Acceptance:** Deterministic clock-driven tests cover failure, recovery, cancellation, and concurrent workers. Total operation limits remain exact under contention. A failing origin cannot indefinitely starve a healthy one.

### 11.6 Resumable template batches

**Why:** Large selections can have expensive startup and lose progress on interruption.

**How to implement:**

1. Complete section 8 first; batch only if measurements justify it.
2. Create a deterministic manifest of selected template paths, hashes, filters, and exclusions.
3. Partition it into stable batches with persistent job IDs.
4. Use a unique output file for every attempt. Validate status and output format before transactional import; never ingest stale output from a previous attempt.
5. Preserve one shared total budget across batches, retries, and compatible resume.
6. Resume only compatible unfinished work. Do not automatically replay potentially state-changing work whose completion is uncertain.
7. Deduplicate imports while retaining batch provenance and partial-completion status.

**Components:** `core/job_store.py`, task queue, Nuclei agent, adapters, proposed template manifest helper.

**Acceptance:** Interrupted local runs retain completed batches. Changed template contents invalidate incompatible resume state. Failed attempts cannot import stale evidence. Batching cannot multiply the run budget.

### 11.7 Real-browser and protocol integration labs

**Why:** Replayed observations validate detector decisions but can miss browser lifecycle, certificate, socket-framing, or routing defects.

**How to implement:**

1. Keep fast replay tests as the default regression layer.
2. Add isolated local pages for DOM execution, encoded content, stored reflection, and cross-origin message handling, each with positive and clean controls.
3. Run an actual browser using production routing guards, deterministic state, and bounded navigation timeouts.
4. Add localhost WebSocket and HTTP/2 servers exercising handshake, framing, timeout, and cancellation behavior.
5. Upgrade inventory labels only after corresponding real integration tests exist.
6. Put slower tests in a separate CI stage. Missing runtimes must be reported as unexecuted coverage, not a passing integration result.

**Components:** Scanner labs, browser/protocol fixtures, `bench/coverage.py`, CI workflow.

**Acceptance:** A real browser distinguishes execution from encoded text. Actual sockets exercise budgets and cleanup. Tests use no external vulnerable services, and results state which integration jobs ran.

### 11.8 Proof decision traces

**Why:** Reviewers need to understand verification and quarantine decisions without reconstructing an entire run.

**How to implement:**

1. Define a versioned trace containing baseline references, observed signal, identity context, verification attempts, expiry result, policy outcome, and final gate decision.
2. Reference evidence hashes instead of duplicating response bodies.
3. Separate transport observations from detector interpretations.
4. Have the proof gate attach stable reason codes and explanations; a scanner narrative cannot override the decision.
5. Render a concise timeline through offline review.
6. Preserve prior decisions as lifecycle state changes.

**Components:** Proof gate, verification, evidence, memory, review.

**Acceptance:** A reviewer can locate baseline, decisive observation, revalidation, and final reason. Missing/expired evidence remains inconclusive or quarantined. Traces contain no raw credentials.

### 11.9 Database recovery and migration checks

**Why:** Durable jobs need coherent behavior across upgrades, crashes, and partial writes.

**How to implement:**

1. Introduce explicit schema versions and ordered migrations for job/finding stores.
2. Make migrations transactional and create consistent pre-upgrade backups using SQLite backup facilities.
3. Define recovery for expired leases, incomplete imports, and vanished workers. Requeue only operations whose retry policy allows it.
4. Add local crash-injection tests around claim, evidence write, import, and completion boundaries.
5. Add offline integrity reporting that distinguishes recoverable conditions from required manual action.
6. Document backup restoration and compatibility constraints; never silently discard unreadable history.

**Components:** `core/job_store.py`, `core/memory.py`, startup orchestration, migration/recovery tests.

**Acceptance:** Failed migration preserves the old database. Expired workers cannot overwrite newer results. Restored backups preserve evidence references. Uncertain mutation completion requires review, not automatic repetition.

### 11.10 Evidence retention and export controls

**Why:** Captured content can remain sensitive after common credentials are redacted, and indefinite retention grows workspaces unnecessarily.

**How to implement:**

1. Separate retention policies for logs, response traces, verified bundles, and lifecycle metadata.
2. Default cleanup to an inventory/dry-run report. Delete only through an explicit cleanup action or deliberately enabled retention policy.
3. Preserve explicit removal records for referenced evidence; never silently break links.
4. Add export profiles with allowlisted fields, bounded excerpts, and another redaction pass using known session secrets.
5. Keep internal history separate from shareable packages; include exported-file hashes in a manifest.
6. Test nested JSON, repeated headers, URLs, and supported encoded credential forms.

**Components:** Evidence, reporting/export, configuration, proposed retention helper.

**Acceptance:** Dry runs change nothing. Export fixtures contain none of their known secrets. Removed evidence cannot be interpreted as proof that a finding was fixed.

### 11.11 Conservative finding grouping across tools

**Why:** Duplicate observations overwhelm review, but broad deduplication can erase meaningful input or identity boundaries.

**How to implement:**

1. Define a conservative fingerprint using family, origin/path, method, input location, identity boundary, and relevant proof attributes.
2. Do not normalize away parameter names, positions, or other security-relevant distinctions.
3. Keep observations independently stored, relating likely duplicates to a canonical review item.
4. Present ambiguous similarities as suggestions rather than destructive merges.
5. Preserve source, run IDs, and all evidence versions in groups.
6. Make manual grouping and splitting reversible and auditable.

**Components:** Memory, scanner ingestion, external output import, lifecycle and review.

**Acceptance:** Two tools can be grouped without deleting either observation. Different methods, inputs, tenants, and proof boundaries remain distinct unless reviewed. Splitting restores original relationships.

### 11.12 Performance and resource regression gates

**Why:** Functional tests can pass while startup slows, request counts grow, or cancellation leaks resources.

**How to implement:**

1. Define fixed local workloads for startup, scanning, evidence capture, and cancellation.
2. Measure elapsed phases, request counts, evidence size, open resources, and peak memory where available.
3. Establish per-environment baselines before choosing thresholds; label thresholds as project targets.
4. Keep correctness/resource-count assertions strict and use repeated samples with tolerant bounds for noisy timing measurements.
5. Save benchmark artifacts with run manifests and tool/template versions.
6. Gate documented regressions and explicitly report unavailable measurements.

**Components:** `bench/`, transport cleanup tests, evidence tests, CI.

**Acceptance:** Deliberate extra requests and process leaks fail deterministic checks. Timing gates do not depend on one noisy sample. Results identify workload, platform, runtime, and dependency versions.

### 11.13 Milestone 1 delivery evidence (2026-09-12)

- `core/readiness.py` + `samaritanx.py doctor` (human and `--json` output,
  exit 1 on failures). Live run reports every capability separately; a
  missing chromium was flagged as `browser_interception: FAIL` with its
  affected operations, then resolved by installing the full chromium build.
- `core/run_manifest.py` — run manifests written per run
  (`workspace/<target>/run_manifest.json`); execution rows reference the run
  id (observed: `scanner_executions.run_id` == manifest `run_id`); config
  redaction strips credentials from digests; comparison view lists changed
  inputs.
- Structured states — `core/scan_execution.STATUSES`/`REASON_CODES`;
  `scanner_executions` gained `run_id`, `exit_code`, `phase`, `startup_s`,
  `duration_s`, `diagnostics` (additive migration, historical rows kept);
  `execution_summary` separates completed from incomplete; nuclei groups
  record exit codes, durations and per-group states.
- Credential boundaries — session credentials are origin-bound (login URL
  host); cross-origin requests strip credential-shaped headers and all
  session cookies; `transport.strict_mutations` rejects unclassified
  mutations without `safety.aggressive` while sanctioned login flows remain
  allowed (three-way policy test: off / strict / aggressive).
- Tests: `tests/test_milestone1.py` — 13 acceptance tests covering the
  four P1 items, including an offline-only readiness guarantee test.
- Checks: 278 unit tests, 143 structural checks, compile, `git diff --check`
  all passing.

### 11.14 Milestone 2 delivery evidence (2026-09-12)

- **Circuit breakers** — `core/circuit.py` + HTTP-client integration: opens
  after N failures in a rolling window (or a single high-latency response),
  rejects fast with the stable `circuit_open` reason (never billed to the
  budget), half-open recovery with read-only probes only; deterministic
  clock-driven tests cover open/close/re-open/probe-budget/high-latency and
  prove a failing origin cannot starve a healthy one. A scanner that produced
  nothing because the circuit was open is recorded `blocked`, never
  "completed / no vulnerabilities".
- **Resumable template batches** — each nuclei group records its template
  digest; `--resume` skips only groups whose digest is unchanged (edited
  templates invalidate the resume decision); per-attempt output files mean
  stale output can never be imported; unparseable output lines produce a
  `partial` status with the `output_parse_error` reason.
- **Database recovery and migrations** — `core/migrations.py`: ordered
  transactional migrations keyed by `PRAGMA user_version`, pre-upgrade
  SQLite online backups (a failed migration leaves the old database usable
  and the backup is the explicit rollback path), offline `integrity_report`
  separating recoverable (expired leases) from manual-review conditions
  (interrupted mutations), surfaced through `doctor`.
- Tests: `tests/test_milestone2.py` (12 tests) + migration/integrity
  integration; full suite now 290 unit tests, 145 structural checks,
  compile and whitespace checks passing.

### 11.15 Milestone 3 delivery evidence (2026-09-14)

- **Real-browser integration lab** — `tests/test_browser_lab.py` runs against
  a local HTTP lab with real headless chromium: DOM-XSS detection fires only
  on the vulnerable page (encoded page stays silent), postMessage sinks
  confirmed on the vulnerable page and ignored on the safe page, and the
  stored-XSS flow submits a payload over a form and observes execution on the
  served page (critical finding with `executed_at`/`sinks` metadata). The
  browser is launched through `core/browser_pool.launch_chromium`, which
  falls back to the full chromium build when the headless shell is missing.
- **Protocol integration lab** — `tests/test_protocol_lab.py` drives a real
  `websockets` server and confirms the SQLi error-detection path against
  live socket frames.
- **Proof decision traces** — `core/decision_trace.py` builds versioned
  traces (candidate → verification method → outcome → evidence hashes);
  attached to verified findings by the reporting agent and rendered in the
  review detail view; secrets redacted through the run-manifest redactor.
- **Resource regression gate** — `bench/resource_gate.py` runs a fixed
  localhost workload with deterministic assertions (SQLite connection leak
  delta ≤ 0, sqli/xss/security-header detection, request count ≤ 400) and
  writes `workspace/bench/resource-gate.json`.
- **Browser-fidelity fixes** — JS hooks tag `alert`/`confirm`/`prompt`
  without invoking the native dialog (a real `alert()` blocks headless
  navigation until Playwright handles it); the dom_xss postMessage probe
  passes the token as an evaluate argument instead of embedding it in the
  evaluated source (which self-triggered the `eval` sink); the stored_xss
  browser session stays inside the `async_playwright()` lifetime (launching
  inside and driving outside closed the driver connection).
- Tests: `tests/test_browser_lab.py` (5) + `tests/test_protocol_lab.py` (1)
  + `bench/resource_gate.py`; full suite now 296 unit tests, 146 structural
  checks, compile and whitespace checks passing.

### 11.16 Milestone 4 delivery evidence (2026-09-14)

- **Evidence retention** — `core/retention.py` classifies every workspace
  artifact into logs, raw response traces, verified bundles or lifecycle
  metadata, each with an independent age limit (lifecycle metadata keeps
  longest). `retention` reports an inventory and a dry-run plan and changes
  nothing; deletion requires both `retention.enabled: true` and `--apply`.
  Every removal is written to `retention/removals.jsonl` (class, reason,
  sha256), and findings whose bundle was removed are flagged
  `evidence_removed` — `proof_gate.poc_status` then returns a candidate with
  the explicit "absence is not proof of a fix" reason, so cleanup can never
  manufacture a fix.
- **Shareable export controls** — `core/export_package.py` builds packages
  from allowlisted profiles (`shareable`: identifiers + bounded narrative only;
  `internal`: bounded request/response) with a second redaction pass using the
  persisted session's known secrets, then writes a `manifest.json` hashing
  every emitted file. Redaction now also strips percent-encoded (single and
  double) forms of known secrets; nested JSON, repeated headers and URL query
  credentials are covered by tests.
- **Conservative cross-tool grouping** — `core/grouping.py` fingerprints
  findings on family, origin, method, path, input location, identity boundary
  and proof boundary; two tools' observations are only an *exact* group when
  every dimension agrees, while shared-family/origin/path records with a
  differing method, parameter, tenant or proof state surface as `suggested`
  with the differing dimensions listed. Annotation is non-destructive and
  manual groups are stored reversibly and audited (`finding_groups`,
  `finding_group_members`, `group_history`, schema v9); dissolving or splitting
  restores the original relationships without deleting any observation.
- **CLI** — `samaritanx.py retention <target>` (dry-run/`--apply`),
  `export <target> [--profile] [--out]`, and `group <target>`
  (`--apply`/`--split`/`--list`).
- Tests: `tests/test_milestone4.py` (12 acceptance tests); full suite now 308
  unit tests, 149 structural checks, compile and whitespace checks passing.

## 12. Proposed delivery sequence

### Milestone 1: startup and trustworthy status

Resolve or bound the catalog timeout, then implement readiness checks, version pinning/run manifests, and structured execution states.

**Exit condition:** Operators can determine what is installed, what selection will run, what completed, and why anything did not complete.

### Milestone 2: consistent controls and recoverable execution

Implement safety/credential boundaries, circuit breakers, and database recovery. Add template batching only if catalog measurements support it.

**Exit condition:** Interrupted or unhealthy runs retain coherent state, do not leak credentials, and cannot exceed budgets through retry/resume.

### Milestone 3: stronger validation and review

Add real-browser/protocol integration labs, proof decision traces, and resource regression gates.

**Exit condition:** Critical transport behavior runs against local real runtimes, and report decisions can be traced to evidence and policy.

### Milestone 4: maintainable evidence and findings

Add retention/export controls and reversible cross-tool grouping.

**Exit condition:** Operators can retain/share necessary proof and manage related observations without losing history.

For every milestone: preserve backward compatibility where possible, add failure-path tests, run repository-required checks, and distinguish implemented behavior from pending work in documentation. No delivery date or effort estimate is asserted before the scope and catalog behavior have been measured.
