# Audit repair implementation plan

## Scope

Repair the eight reproduced defects. Preserve proof, baseline, scope and aggressive-mode gates. Validate only with offline and loopback fixtures.

## Implemented and validated repairs

| ID | Implementation | Regression |
| --- | --- | --- |
| F1 | Request-local initial scheme/host/port; strip credential headers on off-origin redirect hops. Reset context on all exits. | HTTPX redirect over mock transport. |
| F2 | Classify browser route methods in the mutation policy. | Strict-mode POST aborts. |
| F3 | Copy nested batch configuration; create unique attempt output files. | Multiple groups preserve the configured catalog. |
| F4 | Stream hashes of all selected YAML/YML files, including single-file selections. | An edit beyond the former cap changes the digest. |
| F5 | Reopen on half-open failure; settle 4xx and cancelled probes. | Expired failure window does not prevent recovery. |
| F6 | Journal intent before unlink, verify workspace containment, report failures and mark only successful removals. | Denied deletion preserves evidence and metadata. |
| F7 | Fingerprint both session, owner/viewer, tenant and role boundaries. | Different viewers remain distinct. |
| F8 | Use explicit baseline metadata; hash attack responses separately. | Absent baseline stays absent; clean and attack hashes differ. |

## Remaining roadmap implementation completed (2026-09-14)

| Item | Implementation | Acceptance evidence |
| --- | --- | --- |
| Versioned installation | `core/tool_installation.py` stores verified immutable binaries by tool/tag, atomically activates a selection, rechecks binary integrity on lookup, and supports rollback. The installer requires explicit tags. Template installation requires an explicit tag and archive checksum and prints its immutable catalog path. | Local ZIP fixtures cover checksum rejection, truncated archives, interrupted activation, version switching, rollback and tampering. |
| Fair scheduling and reservations | `core/task_queue.py` rotates origin/scanner lanes for queued tasks and bounded scanner execution slots. Priority orders each lane. Transport reserves protect 2,000 baseline and 5,000 verification operations within the default 100,000 budget. | Competing origins and scanners receive turns; cancelled waiters release capacity. Existing scanner execution and control-plane suites pass. |
| Durable resume accounting | `core/operation_ledger.py` charges operations in SQLite transactions keyed by run ID. Manifest writes are atomic; resume retains the ID and cannot increase the original cap. Missing legacy accounting fails closed. | Concurrent independent ledger connections cannot overspend; cancelled admitted work stays charged; restart preserves reserves; interrupted manifest writes preserve the previous manifest. |
| Browser readiness and CI | Routing APIs and Chromium are checked. Dedicated CI installs Chromium and rejects skipped browser tests. | Local readiness/browser tests pass; hosted CI remains unexecuted in this session. |
| Real HTTP/2 integration | `tests/test_http2_lab.py` uses a loopback HTTP/2 server and actual managed connections for two independent response streams and stalled-connection cancellation. Closed writers are removed from the transport registry. | Both real-socket HTTP/2 tests pass; CI invokes the lab explicitly. |
| Resource acceptance | `bench/resource_gate.py` measures three startup samples, Python allocation peak, OS process resident-memory peak, real child reaping, socket closure and registry cleanup, plus the existing accuracy/request/SQLite checks. Workload clients and temporary artifacts are closed. | All eleven checks pass. Repeated Windows measurements: startup median approximately 0.18-0.24 seconds, Python peak approximately 5.7 MiB, process peak approximately 66 MiB. |

### Operational details

Use `python -m bench.install_smoke_tools --version "ffuf=<tag>"` (repeat `--version` for other tools), `--no-activate` to stage, `--activate TOOL TAG` to select, and `--rollback TOOL` to restore the previous verified selection. Existing fixed-path binaries remain usable until a version is selected. No binaries were downloaded or switched during this implementation; installation failure tests use local fixture archives.

Template installation retains `--templates-only` but now requires `--template-version` and `--template-sha256`. Set `external_tools.nuclei_templates` to the printed immutable `http` directory. This avoids silently changing a configured catalog.

Admitted operations remain charged after cancellation because transmission may already have started. Cancelled scanner-slot waiters have no transport charge. Resume requires the original manifest and ledger; an older run without usage records must be started explicitly as a new run. Scope and aggressive-mode checks remain before accounting.

Resource thresholds are configurable under `resource_limits`. Startup uses a median of three fresh-process imports (15 seconds on Windows, 10 elsewhere); Python and process memory limits are 256 and 512 MiB. These are broad regression ceilings, not throughput claims. Measurements above were taken on Windows; other OS thresholds and the hosted workflow still need their first CI execution.

## Validation sequence

Run audit regressions, related tests, full unit tests, structural self-test, compile checks, diff checks, resource gate and local adapter smoke. Record actual results and keep pending requirements explicit.

## Validation results (2026-09-14)

- Permanent audit regression tests: 12 passed, covering all eight defects plus origin boundaries, failed journaling and single-file hashing.
- Final structural self-test: 149 passed, 0 failed; its complete unit run passed all 320 tests.
- Compilation and git diff whitespace checks passed.
- Browser readiness: required routing APIs and installed Chromium available.
- Resource gate: all 5 checks passed; 11 requests, 8 findings, SQLite connection delta 0.
- CI configuration updated locally; no hosted CI result is claimed.

The historical results above describe the first repair phase. The remaining roadmap implementations are documented in the completed table above.

- Adapter smoke: ffuf, Nuclei and subfinder all passed on retry. The initial subfinder attempt timed out before any provider request; preserve this as a startup reliability observation rather than hiding it. Logs: `workspace/repair-adapter.txt` and `workspace/repair-adapter-retry.txt`.
- CI YAML parsed successfully. UTF-8 punctuation was preserved during final diff review.

## Completion validation

- Full unit suite before final legacy-resume guard: 330 passed.
- Structural self-test: 151 passed, 0 failed.
- Focused roadmap suite after the guard: 9 passed; real HTTP/2 lab: 2 passed.
- Local ffuf, Nuclei and subfinder smoke: all passed on the first attempt in this phase.
- Expanded resource gate: all 11 passed; native and Python peak memory recorded.
- Logs: `workspace/roadmap-unit.txt`, `workspace/roadmap-selftest.txt`, `workspace/roadmap-resource-final.txt`, `workspace/roadmap-adapter.txt`.
- Hosted CI and newly downloaded release binaries were not executed; no claim is made about those environments.

## Subfinder smoke root cause and correction

The repeated timeout was caused by the crtsh source attempting a direct PostgreSQL
connection on port 5432 before falling back to HTTP. Diagnostics captured both
connection timeouts and database connection-limit errors; no HTTP gateway
operation was admitted during that initial attempt. The v2.16.0 upstream source
confirms this sequence. This also invalidated the earlier assumption that the
crtsh smoke was wholly local.

The managed command builder now defaults to the reviewed hackertarget HTTP source
and rejects crtsh, mixed source lists and unreviewed selectors before launching.
The smoke stub returns the expected hostsearch text from an in-process provider.
Timeout collection preserves partial output, names the exception and deadline,
terminates the process and waits for cleanup. Regression tests cover source
selection/rejection and a real timed-out Python child with retained diagnostics.

Five consecutive corrected runs passed ffuf, Nuclei and subfinder. Results are in
`workspace/subfinder-fixed-smoke-1.txt` through `-5.txt`. The original diagnostic
logs remain as evidence; no further crtsh diagnostic attempts are required.

Final correction validation: 334 unit tests and 151 structural checks passed;
all 11 resource checks, compilation and diff checks passed. Five consecutive
three-adapter smoke runs passed; subfinder took 0.135-0.204 seconds per run.
Full validation log: `workspace/subfinder-fixed-selftest.txt`.

## Current re-validation (2026-09-15)

Re-ran the required gates on the current working tree (Windows host):

- Full unit suite: **367 tests passed**.
- Structural self-test: **162 passed, 0 failed**.
- `compileall` (core, agents, scanners, reporting, assessments, bench,
  samaritanx.py): exit 0.
- `git diff --check`: clean.
- `python -m bench.resource_gate`: **all 11 checks passed** (SQLite leak delta
  0, 13 requests, startup/memory/cleanup gates).
- `python -m bench.adapter_smoke`: ffuf, Nuclei and subfinder all passed.

The first real Juice Shop lifecycle run (see the automation plan §20) also
exercised the repair paths — transport scope enforcement, strict mutation
policy and the operation ledger — and surfaced one harness defect, fixed here:
`bench/lab_runtime.command` decoded Docker CLI output with the Windows default
cp1252 codec, so a non-ASCII byte killed the subprocess reader thread, left
`stderr` as `None`, and masked the real failure as
`'NoneType' object has no attribute 'strip'`. The helper now forces
`encoding="utf-8", errors="replace"` and tolerates missing `stderr`/`stdout`;
`tests/test_assessment_automation.RuntimeDecodingTests` covers both paths.

Two further transport defects were found and repaired while running the real
lab benchmark (details and measurements in the automation plan §20):

- `TransportBlocked` policy/budget denials and `asyncio.CancelledError` were
  recorded as origin circuit failures, so policy denials and deadline
  cancellations opened the breaker and blocked healthy tests.
- The breaker opened on absolute failure counts alone; it now also requires a
  minimum failure rate so isolated timeouts cannot take a healthy origin down.

Effect on the local lab: blocked scanner executions 330 → 0 and completed
executions 433 → 498 at the same 600 s budget. Regression tests:
`tests/test_audit_regressions.py::CircuitPolicyTests` and the failure-rate
cases in `tests/test_milestone2.py`.
