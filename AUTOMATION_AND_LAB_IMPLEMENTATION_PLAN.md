# SamaritanX automation, Juice Shop and mobile implementation plan

Date: 2026-09-14
Status: Implemented offline; validated against a real local Juice Shop on
2026-09-15 (first runs partial, gaps explicit). Remaining blocked work is
runtime-only: repeated benchmark runs, real mobile devices and a macOS iOS
host. See §20 for measured results and current blockers.

## 1. Intended outcome

Turn SamaritanX into a repeatable assessment workflow: accept a bounded assessment profile, check prerequisites, prepare identities and approved lab resources, discover attack surface, schedule relevant tests, verify evidence, report coverage and gaps, and clean up owned resources. An operator should be able to run an entire supported workflow with one command and inspect why every check passed, failed, was skipped or remained inconclusive.

Use a fresh local OWASP Juice Shop instance as the first end-to-end benchmark. The goal is to steadily increase reproducible vulnerability detection and challenge coverage. Neither a successful process exit nor a green infrastructure test means every Juice Shop bug was found. Juice Shop challenges also include tutorial, coding, puzzle and business-process tasks; the challenge count is not a count of independently reportable vulnerabilities.

Extend the same orchestration to web authorization/privilege boundaries, read-only Windows/Linux privilege assessments, and Android/iOS static and dynamic assessments. Keep evidence standards consistent without pretending static observations are verified exploits.

This document describes implementation; the proposed commands and files below do not exist unless explicitly identified as existing. It supersedes neither the historical repair record nor the existing implementation record.

## 2. Current baseline and actual blockers

| Area | Existing implementation | Remaining work |
| --- | --- | --- |
| Web pipeline | Recon, crawling, discovery, vulnerability, authorization, logic, verification and reporting agents; TaskQueue coordination | Unified automation profile, explicit phase outcomes and local-lab orchestration |
| Proof and transport | Proof gate, baseline checks, request budgets, durable operation accounting, scope enforcement, fair scheduling | Integrate all new work without bypassing these controls |
| Benchmark | `bench/runner.py`, scorer, paired fixtures, resource gate and adapter smoke | Versioned Juice Shop lifecycle, full challenge inventory and honest coverage metrics |
| Web privilege testing | Authorization/logic agents and multiple-session support | Reproducible role/tenant fixtures, workflow state and stronger negative controls |
| Local privilege review | Windows/Linux inventory and configuration candidates in `assessments/local_privilege.py` | More evidence-aware checks and isolated OS lab validation; no exploit execution currently |
| Android static | Plain/compiled APK manifest inspection | Resource resolution, policy inspection, signing inventory and deeper code analysis |
| iOS static | IPA Info.plist inspection | Entitlement/signing inventory and bounded executable analysis |
| Mobile dynamic | Attach to existing Android/iOS Appium sessions; app identity checks; bounded UI flows | Session provisioning, broader runtime checks, traffic collection and actual device validation |
| Mobile traffic | Scoped HAR review and sanitized GET/HEAD API seeds | Automated capture, correlation and authenticated backend workflows |

The current measured baseline is 363 unit tests and 162 structural checks
passing, plus resource (11/11) and three-adapter smoke gates, with the first
real Juice Shop runs recorded in §20. Real mobile devices have not been tested
in this workspace.

Docker CLI and Docker Desktop are installed. On 2026-09-15 the Docker Desktop
Linux engine was started and reported server 29.1.3; the pinned Juice Shop
image pulled and three owned benchmark runs executed (§20). Windows is the
current host; actual iOS XCUITest execution still needs an appropriately
configured macOS host, and no real Android/iOS device validation has run. A
remote device host is a separate prerequisite, not something this Windows
checkout can manufacture.

## 3. Invariants

- Target only owned labs or explicitly authorized assessment scope. The Juice Shop command creates its own local instance and accepts no arbitrary remote target.
- Agents communicate through `core/task_queue.TaskQueue`. New scanners retain the pure async signature and enter both `scanners/__init__.py::REGISTRY` and `config/config.yaml:scanners.enabled`.
- Only findings accepted by `core/proof_gate.poc_status` enter verified reports. Use `core/poc.proof_record`; preserve baseline gating. Candidates, unavailable checks and runtime failures remain distinct.
- State-changing probes require `safety.aggressive`. Enable this only through an explicit disposable-lab profile for Juice Shop; ordinary profiles retain their existing safe default.
- Derive CVSS vectors, scores and severity through `core/cvss.py`.
- Keep secrets in environment references or protected runtime storage. Never save credentials in committed profiles, examples, shared reports or process command lines.
- The benchmark answer key and challenge state are scorer inputs only. They must never be used to manufacture scanner evidence or mark application challenges solved.
- Bound operations, time, storage, response size and subprocess lifetime. Missing prerequisites cannot produce a pass.

## 4. Proposed operator interface

```powershell
# Proposed: validate a profile without scanning
python samaritanx.py assess --profile config/assessment.example.yaml --preflight

# Proposed: execute an authorized assessment
python samaritanx.py assess --profile config/assessment.example.yaml

# Proposed: create a fresh local Juice Shop, scan, measure and clean up
python -m bench.juice_shop run --deadline 600

# Proposed: retain only this run's lab for inspection
python -m bench.juice_shop run --deadline 600 --keep-lab

# Proposed: inspect an existing benchmark artifact without network access
python -m bench.juice_shop report --run workspace/juice-shop/<run-id>
```

The existing `scan`, `local-audit`, `mobile-static`, `mobile-dynamic` and `mobile-traffic` commands remain usable. The new assessment command composes them through shared services, avoiding duplicate scanning implementations. `--deadline` governs active assessment time; dependency preparation and cleanup have separate explicit bounds. Document total possible wall time.

Automatic means one invocation performs the declared workflow. Scheduling is optional future work and is not enabled by this plan. No recurring job, external notification or publication is created implicitly.

## 5. Phase A: profile and execution contract

### Implementation

1. Add `core/assessment_profile.py` with a versioned schema: target kind, exact scope, artifact paths, identity references, requested capabilities, runtime endpoints, budgets, mutation policy, reporting and resource ownership.
2. Validate unknown fields, contradictory settings, missing paths, URL credentials and invalid budgets before any side effects. Resolve relative paths against the profile directory. Persist a sanitized effective profile and its hash.
3. Add `core/assessment_runner.py` to track phases: pending, running, completed, partial, blocked, failed and cancelled. Give every phase structured timestamps, dependencies, artifact references and failure reasons.
4. Reuse the existing manifest, operation ledger, transport controller and TaskQueue. Add assessment metadata around them rather than a competing queue or budget implementation.
5. Add capability-specific preflight checks for Docker, browser runtime, external adapters, APK/IPA inputs, Appium platform/driver, current app identity and API reachability. Checks must be bounded and report missing capabilities independently.
6. Establish exit semantics: 0 means the requested execution contract completed, 2 means prerequisites or requested coverage are unavailable, and 1 means an unexpected execution failure. A vulnerability found is not a tool error. A separate strict benchmark option can fail a regression threshold.
7. Implement cancellation and resume: retain charged operations and immutable run scope; never repeat uncertain mutations automatically. Mark interrupted steps as requiring state reconciliation before replay.

### Acceptance

Invalid profiles fail before network or subprocess work. Cancellation closes owned resources. Resume cannot increase the original budget or silently broaden scope. Optional capabilities may be skipped explicitly; missing required capabilities make the assessment partial or blocked.

## 6. Phase B: local Juice Shop lifecycle

### Implementation

1. Add `bench/juice_shop.py` and a small `bench/lab_runtime.py` lifecycle helper. Pin a reviewed official image version in a versioned lab manifest; record the pulled image ID and digest. Do not silently use a moving `latest` tag.
2. Check Docker with a short subprocess timeout. If the daemon is unavailable, report its actual error. Document the Windows Docker/WSL prerequisite and a separately implemented Node distribution fallback; do not silently swap runtime during a scored run.
3. Pull only the declared image with a bounded deadline. Dependency download requires network access during preparation; it is separate from scan traffic. Capture version, digest and startup logs.
4. Create a unique container with a run ownership label. Publish the application port on `127.0.0.1` only, with an automatically allocated host port. Use no privileged mode, host mounts, Docker socket mounts or host networking. Set sensible CPU/memory limits supported by the runtime.
5. Poll local readiness with bounded response reads and redirect rejection. Verify an application identity/version response, not just any HTTP 200. Persist the actual origin.
6. Use a fresh container per benchmark. Take challenge snapshots before scanning and after scanning; detect unexpected application restarts or resets so they cannot invalidate measurements silently.
7. On completion, cancellation or error, collect logs and remove only a resource whose ownership label matches this run. `--keep-lab` records its name, local URL and exact cleanup command. Never delete unrelated containers, images or workspaces.
8. If a Node fallback is implemented, pin an official release and supported Node version, verify available release checksums, bind loopback explicitly, and track only the spawned process tree. Record the fallback as a different runtime in comparisons.

### Acceptance

Tests cover occupied ports, missing Docker, image pull failure, failed readiness, scan failure, interruption, cleanup failure and keep-lab. A local run proves loopback-only publication and leaves no owned process/container after ordinary completion.

## 7. Phase C: local-only scan profile and discovery repairs

### Implementation

1. Generate an isolated workspace, SQLite database, manifest, operation ledger and exact-origin scope rule for each lab run. Avoid reuse of the default project database.
2. Introduce an explicit `recon.local_only` mode in `agents/recon_agent.py`. Preserve the supplied scheme and port when probing the seed. Skip passive HTTP providers, DNS enumeration, wildcard detection, AXFR, keyed sources, permutations and vhost enumeration entirely in this mode.
3. Disable remote enrichment, Wayback/GitHub/cloud discovery, external tool adapters, external OOB, LLM services, secret validation against providers, notification webhooks and publishing in the generated lab profile. Inspect the actual code paths; configuration switches alone are insufficient if a collector ignores them.
4. Scope-check browser requests, redirects, WebSockets and raw transports through the existing transport layer. Reject off-origin traffic. Record blocked operations. The current gateway is cooperative, so do not describe it as an OS network sandbox; container-side egress isolation is a separate runtime capability to validate.
5. Seed the root URL immediately into normal discovery. Exercise the existing JavaScript mining and API discovery first; fix failures in SPA route/API extraction revealed by the lab.
6. If explicit lab API seeds are needed, version them, identify their provenance and label the run `seeded`. Preserve a separate unseeded discovery measurement so supplied endpoints do not inflate discovery claims.
7. Bound scanner concurrency and request rate to keep Juice Shop stable. Preserve reserved baseline/verification budgets. Report budget exhaustion and task timeouts as incomplete execution, not absence of vulnerabilities.
8. Repair the existing `bench/runner.py` workspace propagation and failure reporting before reusing it. Its scan path currently does not pass the selected workspace to `run_scan`; malformed or absent reports must not silently score as successful empty results.

### Acceptance

A fixture using a nondefault loopback port reaches the correct origin. Tests prove zero passive-source/adaptor calls in local-only mode and reject redirects to another origin. Every report belongs to the generated workspace and run ID. A failed scanner or missing report is visible in the benchmark result.

## 8. Phase D: identities and application workflows

### Implementation

1. Add `bench/juice_shop_setup.py` to create two disposable test users through ordinary local registration/login flows. Store sensitive state only under the run workspace with restricted access where supported; redact all report exports.
2. Generate existing-format auth recipes or runtime session handles for those users. Populate separate owned resources, such as distinct baskets, through ordinary workflows. Track setup actions separately from vulnerability-testing actions and take the benchmark baseline after setup.
3. Test same-role cross-user access first, using an owner-success control and a viewer-denied expectation. Supply privileged identities only when provisioned through a documented lab mechanism; never label a normal user admin by convention.
4. Reuse AuthzAgent/LogicAgent to compare anonymous, owner, peer and privileged sessions where available. Check semantic content and resource ownership rather than relying on status codes alone. Preserve tenant/role dimensions in grouping.
5. Add a bounded workflow schema for prerequisite steps, actions, assertions and cleanup. Each action names its expected app/origin and mutation policy. Persist checkpoints but not secret input values.
6. Track authentication expiry and refresh explicitly. Expired sessions produce unavailable comparisons, not fabricated access-control vulnerabilities. Do not automatically retry a mutation with uncertain outcome.

### Acceptance

Paired protected/vulnerable ownership fixtures produce the correct results. A login page returned with 200 is not a successful authorization bypass. Baseline setup does not count as scanner challenge progress. Missing admin identity is reported as an untested role boundary.

## 9. Phase E: verification and Juice Shop coverage

### Implementation

1. Add `bench/juice_shop_catalog.py` to validate and store the lab's challenge inventory and state. Treat server strings as data, strip unsafe presentation markup, and bound the response size. Avoid reading solutions or using solver-only routes in the scan.
2. Add a versioned mapping between challenge IDs, vulnerability categories, prerequisites, supporting scanner capabilities and expected proof. A mapping can be one-to-many or have no scanner equivalent; review it per Juice Shop release.
3. Add `bench/juice_shop_score.py` to keep separate counts for discovered endpoints, scheduled/completed checks, verified findings, candidates, unavailable checks and application-observed solved challenge changes.
4. Preserve the proof gate. Strengthen individual scanner verification only where a reproduced false positive/negative demonstrates a gap. Use clean baselines, controlled differences, bounded revalidation and explicit evidence records.
5. Do not call an unmatched finding a false positive when the answer key is incomplete. Report it as unmatched pending adjudication. Measure precision only against reviewed labels; show the sample size. Measure recall only against a defined evaluable expected set and list exclusions.
6. Include before/after solved IDs, pre-solved IDs, remaining IDs, challenge resets, setup effects and runtime health. Distinguish scanner-confirmed vulnerabilities from scoreboard observations; neither substitutes for the other.
7. Generate `benchmark.json`, `benchmark.md`, challenge snapshots, a coverage matrix and a ranked backlog of missing capabilities. Redact response evidence and link to retained local proof bundles where appropriate.
8. Group remaining challenges by cause: undiscovered surface, missing identity/state, unsupported mechanism, candidate without proof, execution failure, or non-scanner challenge. Do not assign a cause without evidence; use unknown where necessary.

### Acceptance

Tests cover a pre-solved challenge, no progress, progress after scanning, reset during scanning, malformed API output, absent report, duplicate findings, candidates-only output and unmatched legitimate findings. None can accidentally claim complete coverage. Report both numerator and denominator for every percentage.

## 10. Phase F: privilege assessment depth

### Web and API privilege boundaries

Extend the existing authorization agents rather than adding an unrelated privilege exploit engine. Build a declared role/action matrix for each profile, covering read access, allowed updates and privileged actions. Use disposable objects for aggressive tests. Require owner/privileged positive controls and lower-privilege negative controls before reporting a boundary violation. Capture the exact session labels, request/response evidence and observed state change with credentials removed.

Add regression cases for cross-user access, same-user access, legitimate shared resources, missing sessions, expired sessions, identical error pages and redirects. Test tenant separation independently of user-role separation. Privilege testing in Juice Shop demonstrates only the lab's supported web boundaries; it does not validate Windows/Linux local escalation.

### Windows/Linux local assessment

1. Expand the inventory schema with OS/build, collection privilege, file ownership/ACLs, executable path existence, service identity, sudo rule context and collection errors. Version the schema and accept offline snapshots.
2. Improve candidate confidence by checking prerequisites: for example, an unquoted service path alone is not proof without relevant path permissions and execution conditions. Separate setuid presence from unsafe ownership or writable dependencies.
3. Add bounded collectors for supported checks. Use fixed commands or native APIs; never execute commands embedded in imported snapshots. Limit filesystem traversal and record inaccessible paths as unknown.
4. Add remediation guidance and reference evidence for each rule. Preserve candidate status when actual exploitability has not been established.
5. Validate with paired snapshots and disposable Windows/Linux VMs containing known safe and unsafe configurations. Do not use the operator's workstation as an exploitation lab.

Automatic OS exploit execution, token theft, persistence, kernel exploitation, rooting and jailbreaking are not included in this assessment automation. If a future controlled validation mechanism is considered, it requires a separate design and acceptance scope; the existing read-only audit must not quietly acquire those behaviors.

## 11. Phase G: Android static analysis

1. Extend `assessments/android_xml.py` with bounded resource-table resolution, or isolate a reviewed parser dependency behind a narrow adapter. Resolve manifest resource references and network-security XML; explicitly retain unknown values for unsupported encodings.
2. Extend `assessments/mobile_static.py` to inventory target/min SDK, exported components, effective permissions, custom permission protection levels, backup configuration, debug settings, deep links and network policy. Interpret defaults according to the artifact's target/platform context instead of treating every flag as a vulnerability.
3. Add signing/certificate metadata through a pinned optional Android SDK tool adapter with process and output limits. Missing tooling means unavailable signing analysis.
4. Add optional bounded DEX/string analysis for endpoints, embedded credential-like material and risky API usage. Label pattern matches as candidates; a string does not prove a reachable vulnerability. Redact secret-like values in reports.
5. Make deeper interprocedural/native analysis an explicit later capability with its own dependency and resource budget. Do not advertise full data-flow analysis from string matching.
6. Test paired APKs with compiled and plain manifests, resource references, safe/insecure policies, corrupt archives, duplicate entries, extreme compression and oversized metadata. Read archive members without unsafe extraction.

Acceptance: each check identifies the artifact hash, supporting member, parser/tool version and coverage status. A parser failure cannot become a clean result. Findings requiring runtime proof remain candidates until the applicable verifier succeeds.

## 12. Phase H: iOS static analysis

1. Add bounded provisioning-profile and entitlement parsing through reviewed platform tools where required. Report absent or encrypted information as unavailable.
2. Inspect ATS exceptions, URL schemes, associated domains, document sharing, app groups, keychain access groups and debug-related entitlements with context. Avoid treating legitimate platform capabilities as vulnerabilities by default.
3. Add Mach-O metadata inspection for architectures and supported binary protection indicators, using a pinned parser/tool adapter. Distinguish simulator builds, device builds and encrypted binaries; do not claim analysis of encrypted executable contents.
4. Inventory endpoint and secret-like strings with redaction and candidate-only semantics. Correlate static evidence with later runtime observations without upgrading confidence merely because two weak signals agree.
5. Build safe/risky IPA pairs, binary/XML plist fixtures, malformed provisioning data, duplicate archive entries and encrypted/unsupported binary cases.

Acceptance: reports name unsupported capabilities and host requirements. Static analysis runs on Windows where the chosen parser supports it; macOS-only signing checks are capability-gated. No unavailable signing or runtime check is counted as passing.

## 13. Phase I: Android and iOS dynamic orchestration

### Runtime provisioning

1. Add an Appium runtime adapter under `assessments/` that validates platform, driver version, device identity, app identity and endpoint trust before creating a session.
2. Support two distinct ownership modes: attach to an existing session, which must never be deleted by the runner, and create an owned session, which must be closed on exit.
3. For Android, support a preconfigured emulator or explicitly selected authorized device with the required driver. For iOS, connect to a configured macOS Appium/XCUITest host with the required simulator/device signing setup. Do not automatically select an arbitrary connected device.
4. Installation/reset is an explicit profile action restricted to the selected test app. Record artifact hash and installed package/bundle identity. Preserve attach-only behavior for existing commands.
5. Add bounded retry only for safe session/readiness operations; device disconnection or identity mismatch aborts dependent actions. Never silently switch apps or devices.

### Runtime checks and workflows

1. Reuse the current foreground-identity checks before every flow step. Add assertions for expected UI state and semantic checkpoints for login, logout, resource creation and account switching.
2. Extend password-field observations with platform-supported secure input evidence and safe/risky test fixtures. Raw UI dumps and typed credentials remain excluded from shared artifacts.
3. Add platform-specific checks for declared deep-link handling, webview configuration observable through supported interfaces, logout/session behavior and test-app storage only where access is available. Mark inaccessible storage/keychain data unavailable.
4. Add optional controlled traffic capture using an operator-configured local proxy. Certificate installation and device proxy changes require explicit profile ownership and restoration. If pinning prevents capture, record the gap; do not silently bypass it or infer TLS correctness from missing traffic.
5. Reuse scoped HAR import to produce sanitized backend seeds. Feed approved backend requests to existing web agents through TaskQueue with separate auth recipes. Keep app identity and API-origin scope distinct.
6. Model runtime checks with capability flags per platform. Android success cannot be reported as iOS validation; mock Appium tests cannot be reported as real-device tests.

### Acceptance

Run paired test applications on an Android emulator and iOS simulator, then perform a limited real-device smoke for each platform when devices are available. Validate disconnect, expired session, app switch, blocked capture, failed cleanup and interrupted mutation. Record host/device/OS/driver versions and evidence provenance. Platform completion remains blocked until that platform's required runtime tests actually execute.

## 14. Phase J: reports, automation feedback and usability

1. Add an assessment overview that separates verified vulnerabilities, candidates, completed checks, untested capabilities and operational errors. Link each item to its phase and evidence record.
2. Provide a capability matrix across web, API, local OS, Android static/dynamic and iOS static/dynamic. Every cell contains a status and reason, not a decorative green indicator.
3. Add reproducibility data: engine revision, profile hash, lab image digest, fixture/app hashes, adapter versions, identity labels, budgets and timestamps. Never include secret values.
4. Generate a prioritized improvement backlog from observed misses and failures. Rank by evidence strength, impact, affected coverage and implementation cost; require a reproduced case before changing detector behavior.
5. Add comparison of compatible benchmark runs. Reject or clearly label comparisons with different application versions, seeds, identity setups, scanner sets or budgets. Do not claim a performance regression from incomparable workloads.
6. Produce Markdown and JSON first, integrating with existing verified reporting. Add UI views only after the data model is stable. Do not let a dashboard conceal partial or blocked execution.

Acceptance: a reviewer can explain why a run is incomplete, reproduce a verified finding from retained evidence, and identify the next coverage gap without reading raw logs. Exports pass redaction checks.

## 15. Implementation file map

All new paths below are proposed and may be adjusted to fit repository conventions during implementation.

| Path | Responsibility |
| --- | --- |
| `core/assessment_profile.py` | Profile schema, normalization and validation |
| `core/assessment_runner.py` | Phase lifecycle, capability requirements and execution results |
| `samaritanx.py` | New assessment CLI entry point reusing shared services |
| `config/assessment.example.yaml` | Documented secret-free assessment profile |
| `bench/lab_runtime.py` | Owned lab process/container lifecycle |
| `bench/juice_shop.py` | One-command local benchmark and offline report command |
| `bench/juice_shop_setup.py` | Disposable identities and baseline workflow state |
| `bench/juice_shop_catalog.py` | Versioned challenge inventory and mappings |
| `bench/juice_shop_score.py` | Findings/coverage/challenge measurements |
| `bench/juice_shop_manifest.json` | Reviewed application version and expected setup contract |
| `bench/runner.py` | Existing workspace/failure-reporting fixes |
| `agents/recon_agent.py` | Local-only recon and exact supplied-origin handling |
| `assessments/` | Extend current local/mobile parsers and runtime adapters |
| `tests/test_assessment_runner.py` | Profiles, lifecycle, resume and cancellation |
| `tests/test_juice_shop_benchmark.py` | Lab ownership, scope, scoring and failure semantics |
| `tests/test_mobile_assessments.py` | Extend existing paired mobile/local regression fixtures |
| `tests/test_mobile_runtime.py` | Owned/attached sessions, device failures and platform checks |
| `bench/README.md` and `MOBILE_AND_LOCAL_ASSESSMENT.md` | Actual commands, setup, limitations and recorded results |
| `.github/workflows/ci.yml` | Required offline gates and opt-in isolated integration jobs |

## 16. Validation strategy

### Layer 1: offline regression

Use mocks for Docker lifecycle and Appium ownership, and paired vulnerable/protected fixtures for detection logic. Exercise malformed inputs, scope escapes, budget exhaustion, cancellation, missing dependencies, redaction and report corruption. A meaningful test asserts externally visible behavior, not just a helper's implementation details.

### Layer 2: local protocol integration

Use real loopback HTTP/Appium fixtures and existing raw HTTP/2/browser/resource tests. Prove origin enforcement, credential stripping, request accounting and cleanup with actual connections. Run adapters only against the existing local mocked-provider smoke harness; do not reintroduce direct external-provider calls.

### Layer 3: real Juice Shop benchmark

1. Verify Docker readiness and pull the pinned image.
2. Start a fresh owned container and record digest, version and local origin.
3. Prepare declared identities/state, then capture baseline challenge state.
4. Run a short unseeded smoke with a fixed budget; inspect infrastructure failures first.
5. Run a fresh deeper assessment with the documented budget, then a separately labeled seeded/authenticated pass if needed. Preserve separate results.
6. Capture final challenge state, verified findings, candidates, scanner execution records and lab logs before cleanup.
7. Reproduce consequential misses and false positives on fresh state, add paired regression cases, fix the underlying cause and rerun the affected checks.
8. Repeat the final benchmark on at least three fresh instances to expose flakiness; report per-run counts and ranges rather than selecting the best result.

Do not mark this layer complete until it has run. A failed daemon or missing image is a blocker, not an empty successful scan.

### Layer 4: platform integration

Use isolated OS VMs and dedicated mobile test applications. Require separate Android and iOS results. Device tests may be manually triggered on dedicated hosts; ordinary CI cannot substitute for unavailable Apple hardware/runtime. Keep credentials in the runner's secret store and test artifacts out of public logs.

### Required repository gates

Run after implementation changes, before declaring completion:

```powershell
python -m unittest discover -s tests
python selftest.py
python -m compileall -q core agents scanners reporting assessments bench samaritanx.py
python -m bench.resource_gate
python -m bench.adapter_smoke
git diff --check
```

The unit suite and structural self-test must both be green as required by `AGENTS.md`. `selftest.py --live` is only used with an explicitly configured reachable local test target. Hosted CI results are separate from local execution results and must be recorded honestly.

## 17. Delivery sequence and completion gates

| Milestone | Work | Depends on | Complete when |
| --- | --- | --- | --- |
| M1 | Profile contract and local-only recon fixes | Existing pipeline | Offline lifecycle/scope tests pass |
| M2 | Docker lab lifecycle and pinned manifest | Working Docker runtime | Fresh lab starts, is verified and cleans up correctly |
| M3 | Anonymous Juice Shop benchmark and honest scoring | M1, M2 | Actual run yields valid artifacts and explicit gaps |
| M4 | Two-user setup and authorization workflows | M3 | Paired identity tests and local authenticated run pass |
| M5 | Evidence-driven detector improvements | M3/M4 measurements | Each fix has a reproduced case and regression test |
| M6 | Expanded local OS audit | Profile contract | Paired snapshots and disposable VM validation pass |
| M7 | Android/iOS static depth | Profile contract | Bounded parsers and platform-specific paired fixtures pass |
| M8 | Mobile runtime provisioning and capture | M7, platform hosts | Android and iOS each pass their own runtime validation |
| M9 | Unified reports, comparisons and CI | Prior artifact contracts | Repeated compatible runs are reproducible and gaps remain visible |

Implement M1-M4 first so the project obtains real Juice Shop measurements early. Let measured failures drive M5. Local OS and mobile work have separate dependencies and completion records; do not delay the first web benchmark while waiting for an iOS host.

## 18. Success criteria and coverage goals

- One command can prepare, run, measure and clean up a supported local Juice Shop assessment without manual intermediate steps.
- Every requested phase has an explicit terminal status and reason; silent skipping is eliminated.
- Every verified report item satisfies the existing proof gate, and candidates remain separate.
- All scheduled assessment traffic remains within the declared scope; any missing transport isolation guarantee is disclosed.
- Every evaluable missed vulnerability becomes a documented coverage gap with reproduction evidence or an unknown cause, never an invented pass.
- Full challenge coverage is a stretch goal tracked per version. Set a numerical improvement target only after collecting the first real baseline. Do not declare 100% from a partial answer key or supplied solutions.
- Local OS configuration checks are described as assessments unless exploitability is independently proven.
- Android and iOS each have static and dynamic capability matrices; runtime claims are backed by that platform's actual execution.
- Required tests pass and cleanup/redaction checks succeed. Infrastructure green, benchmark coverage and platform availability are three separate acceptance dimensions.

## 19. References and change control

Use official documentation when selecting pinned versions and implementing runtime adapters:

- [OWASP Juice Shop running guide](https://help.owasp-juice.shop/part1/running.html)
- [Official Juice Shop releases](https://github.com/juice-shop/juice-shop/releases/)
- [Android UiAutomator2 driver](https://github.com/appium/appium-uiautomator2-driver)
- [iOS XCUITest driver](https://github.com/appium/appium-xcuitest-driver)

Reverify version-specific requirements during implementation. Preserve `IMPLEMENTATION_PLAN.md` and `REPAIR_IMPLEMENTATION_PLAN.md` as historical records. Update this plan with actual dates, commands, artifact locations, measured results and remaining blockers after each milestone. Mark proposed features complete only when their acceptance evidence exists.

## 20. Measured implementation status (2026-09-15)

### Offline gates (required by §16)

| Gate | Result |
| --- | --- |
| `python -m unittest discover -s tests` | **363 passed** |
| `python selftest.py` | **162 passed, 0 failed** |
| `python -m compileall -q core agents scanners reporting assessments bench samaritanx.py` | exit 0 |
| `python -m bench.resource_gate` | **11/11 passed** (SQLite leak delta 0, 13 requests, memory/startup/cleanup) |
| `python -m bench.adapter_smoke` | ffuf, Nuclei, subfinder all passed |
| `git diff --check` | clean |

### Real Juice Shop benchmark (Layer 3, first execution)

Host: Windows. Docker Desktop Linux engine 29.1.3. Image
`bkimminich/juice-shop:v19.2.1`, image ID / digest
`sha256:b3450d951d98b607805b21a4b9b4da7451b334c804ad93a79fcee490b3a7c5ad`.
Node v24.13.0 was available; the Docker path was used (Node fallback unused).

Command: `python -m bench.juice_shop run --deadline <N> [--authenticated]`

| Run id | Mode | Deadline | Identities | Status | Solved | Verified | Candidates | Executions | Cleanup |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| `7bcd90c8e1f7407f964894a15840bd35` | anon | 300 | anonymous | blocked | — | — | — | — | completed |
| `2d31ee1c666d4416926f728a907eebfa` | anon | 300 | anonymous | partial | 3 | 8 | 9 | 244/1050 | completed |
| `e01eac954c924937821777ce1e581faa` | anon | 600 | anonymous | partial | 3 | 9 | 17 | 389/1330 | completed |
| `58966544df5f423e8ce3c153b326ed94` | auth | 600 | user-a, user-b | partial | 3 | 9 | 21 | 318/1260 | completed |

The first attempt was blocked by a harness defect: `bench/lab_runtime.command`
decoded Docker CLI output with the Windows cp1252 codec, crashed the
subprocess reader thread on a non-ASCII byte, left `stderr` as `None`, and
masked the failure as `'NoneType' object has no attribute 'strip'`. Fixed by
forcing `encoding="utf-8", errors="replace"` and tolerating missing
`stderr`/`stdout`; regression tests were added
(`RuntimeDecodingTests`). This is a Layer-3 infrastructure finding, not a
scanner result.

Challenge state: 111 challenges, 0 pre-solved, no reset detected. Newly solved
by the scan on every scored run: **27 Error Handling** (Security
Misconfiguration), **59 Outdated Allowlist** (Unvalidated Redirects), **76
Security Policy** (Miscellaneous).

Verified finding categories (authenticated run): 1 critical (HTTP/2 CRLF in
pseudo-header `:path`), 1 high (`broken_auth`: privileged admin
configuration endpoint reachable without authentication), 1 medium (`exposure`:
`/.well-known/security.txt`), 6 low (`security_headers`). 21 candidates were
quarantined by the proof gate.

Cleanup verified: no container carrying the `samaritanx.lab.run` label
remained after any run. Artifacts:
`workspace/juice-shop/<run-id>/benchmark.json`, `benchmark.md`,
`challenges-before.json`, `challenges-after.json`, `lab.log`, and
`scan/<origin-slug>/reports/{report.md,findings.json,candidates.json,coverage.json}`.

### Iteration: circuit-breaker correctness (2026-09-15)

Two transport defects were reproduced and fixed while raising coverage:

- **Local policy/budget/cancel outcomes were counted as origin failures.**
  `TransportBlocked` (scope, local-only, mutation and run-budget denials) and
  `asyncio.CancelledError` were caught by the generic handler in
  `core/http_client.py` and recorded as circuit failures, so policy denials
  and deadline cancellations opened the breaker and blocked healthy
  same-origin tests. Neither is recorded now: cancellation re-raises and the
  handler checks `RequestBudgetExceeded` before counting a failure.
- **Absolute failure counts ignored the healthy majority.** The breaker opened
  after 5 failures in 60 s even when hundreds of requests had succeeded; on
  the lab the trigger was `ReadTimeout` / `status 500`. `core/circuit.py` now
  additionally requires a minimum failure *rate* (`min_failure_rate`, default
  0.5) inside the rolling window.

Measured effect on the local lab (anonymous, 600 s each):

| Run id | Cycle | Blocked | Completed | Challenges solved | Verified |
| --- | --- | --- | --- | --- | --- |
| `e01eac95` | before fixes | 240 | 389 | 3 | 9 |
| `11f52fa1` | policy/cancel fix | 324 | 476 | 3 | 9 |
| `47cdd076` | diagnostics (`last_failure=ReadTimeout`) | 330 | 433 | 3 | 9 |
| `fec01ff9` | failure-rate gate | **0** | **498** | **4** | **10** |

The fourth challenge is **97 Exposed Metrics** (Observability Failures);
27 Error Handling, 59 Outdated Allowlist and 76 Security Policy are solved on
every run. The breaker's `last_failure` reason is now captured in its snapshot
and in `benchmark.json:circuit`. Regression tests:
`tests/test_milestone2.py` (failure-rate) and
`tests/test_audit_regressions.py::CircuitPolicyTests` (policy/cancel).

### Layer and milestone status

- Layer 1 (offline regression): complete.
- Layer 2 (loopback protocol): complete — the real HTTP/2 lab and loopback
  Appium fixtures pass.
- Layer 3 (real Juice Shop): **started, not complete**. Real owned instances
  were created, scanned, scored and cleaned up; repeated fresh-instance runs,
  the strict regression threshold and answer-key adjudication remain.
- Layer 4 (platform devices): not started — no Android/iOS device or macOS
  iOS host in this workspace.
- M1 offline complete; M2 lifecycle verified by the real runs; M3 first
  measurement produced (partial); M4 exercised by the two-user authenticated
  run but no paired authorization finding and no repeat; M5 pending on those
  measurements; M6–M9 implemented offline, runtime/platform validation pending.

### Honest limits

- Every scored run hit its deadline with 652–676 tasks still queued, so the
  numbers are budget-bounded, not the tool's ceiling.
- 3 of 111 challenges solved is challenge progress, not coverage; it is not a
  recall measurement.
- No complete answer key has been adjudicated for v19.2.1, so unmatched
  findings (including the HTTP/2 smuggling and workflow step-skip findings)
  remain **pending adjudication**, not confirmed true or false positives.
- Hosted CI and real-device runs were not executed in this session.
