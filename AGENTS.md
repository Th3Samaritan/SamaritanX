# AGENTS.md — working in SamaritanX

Offensive tooling. Only point it at assets you own, assets in a public
bug-bounty program scope you have read, or assets under explicit written
authorization.

## Commands

- Tests: `python -m unittest discover -s tests`
- Structural self-test (imports, scanner signatures, config/registry
  consistency, agent routing): `python selftest.py`
- Offline smoke of the full pipeline against a local lab is done with
  `selftest.py --live` (needs a reachable test target) — do NOT run live
  scans against third parties from CI.
- Compile check: `python -m compileall -q core agents scanners reporting samaritanx.py`

Run the test suite + selftest before finishing any change. Both must be green.

## Architecture rules

- Agents only talk through `core/task_queue.TaskQueue` — never call each other.
- Scanners are pure async functions `scan(ctx, url, params, method, form)`
  registered in `scanners/__init__.py::REGISTRY`; add new scanners to BOTH
  the registry and `config/config.yaml:scanners.enabled` or the self-test
  fails.
- **Proof-gate rule (do not weaken):** a finding only reaches the report if
  `core/proof_gate.poc_status` says `verified` — a captured `metadata.poc`
  (via `core/poc.proof_record`), a hard detection (`oob`/`marker`), or a
  successful revalidation. Unproven signals belong in `candidates.json`.
- Detectors must be baseline-gated where the signal can be static (marker
  already on the clean page = not a finding). See `core/baseline.py` and the
  sqli/rce/ssrf scanners for the pattern.
- State-changing probes (mass assignment, anonymous mutations, reset emails,
  race submissions) must be gated behind `safety.aggressive`.
- CVSS numbers must come from `core/cvss.py` — the vector, score and severity
  band must agree.

## Secrets

- Never commit keys/tokens. Config uses `{ENV:NAME}` expansion (see
  `config/config.yaml` `llm.api_key`, `hackerone.api_token`).
- `workspace/`, `*.sqlite`, `*.log` are gitignored runtime artifacts.

## Style

- No comments that restate the code; comments explain *why*.
- Follow the existing module docstring style (what/why, then code).
- Commit messages: imperative subject line, blank line, bullet body of
  user-visible changes (see git log for house style).
