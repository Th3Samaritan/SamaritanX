# Legacy scan artifacts — superseded, kept for reference only

These files are the raw outputs of an **early June 2026 scan** (targets:
`arewagate.com`, `subcription.seentrad.com`) produced **before** the proof-gate
pipeline existed (`core/proof_gate.py`, `core/revalidate.py`, the desync-capture
smuggling detectors, and the two-fetch broken-auth / sensitive-path
confirmation).

They are **not** representative of what SamaritanX emits today and must not be
read as canonical output:

- `findings.json` — 45 findings, of which the tool's own later revalidation
  reproduced **0**. Dominated by timing-only HTTP/2 "smuggling" (emitted at
  CVSS 9.0 with no captured desync) and "200 = admin" broken-auth findings that
  actually flagged the target's **login page**.
- `revalidation*.json` — the revalidation passes that reproduced 0 / dropped the
  broken-auth set, i.e. the evidence these were false positives.
- `exploitation.json`, `*.log`, `*.jsonl` — supporting run logs.

Under the current code these findings would never reach the report: timing-only
smuggling and unconfirmed authz checks are quarantined to `candidates.json` by
the proof-gate, and only findings carrying a captured, re-tested response are
presented. Regenerate fresh output with `python samaritanx.py scan <target>`
rather than trusting anything in this folder.
