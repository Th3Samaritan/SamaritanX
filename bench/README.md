# SamaritanX benchmark harness

Turns "we made it better" into a number. It scores what the scanner **proved**
(and what it saw but couldn't prove) against a ground-truth answer key of
known-vulnerable lab targets.

## Why this exists

After the proof-gate landed, the tool optimises for *precision* — it only ships
findings it can prove. That's the right trade for bug bounty, but it means you
must watch two numbers, not one:

- **precision** — of the findings we reported, how many were real? (FP control)
- **recall** — of the real bugs, how many did we prove? (coverage)

…and a third that's unique to a proof-gated scanner:

- **gated** — real bugs a detector *saw* but couldn't turn into captured proof.
  A high `gated` count means the detector works but its proof channel is weak —
  that's where to invest (better OOB, browser verification, desync capture).

## Answer key format

A JSON array; see `answer_key.example.json`. Each entry:

```json
{"id": "juice-sqli-login", "target": "juice.local", "category": "sqli",
 "match": "/rest/user/login", "severity": "critical"}
```

`match` is a case-insensitive substring tested against each finding's
`url + parameter`. `category` must equal the finding's category.

## Recommended lab targets (authorised, local)

- **OWASP Juice Shop** — `docker run -p 3000:3000 bkimminich/juice-shop`
- **PortSwigger Web Security Academy** — per-lab hosted instances
- **DVWA**, **bWAPP** — classic injection/XSS coverage
- your own deliberately-broken apps

⚠ Only ever benchmark against targets you are authorised to test. Never point
`scan` mode at third-party production hosts.

## Usage

Score reports a run already produced:

```bash
python -m bench.runner score --answers bench/answer_key.example.json --workspace ./workspace
```

Scan the lab targets then score (needs the labs reachable):

```bash
python -m bench.runner scan --answers bench/answer_key.example.json
```

Output is a per-category scoreboard plus `workspace/benchmark.json`. Run it
before and after a change to see whether precision/recall actually moved.
