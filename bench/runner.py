"""Benchmark runner CLI.

Two modes:

  * score existing output — point it at an answer key and the workspace reports
    already produced by a run:

        python -m bench.runner score --answers bench/answer_key.example.json \\
            --workspace ./workspace

    It loads each target's ``reports/findings.json`` (verified) and
    ``reports/candidates.json`` (quarantined) and prints a scoreboard.

  * scan then score — run the full pipeline against each target in the answer
    key first (needs the targets to be reachable, e.g. local lab containers),
    then score:

        python -m bench.runner scan --answers bench/answer_key.example.json

Keep the answer key pointed at labs you are authorised to test (Juice Shop,
PortSwigger Academy, DVWA, bWAPP, your own broken apps). Never point the scan
mode at third-party production hosts.
"""
from __future__ import annotations

import argparse
import json
import sys
from collections import defaultdict
from pathlib import Path

from .scorer import score, format_scoreboard

from core.utils import slugify


def _load(path: Path) -> list[dict]:
    if not path.exists():
        return []
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        return data if isinstance(data, list) else data.get("findings", [])
    except Exception:
        return []


def _answers_by_target(answers: list[dict]) -> dict[str, list[dict]]:
    by = defaultdict(list)
    for a in answers:
        by[a.get("target", "")].append(a)
    return by


def score_existing(answers_path: Path, workspace: Path) -> dict:
    answers = json.loads(answers_path.read_text(encoding="utf-8"))
    by_target = _answers_by_target(answers)
    all_findings: list[dict] = []
    all_candidates: list[dict] = []
    for target in by_target:
        base = workspace / slugify(target) / "reports"
        all_findings += _load(base / "findings.json")
        all_candidates += _load(base / "candidates.json")
    result = score(all_findings, all_candidates, answers)
    return result


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="bench.runner")
    sub = ap.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("score", help="score existing workspace reports")
    s.add_argument("--answers", required=True, type=Path)
    s.add_argument("--workspace", default=Path("./workspace"), type=Path)

    sc = sub.add_parser("scan", help="scan each answer-key target then score")
    sc.add_argument("--answers", required=True, type=Path)
    sc.add_argument("--workspace", default=Path("./workspace"), type=Path)

    args = ap.parse_args(argv)

    if args.cmd == "scan":
        try:
            import asyncio
            from samaritanx import run_scan  # type: ignore
        except Exception as exc:
            print(f"scan mode needs the CLI entrypoint (run_scan): {exc}", file=sys.stderr)
            return 2
        answers = json.loads(args.answers.read_text(encoding="utf-8"))
        for target in _answers_by_target(answers):
            print(f"[bench] scanning {target} …", file=sys.stderr)
            try:
                asyncio.run(run_scan(target))
            except Exception as exc:  # noqa: BLE001
                print(f"[bench] scan of {target} failed: {exc}", file=sys.stderr)

    result = score_existing(args.answers, args.workspace)
    print(format_scoreboard(result))
    (args.workspace / "benchmark.json").write_text(json.dumps(result, indent=2), encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
