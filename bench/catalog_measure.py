"""Progressive Nuclei catalog startup measurement (plan section 8).

Runs nuclei with progressively larger template selections against a
closed local port (connection refused — template parsing dominates the
elapsed time) and records the results. Read-only; no scan target.
"""
import json
import subprocess
import sys
import time
from pathlib import Path

NUCLEI = Path("workspace/tools/nuclei.exe")
TPL = Path("workspace/tools/nuclei-templates/http")
OUT = Path("workspace/nuclei-catalog-check.json")


def measure(label: str, templates: list[str], timeout: int) -> dict:
    args = [str(NUCLEI), "-u", "http://127.0.0.1:9", "-ni",
            "-duc", "-disable-update-check", "-silent", "-stats"]
    # nuclei accepts comma-separated -t lists; individual -t args blow the
    # Windows command-line length limit above a few hundred paths
    if len(templates) == 1:
        args += ["-t", templates[0]]
    else:
        args += ["-t", ",".join(templates)]
    t0 = time.perf_counter()
    rec = {"label": label, "templates": len(templates)}
    try:
        proc = subprocess.run(args, capture_output=True, text=True,
                              encoding="utf-8", errors="replace", timeout=timeout)
        rec.update({"elapsed_s": round(time.perf_counter() - t0, 2),
                    "exit": proc.returncode,
                    "stdout_tail": (proc.stdout or "")[-400:],
                    "stderr_tail": (proc.stderr or "")[-400:]})
    except subprocess.TimeoutExpired:
        rec.update({"elapsed_s": round(time.perf_counter() - t0, 2),
                    "exit": "TIMEOUT",
                    "timeout": timeout})
    except OSError as exc:
        rec.update({"elapsed_s": round(time.perf_counter() - t0, 2),
                    "exit": f"OSError: {exc}"})
    print(json.dumps(rec, indent=2)[:600])
    return rec


def _dirs_up_to(limit: int) -> list[str]:
    """Select subdirectory groups whose combined template count first reaches
    `limit` (directory-based selection keeps command lines short)."""
    import collections
    by_dir = collections.defaultdict(int)
    for p in TPL.rglob("*.yaml"):
        rel = p.relative_to(TPL)
        by_dir[str(rel.parts[0] if len(rel.parts) > 1 else "_root")] += 1
    chosen, total = [], 0
    for d in sorted(by_dir):
        chosen.append(d)
        total += by_dir[d]
        if total >= limit:
            break
    return chosen


def main():
    results = []
    yamls = sorted(TPL.rglob("*.yaml"))
    print(f"catalog: {len(yamls)} templates")
    single = [str(yamls[0])]
    small_dirs = _dirs_up_to(100)
    medium_dirs = _dirs_up_to(1000)

    results.append(measure("single_template", single, 60))
    results.append(measure("dirs_~100", [str(TPL / d) for d in small_dirs], 60))
    results.append(measure("dirs_~1000", [str(TPL / d) for d in medium_dirs], 120))
    results.append(measure("full_catalog_dir", [str(TPL)], 300))
    OUT.write_text(json.dumps(results, indent=2), encoding="utf-8")
    print(f"\nrecorded -> {OUT}")


if __name__ == "__main__":
    main()
