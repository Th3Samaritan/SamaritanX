"""Bisect the slow ~100-template directory group (plan section 8 step 3)."""
import json
import subprocess
import time
from pathlib import Path

NUCLEI = Path("workspace/tools/nuclei.exe")
TPL = Path("workspace/tools/nuclei-templates/http")


def timed(label, args, timeout=60):
    t0 = time.perf_counter()
    try:
        proc = subprocess.run(args, capture_output=True, text=True,
                              encoding="utf-8", errors="replace", timeout=timeout)
        return {"label": label, "elapsed_s": round(time.perf_counter() - t0, 2),
                "exit": proc.returncode}
    except subprocess.TimeoutExpired:
        return {"label": label, "elapsed_s": round(time.perf_counter() - t0, 2),
                "exit": "TIMEOUT"}


def main():
    results = []
    for d in sorted(TPL.iterdir()):
        if not d.is_dir():
            continue
        n = len(list(d.rglob("*.yaml")))
        if n < 5:
            continue
        r = timed(f"dir:{d.name}({n})",
                  [str(NUCLEI), "-u", "http://127.0.0.1:9", "-ni", "-duc",
                   "-disable-update-check", "-silent", "-t", str(d)])
        print(r["label"], r["elapsed_s"], r["exit"])
        results.append(r)
    Path("workspace/nuclei-catalog-dir-timings.json").write_text(
        json.dumps(results, indent=2), encoding="utf-8")
    slow = [r for r in results if isinstance(r["elapsed_s"], float) and r["elapsed_s"] > 5]
    print("\nslow dirs:", slow)


if __name__ == "__main__":
    main()
