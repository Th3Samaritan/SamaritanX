#!/usr/bin/env bash
# =====================================================================
# SamaritanX — installer for Kali Linux (also works on Debian/Ubuntu)
# =====================================================================
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT"

bold()  { printf '\033[1m%s\033[0m\n' "$*"; }
green() { printf '\033[32m%s\033[0m\n' "$*"; }
warn()  { printf '\033[33m%s\033[0m\n' "$*"; }
fail()  { printf '\033[31m%s\033[0m\n' "$*"; exit 1; }

[[ "$EUID" -eq 0 ]] || warn "running unprivileged — apt steps will use sudo"

bold "==> system packages"
sudo apt-get update -y
sudo apt-get install -y --no-install-recommends \
    python3 python3-venv python3-pip pipx git curl jq \
    libpango-1.0-0 libpangoft2-1.0-0 libcairo2 libgdk-pixbuf-2.0-0 \
    libffi-dev libssl-dev libxml2-dev libxslt1-dev tor \
    chromium

bold "==> recon / scanner CLI tools (apt)"
sudo apt-get install -y --no-install-recommends \
    amass subfinder nuclei ffuf sqlmap httpx-toolkit || \
    warn "some tools may be missing in apt — install manually with go install"

bold "==> python virtualenv"
python3 -m venv .venv
# shellcheck disable=SC1091
source .venv/bin/activate
pip install --upgrade pip wheel
pip install -r requirements.txt

bold "==> playwright browsers"
python -m playwright install chromium || warn "playwright install failed — JS render disabled"

bold "==> nuclei templates"
nuclei -update-templates -silent || warn "nuclei templates update failed"

bold "==> done"
green "Activate the venv with:  source .venv/bin/activate"
green "Then run:               python samaritanx.py self-check"
green "Or kick off a scan:     python samaritanx.py scan example.com --walkthrough"
