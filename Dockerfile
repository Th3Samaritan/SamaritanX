# SamaritanX — bug-bounty framework container (Kali toolchain)
#
#   docker build -t samaritanx .
#   docker run -it --rm \
#       -v "$PWD/workspace:/opt/samaritanx/workspace" \
#       -v "$PWD/config:/opt/samaritanx/config" \
#       -e TARGET_USER=... -e TARGET_PASS=... \
#       samaritanx scan example.com --scope config/scope.example.txt
#
FROM kalilinux/kali-rolling:latest

ENV DEBIAN_FRONTEND=noninteractive

# PDF (weasyprint/GTK), headless chromium, nuclei + friends
RUN apt-get update && apt-get install -y --no-install-recommends \
      python3 python3-pip python3-venv \
      libpango-1.0-0 libpangocairo-1.0-0 libgdk-pixbuf2.0-0 \
      libffi-dev shared-mime-info \
      chromium curl ca-certificates \
      nuclei subfinder ffuf && \
    apt-get clean && rm -rf /var/lib/apt/lists/*

WORKDIR /opt/samaritanx
COPY requirements.txt .
RUN pip3 install --no-cache-dir -r requirements.txt
COPY . .

# playwright's chromium isn't needed — the system chromium is used via
# browser_pool when PLAYWRIGHT_CHROMIUM_PATH is unset; keep playwright happy
ENV PLAYWRIGHT_BROWSERS_PATH=/opt/samaritanx/.pw-browsers

ENTRYPOINT ["python3", "samaritanx.py"]
