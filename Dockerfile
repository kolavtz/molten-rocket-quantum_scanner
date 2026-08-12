# ── Stage 1: Build Subfinder Binary ──
FROM golang:1.22-alpine AS go-builder
RUN apk add --no-cache git
RUN go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest

# ── Stage 2: QuantumShield Container ──
FROM python:3.12-slim

LABEL maintainer="QuantumShield Team"
LABEL description="Quantum-Safe TLS Scanner — PNB Cybersecurity Hackathon 2026"

RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Copy subfinder binary from builder
COPY --from=go-builder /go/bin/subfinder /usr/local/bin/subfinder
RUN chmod +x /usr/local/bin/subfinder

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt gunicorn

COPY . .

# Create results directory
RUN mkdir -p scan_results

EXPOSE 5000

# Healthcheck
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:5000/')" || exit 1

CMD ["gunicorn", "-w", "4", "-b", "0.0.0.0:5000", "--timeout", "120", "web.app:app"]
