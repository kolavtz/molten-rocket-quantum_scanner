FROM python:3.12-slim

LABEL maintainer="QuantumShield Team"
LABEL description="Quantum-Safe TLS Scanner — PNB Cybersecurity Hackathon 2026"

WORKDIR /app

ENV DEBIAN_FRONTEND=noninteractive

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    g++ \
    && rm -rf /var/lib/apt/lists/*

# Install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt gunicorn

# Copy project files
COPY config.py .
COPY src/ src/
COPY web/ web/
COPY scan.py .

# Create results directory
RUN mkdir -p scan_results

# Healthcheck
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s \
    CMD ["sh", "-c", "python -c \"import urllib.request, os; urllib.request.urlopen('http://localhost:' + os.environ['PORT'])\" || exit 1"]

# Run with gunicorn for production; PORT must be provided by platform
CMD ["sh", "-c", "exec gunicorn -w ${WEB_CONCURRENCY:-4} -b 0.0.0.0:${PORT:?PORT is required} --timeout 120 web.app:app"]
