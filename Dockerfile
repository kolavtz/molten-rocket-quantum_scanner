FROM python:3.12-slim

LABEL maintainer="QuantumShield Team"
LABEL description="Quantum-Safe TLS Scanner — PNB Cybersecurity Hackathon 2026"

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
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

# Expose port
EXPOSE 5000

# Healthcheck
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:5000/')" || exit 1

# Run with gunicorn for production
CMD ["gunicorn", "-w", "4", "-b", "0.0.0.0:5000", "--timeout", "120", "web.app:app"]
