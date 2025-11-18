# Stage 1: Builder
FROM python:3.13-slim AS builder

WORKDIR /build

# Install build dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    libffi-dev \
    && rm -rf /var/lib/apt/lists/*

# Create virtual environment
RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

# Copy project files
COPY pyproject.toml .
COPY fxtunnel/ ./fxtunnel/
COPY main.py .

# Install package
RUN pip install --no-cache-dir .

# Stage 2: Runtime
FROM python:3.13-slim AS runtime

# Security: run as non-root user
RUN groupadd -r fxtunnel && useradd -r -g fxtunnel fxtunnel

# Copy virtual environment from builder
COPY --from=builder /opt/venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

WORKDIR /app

# Copy application code
COPY --chown=fxtunnel:fxtunnel fxtunnel/ ./fxtunnel/
COPY --chown=fxtunnel:fxtunnel main.py .

# Create data directory
RUN mkdir -p /data && chown fxtunnel:fxtunnel /data

USER fxtunnel

# Environment variables
ENV FXTUNNEL_DATA_DIR=/data
ENV PYTHONUNBUFFERED=1

# Expose ports
EXPOSE 9000
EXPOSE 8080

# Health check
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8080/health')" || exit 1

# Default command
ENTRYPOINT ["python", "main.py"]
CMD ["server", "--health-port", "8080", "--log-json"]
