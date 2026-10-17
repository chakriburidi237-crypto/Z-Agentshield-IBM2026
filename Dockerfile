# ==============================================================================
# Z-AgentShield: Multi-Architecture Dockerfile
# Compatible with: x86_64 (amd64), ARM64 (aarch64), and IBM LinuxONE (s390x)
# ==============================================================================

FROM python:3.11-slim AS base

# Prevent Python from writing .pyc and buffer stdout/stderr
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONPATH=/app/src

WORKDIR /app

# Install system dependencies (including sqlite3 and build essentials for s390x)
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    sqlite3 \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

# Install python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt

# Copy source code and configuration
COPY src/ ./src/
COPY config/ ./config/
COPY dashboard/ ./dashboard/
COPY scripts/ ./scripts/
COPY README.md .

# Create non-root system user for enterprise zero-trust execution
RUN useradd -u 10001 -m -s /bin/bash appuser && \
    mkdir -p /app/data && \
    chown -R appuser:appuser /app

USER appuser

EXPOSE 8000 8501

# Health check against the FastAPI gateway
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD curl -f http://localhost:8000/health || exit 1

# Default command starts the FastAPI Security Gateway
CMD ["uvicorn", "zagentshield.api.app:app", "--host", "0.0.0.0", "--port", "8000"]
