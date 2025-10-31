# Multi-stage build for SecureFix
FROM python:3.11-slim AS builder

# Install build dependencies
RUN apt-get update && apt-get install -y \
    gcc \
    g++ \
    make \
    cmake \
    git \
    && rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /build

# Copy dependency files
COPY pyproject.toml ./
COPY README.md ./

# Install Python dependencies (without source code to cache this layer)
RUN pip install --no-cache-dir --upgrade pip setuptools wheel && \
    pip install --no-cache-dir build

# Copy source code
COPY securefix ./securefix

# Build the package
RUN python -m build

# =============================================================================
# Final stage - slim runtime image
# =============================================================================
FROM python:3.11-slim

# Install runtime dependencies AND build tools for llama-cpp-python
RUN apt-get update && apt-get install -y \
    git \
    curl \
    gcc \
    g++ \
    make \
    cmake \
    && rm -rf /var/lib/apt/lists/*

# Create non-root user for security
RUN useradd -m -u 1000 securefix && \
    mkdir -p /securefix /data /models && \
    chown -R securefix:securefix /securefix /data /models

# Set working directory
WORKDIR /securefix

# Copy built package from builder
COPY --from=builder /build/dist/*.whl /tmp/

# Install SecureFix with all optional dependencies
RUN pip install --no-cache-dir --upgrade pip && \
    WHEEL_FILE=$(ls /tmp/*.whl) && \
    pip install --no-cache-dir "$WHEEL_FILE[llamacpp]" && \
    rm -rf /tmp/*.whl

# Copy application files
COPY --chown=securefix:securefix securefix ./securefix
COPY --chown=securefix:securefix config ./config

# Download and setup security corpus (if not mounting as volume)
# This can be commented out if you prefer to mount corpus as volume
RUN python -m securefix.corpus_downloader --corpus-path /securefix/remediation/corpus || true

# Create directories for persistent data
RUN mkdir -p /data/reports /data/fixes /data/chroma_db

# Switch to non-root user
USER securefix

# Set environment variables
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PATH="/home/securefix/.local/bin:$PATH"

# Volumes for persistent data
VOLUME ["/data", "/models", "/securefix/remediation/corpus"]

# Default command shows help
ENTRYPOINT ["securefix"]
CMD ["--help"]

# Health check (optional - useful for orchestration)
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD securefix --help || exit 1

# Labels for metadata
LABEL maintainer="HakAl" \
      description="Static Application Security Testing with Smart Remediation" \
      version="0.1.0"