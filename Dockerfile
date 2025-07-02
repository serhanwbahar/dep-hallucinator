# Dep-Hallucinator Production Dockerfile
# Multi-stage build for minimal image size and security

# Build stage - compile dependencies and cache layers
FROM python:3.11-slim as builder

# Set build arguments
ARG BUILD_ENV=production
ARG INSTALL_EXTRAS=""

# Install system dependencies for building
RUN apt-get update && apt-get install -y \
    gcc \
    g++ \
    git \
    && rm -rf /var/lib/apt/lists/*

# Create virtual environment
RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

# Copy requirements first for better caching
COPY pyproject.toml README.md /app/
WORKDIR /app

# Install dependencies based on environment
RUN if [ "$BUILD_ENV" = "production" ]; then \
        pip install --no-cache-dir -e ".[production,rich]"; \
    elif [ "$BUILD_ENV" = "full" ]; then \
        pip install --no-cache-dir -e ".[all]"; \
    else \
        pip install --no-cache-dir -e ".[rich]"; \
    fi

# Copy source code
COPY src/ /app/src/

# Install the package
RUN pip install --no-cache-dir -e .

# Production stage - minimal runtime image
FROM python:3.11-slim as production

# Create non-root user for security
RUN groupadd -r depscanner && useradd -r -g depscanner -d /app -s /bin/bash depscanner

# Install minimal runtime dependencies
RUN apt-get update && apt-get install -y \
    ca-certificates \
    curl \
    && rm -rf /var/lib/apt/lists/* \
    && apt-get clean

# Copy virtual environment from builder
COPY --from=builder /opt/venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

# Copy application
COPY --from=builder /app /app
WORKDIR /app

# Create directories and set permissions
RUN mkdir -p /app/data /app/logs /app/cache \
    && chown -R depscanner:depscanner /app

# Production configuration
ENV DEP_HALLUCINATOR_PRODUCTION=true
ENV DEP_HALLUCINATOR_ENV=production
ENV DEP_HALLUCINATOR_LOG_LEVEL=INFO
ENV DEP_HALLUCINATOR_ENABLE_FILE_LOGGING=true
ENV DEP_HALLUCINATOR_LOG_FILE=/app/logs/scanner.log
ENV DEP_HALLUCINATOR_ENABLE_METRICS=true
ENV DEP_HALLUCINATOR_ENABLE_HEALTH_CHECKS=true
ENV DEP_HALLUCINATOR_CACHE_MEMORY_MB=128
ENV DEP_HALLUCINATOR_MAX_MEMORY_MB=512
ENV DEP_HALLUCINATOR_MAX_ASYNC_WORKERS=15

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD dep-hallucinator --version || exit 1

# Switch to non-root user
USER depscanner

# Expose port for potential web interface (future)
EXPOSE 8080

# Entry point
ENTRYPOINT ["dep-hallucinator"]
CMD ["--help"]

# Development stage - includes dev tools
FROM production as development

USER root

# Install development dependencies
RUN pip install -e ".[dev,test]"

# Install additional dev tools
RUN apt-get update && apt-get install -y \
    vim \
    htop \
    procps \
    && rm -rf /var/lib/apt/lists/*

USER depscanner

# Override for development
ENV DEP_HALLUCINATOR_ENV=development
ENV DEP_HALLUCINATOR_LOG_LEVEL=DEBUG

# Labels for metadata
LABEL maintainer="Serhan Bahar <serhan@swb.sh>"
LABEL org.opencontainers.image.title="Dep-Hallucinator"
LABEL org.opencontainers.image.description="Security scanner for AI-generated dependency confusion vulnerabilities"
LABEL org.opencontainers.image.url="https://github.com/serhanwbahar/dep-hallucinator"
LABEL org.opencontainers.image.source="https://github.com/serhanwbahar/dep-hallucinator"
LABEL org.opencontainers.image.version="1.0.0"
LABEL org.opencontainers.image.created="2024-01-01T00:00:00Z"
LABEL org.opencontainers.image.revision=""
LABEL org.opencontainers.image.vendor="Serhan Bahar"
LABEL org.opencontainers.image.licenses="MIT" 