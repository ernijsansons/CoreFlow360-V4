# MCP Server Dockerfile for CoreFlow360 V4
# Dedicated container for MCP server with enterprise features

FROM python:3.11-alpine AS base

# Security: Create non-root user
RUN addgroup -g 1001 -S mcp && \
    adduser -S mcp -u 1001

# Install system dependencies
RUN apk update && apk upgrade && \
    apk add --no-cache \
    dumb-init \
    curl \
    ca-certificates \
    && rm -rf /var/cache/apk/*

# Set working directory
WORKDIR /app

# ============================================================================
# Dependencies Stage
# ============================================================================
FROM base AS dependencies

# Copy requirements
COPY requirements.txt .

# Install Python dependencies
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt

# ============================================================================
# Production Stage
# ============================================================================
FROM base AS production

# Copy dependencies
COPY --from=dependencies /usr/local/lib/python3.11/site-packages /usr/local/lib/python3.11/site-packages
COPY --from=dependencies /usr/local/bin /usr/local/bin

# Copy application files
COPY --chown=mcp:mcp cloudflare_proxy.py ./
COPY --chown=mcp:mcp mcp-coreflow.json.txt ./mcp-config.json

# Create logs directory
RUN mkdir -p /app/logs && chown mcp:mcp /app/logs

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD python3 -c "import requests; requests.get('http://localhost:8080/health')" || exit 1

# Security: Switch to non-root user
USER mcp

# Expose port
EXPOSE 8080

# Use dumb-init for proper signal handling
ENTRYPOINT ["dumb-init", "--"]

# Default command
CMD ["python3", "cloudflare_proxy.py"]
