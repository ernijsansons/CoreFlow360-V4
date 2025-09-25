# Multi-stage Dockerfile for CoreFlow360 V4 - Enterprise Grade
# Optimized for production deployment with security and performance best practices

# ============================================================================
# Stage 1: Base Image with Security Hardening
# ============================================================================
FROM node:18-alpine AS base

# Security: Create non-root user
RUN addgroup -g 1001 -S nodejs && \
    adduser -S coreflow -u 1001

# Install security updates and required packages
RUN apk update && apk upgrade && \
    apk add --no-cache \
    dumb-init \
    curl \
    ca-certificates \
    && rm -rf /var/cache/apk/*

# Set working directory
WORKDIR /app

# ============================================================================
# Stage 2: Dependencies - Optimized for caching
# ============================================================================
FROM base AS dependencies

# Copy package files for better layer caching
COPY package*.json ./
COPY frontend/package*.json ./frontend/

# Install dependencies with security audit and cache optimization
RUN npm ci --only=production --audit --fund=false --prefer-offline && \
    npm audit --audit-level=moderate || true

# Install dev dependencies for build
RUN npm ci --include=dev --prefer-offline

# ============================================================================
# Stage 3: Build - TypeScript compilation and optimization
# ============================================================================
FROM dependencies AS build

# Copy source code
COPY . .

# Build TypeScript
RUN npm run build

# Build frontend if exists
RUN if [ -d "frontend" ]; then \
    cd frontend && npm ci && npm run build; \
    fi

# Security: Remove dev dependencies and source maps in production
RUN npm prune --production && \
    find . -name "*.map" -delete && \
    find . -name "*.ts" -not -path "./node_modules/*" -delete

# ============================================================================
# Stage 4: Production - Minimal runtime image
# ============================================================================
FROM base AS production

# Security: Set proper permissions
RUN chown -R coreflow:nodejs /app

# Copy built application
COPY --from=build --chown=coreflow:nodejs /app .

# Copy MCP server files
COPY --chown=coreflow:nodejs cloudflare_proxy.py ./
COPY --chown=coreflow:nodejs mcp-coreflow.json.txt ./

# Install Python dependencies for MCP server
RUN apk add --no-cache python3 py3-pip && \
    pip3 install --no-cache-dir mcp

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:3000/health || exit 1

# Security: Switch to non-root user
USER coreflow

# Expose port
EXPOSE 3000

# Use dumb-init for proper signal handling
ENTRYPOINT ["dumb-init", "--"]

# Default command
CMD ["node", "server-simple.js"]

# ============================================================================
# Stage 5: Development - Full development environment
# ============================================================================
FROM dependencies AS development

# Copy source code
COPY . .

# Install development tools
RUN npm install -g nodemon typescript ts-node

# Expose ports for development
EXPOSE 3000 9229

# Development command with hot reload
CMD ["npm", "run", "dev:watch"]

# ============================================================================
# Stage 6: Testing - Isolated testing environment
# ============================================================================
FROM dependencies AS testing

# Copy source code
COPY . .

# Install testing dependencies
RUN npm ci --include=dev

# Run tests
CMD ["npm", "test"]

# ============================================================================
# Metadata
# ============================================================================
LABEL maintainer="CoreFlow360 Team" \
      version="4.0.0" \
      description="CoreFlow360 V4 - Enterprise Business Management Platform" \
      org.opencontainers.image.source="https://github.com/coreflow360/coreflow360-v4" \
      org.opencontainers.image.licenses="MIT" \
      org.opencontainers.image.created="$(date -u +'%Y-%m-%dT%H:%M:%SZ')"
