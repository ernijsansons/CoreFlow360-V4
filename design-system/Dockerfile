# Multi-stage Dockerfile for Future Enterprise Design System
# Optimized for production deployment with security and performance

# ============================================================================
# Stage 1: Base Image with Security Hardening
# ============================================================================
FROM node:18-alpine AS base

# Security: Create non-root user
RUN addgroup -g 1001 -S nodejs && \
    adduser -S designsystem -u 1001

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

# Install pnpm globally
RUN corepack enable && corepack prepare pnpm@8.14.0 --activate

# Copy package files
COPY package.json pnpm-lock.yaml ./

# Install production dependencies
RUN pnpm install --frozen-lockfile --prod

# Copy production dependencies
RUN cp -R node_modules /prod_node_modules

# Install all dependencies for build
RUN pnpm install --frozen-lockfile

# ============================================================================
# Stage 3: Build - TypeScript compilation and optimization
# ============================================================================
FROM dependencies AS build

# Copy source code
COPY . .

# Build the design system
RUN pnpm build && \
    pnpm build:lib

# Build Storybook for static hosting
RUN pnpm storybook:build

# Generate Figma tokens
RUN if [ -f "scripts/sync-figma-tokens.js" ]; then \
    pnpm figma:sync || true; \
    fi

# Optimize bundle size
RUN find dist -name "*.map" -delete && \
    find dist -name "*.ts" -not -name "*.d.ts" -delete

# ============================================================================
# Stage 4: Cloudflare Workers Build
# ============================================================================
FROM build AS workers

# Build for Cloudflare Workers
RUN pnpm wrangler build

# ============================================================================
# Stage 5: Production Runtime
# ============================================================================
FROM base AS production

# Install pnpm for runtime if needed
RUN corepack enable && corepack prepare pnpm@8.14.0 --activate

# Copy production dependencies
COPY --from=dependencies --chown=designsystem:nodejs /prod_node_modules ./node_modules

# Copy built application
COPY --from=build --chown=designsystem:nodejs /app/dist ./dist
COPY --from=build --chown=designsystem:nodejs /app/storybook-static ./storybook-static
COPY --from=build --chown=designsystem:nodejs /app/playground ./playground

# Copy package files
COPY --chown=designsystem:nodejs package.json pnpm-lock.yaml ./

# Copy Cloudflare Workers files
COPY --from=workers --chown=designsystem:nodejs /app/dist/worker ./worker

# Copy configuration files
COPY --chown=designsystem:nodejs wrangler.toml ./
COPY --chown=designsystem:nodejs tailwind.config.js postcss.config.js ./

# Health check endpoint
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:3000/health || exit 1

# Security: Switch to non-root user
USER designsystem

# Expose ports
EXPOSE 3000 6006

# Environment variables
ENV NODE_ENV=production \
    PORT=3000

# Use dumb-init for proper signal handling
ENTRYPOINT ["dumb-init", "--"]

# Default command - serve the playground
CMD ["pnpm", "preview"]

# ============================================================================
# Stage 6: Development - Full development environment
# ============================================================================
FROM dependencies AS development

# Install development tools
RUN pnpm add -g @cloudflare/wrangler

# Copy source code
COPY . .

# Expose ports for development
EXPOSE 3000 6006 5173 9229

# Environment variables
ENV NODE_ENV=development

# Development command with hot reload
CMD ["pnpm", "dev"]

# ============================================================================
# Stage 7: Testing - Isolated testing environment
# ============================================================================
FROM dependencies AS testing

# Copy source code
COPY . .

# Install playwright for visual testing
RUN pnpm add -D @playwright/test && \
    npx playwright install chromium

# Run all tests
CMD ["pnpm", "test"]

# ============================================================================
# Stage 8: Nginx Static Hosting
# ============================================================================
FROM nginx:alpine AS nginx

# Copy built static files
COPY --from=build /app/dist /usr/share/nginx/html/dist
COPY --from=build /app/storybook-static /usr/share/nginx/html/storybook
COPY --from=build /app/playground/dist /usr/share/nginx/html

# Copy nginx configuration
COPY nginx.conf /etc/nginx/nginx.conf

# Health check
HEALTHCHECK --interval=30s --timeout=3s \
    CMD wget --no-verbose --tries=1 --spider http://localhost/ || exit 1

EXPOSE 80

CMD ["nginx", "-g", "daemon off;"]

# ============================================================================
# Metadata
# ============================================================================
LABEL maintainer="Future Enterprise Team" \
      version="1.0.0" \
      description="Revolutionary Enterprise Design System" \
      org.opencontainers.image.source="https://github.com/future-enterprise/design-system" \
      org.opencontainers.image.licenses="MIT"