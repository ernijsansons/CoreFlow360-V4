#!/bin/bash

# ============================================================================
# Design System Deployment Script
# Complete deployment pipeline for Docker, GitHub, and Cloudflare
# ============================================================================

set -e  # Exit on error
set -o pipefail  # Exit on pipe failure

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
DESIGN_SYSTEM_DIR="$PROJECT_ROOT/design-system"
TIMESTAMP=$(date +%Y%m%d-%H%M%S)
ENVIRONMENT=${1:-staging}

# Load environment variables
if [ -f "$DESIGN_SYSTEM_DIR/.env" ]; then
    source "$DESIGN_SYSTEM_DIR/.env"
fi

# ============================================================================
# Functions
# ============================================================================

log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

check_dependencies() {
    log_info "Checking dependencies..."

    local deps=("docker" "git" "node" "pnpm" "wrangler")
    for dep in "${deps[@]}"; do
        if ! command -v "$dep" &> /dev/null; then
            log_error "$dep is not installed"
            exit 1
        fi
    done

    log_success "All dependencies are installed"
}

validate_environment() {
    log_info "Validating environment variables..."

    local required_vars=(
        "CLOUDFLARE_ACCOUNT_ID"
        "CLOUDFLARE_API_TOKEN"
        "GITHUB_TOKEN"
        "FIGMA_TOKEN"
    )

    for var in "${required_vars[@]}"; do
        if [ -z "${!var}" ]; then
            log_error "Required environment variable $var is not set"
            exit 1
        fi
    done

    log_success "Environment variables validated"
}

# ============================================================================
# Pre-deployment Checks
# ============================================================================

pre_deployment_checks() {
    log_info "Running pre-deployment checks..."

    cd "$DESIGN_SYSTEM_DIR"

    # Check for uncommitted changes
    if [ -n "$(git status --porcelain)" ]; then
        log_warning "You have uncommitted changes"
        read -p "Continue anyway? (y/N) " -n 1 -r
        echo
        if [[ ! $REPLY =~ ^[Yy]$ ]]; then
            exit 1
        fi
    fi

    # Run tests
    log_info "Running tests..."
    pnpm test || {
        log_error "Tests failed"
        exit 1
    }

    # Check bundle size
    log_info "Checking bundle size..."
    pnpm build
    BUNDLE_SIZE=$(stat -f%z dist/index.js 2>/dev/null || stat -c%s dist/index.js 2>/dev/null || echo "0")
    if [ "$BUNDLE_SIZE" -gt 102400 ]; then
        log_warning "Bundle size exceeds 100KB limit: $BUNDLE_SIZE bytes"
    fi

    log_success "Pre-deployment checks passed"
}

# ============================================================================
# Docker Build and Push
# ============================================================================

build_docker_images() {
    log_info "Building Docker images..."

    cd "$DESIGN_SYSTEM_DIR"

    # Build multi-platform images
    docker buildx create --use --name design-system-builder || true

    # Build production image
    docker buildx build \
        --platform linux/amd64,linux/arm64 \
        --tag ghcr.io/$GITHUB_ACTOR/design-system:$TIMESTAMP \
        --tag ghcr.io/$GITHUB_ACTOR/design-system:$ENVIRONMENT \
        --tag ghcr.io/$GITHUB_ACTOR/design-system:latest \
        --cache-from type=gha \
        --cache-to type=gha,mode=max \
        --target production \
        --push \
        .

    # Build nginx image for static hosting
    docker buildx build \
        --platform linux/amd64,linux/arm64 \
        --tag ghcr.io/$GITHUB_ACTOR/design-system-nginx:$TIMESTAMP \
        --tag ghcr.io/$GITHUB_ACTOR/design-system-nginx:$ENVIRONMENT \
        --target nginx \
        --push \
        .

    log_success "Docker images built and pushed"
}

# ============================================================================
# GitHub Release
# ============================================================================

create_github_release() {
    log_info "Creating GitHub release..."

    cd "$DESIGN_SYSTEM_DIR"

    # Get latest tag
    LATEST_TAG=$(git describe --tags --abbrev=0 2>/dev/null || echo "v0.0.0")

    # Increment version
    VERSION=$(echo $LATEST_TAG | sed 's/v//')
    IFS='.' read -ra VERSION_PARTS <<< "$VERSION"
    PATCH=$((VERSION_PARTS[2] + 1))
    NEW_VERSION="v${VERSION_PARTS[0]}.${VERSION_PARTS[1]}.$PATCH"

    # Create tag
    git tag -a "$NEW_VERSION" -m "Release $NEW_VERSION - $ENVIRONMENT deployment"
    git push origin "$NEW_VERSION"

    # Create GitHub release
    gh release create "$NEW_VERSION" \
        --title "Design System $NEW_VERSION" \
        --notes "Automated release for $ENVIRONMENT environment" \
        --target main \
        dist/*.js dist/*.css

    log_success "GitHub release created: $NEW_VERSION"
}

# ============================================================================
# Cloudflare Deployment
# ============================================================================

deploy_to_cloudflare() {
    log_info "Deploying to Cloudflare..."

    cd "$DESIGN_SYSTEM_DIR"

    # Deploy Workers
    log_info "Deploying Cloudflare Workers..."
    wrangler deploy --env $ENVIRONMENT

    # Deploy Pages
    log_info "Deploying to Cloudflare Pages..."
    wrangler pages deploy dist --project-name=design-system --env=$ENVIRONMENT

    # Setup KV namespaces
    log_info "Setting up KV namespaces..."
    wrangler kv:namespace create CACHE --env $ENVIRONMENT 2>/dev/null || true
    wrangler kv:namespace create TOKENS --env $ENVIRONMENT 2>/dev/null || true

    # Setup D1 database
    log_info "Setting up D1 database..."
    wrangler d1 create design-system-analytics-$ENVIRONMENT 2>/dev/null || true

    # Setup R2 buckets
    log_info "Setting up R2 buckets..."
    wrangler r2 bucket create design-system-assets-$ENVIRONMENT 2>/dev/null || true

    # Upload assets to R2
    log_info "Uploading assets to R2..."
    for file in dist/assets/*; do
        if [ -f "$file" ]; then
            wrangler r2 object put design-system-assets-$ENVIRONMENT/$(basename "$file") --file="$file"
        fi
    done

    # Set secrets
    log_info "Setting Cloudflare secrets..."
    echo "$FIGMA_TOKEN" | wrangler secret put FIGMA_TOKEN --env $ENVIRONMENT
    echo "$API_KEY" | wrangler secret put API_KEY --env $ENVIRONMENT
    echo "$JWT_SECRET" | wrangler secret put JWT_SECRET --env $ENVIRONMENT

    log_success "Cloudflare deployment completed"
}

# ============================================================================
# Deploy Storybook
# ============================================================================

deploy_storybook() {
    log_info "Deploying Storybook..."

    cd "$DESIGN_SYSTEM_DIR"

    # Build Storybook
    pnpm storybook:build

    # Deploy to Cloudflare Pages
    wrangler pages deploy storybook-static --project-name=design-system-storybook --env=$ENVIRONMENT

    # Deploy to Chromatic (if token available)
    if [ -n "$CHROMATIC_PROJECT_TOKEN" ]; then
        pnpm chromatic --project-token=$CHROMATIC_PROJECT_TOKEN
    fi

    log_success "Storybook deployed"
}

# ============================================================================
# Publish to NPM
# ============================================================================

publish_to_npm() {
    if [ "$ENVIRONMENT" != "production" ]; then
        log_info "Skipping NPM publish for non-production environment"
        return
    fi

    log_info "Publishing to NPM..."

    cd "$DESIGN_SYSTEM_DIR"

    # Build library
    pnpm build:lib

    # Publish
    npm config set //registry.npmjs.org/:_authToken $NPM_TOKEN
    npm publish --access public

    log_success "Published to NPM"
}

# ============================================================================
# Health Checks
# ============================================================================

run_health_checks() {
    log_info "Running health checks..."

    # Check Workers endpoint
    WORKERS_URL="https://design-system.coreflow360.workers.dev/health"
    if [ "$ENVIRONMENT" = "staging" ]; then
        WORKERS_URL="https://staging-design-system.coreflow360.workers.dev/health"
    fi

    if curl -f "$WORKERS_URL" &>/dev/null; then
        log_success "Workers health check passed"
    else
        log_warning "Workers health check failed"
    fi

    # Check Docker container
    if docker ps | grep -q "design-system"; then
        log_success "Docker container is running"
    else
        log_warning "Docker container is not running"
    fi

    log_success "Health checks completed"
}

# ============================================================================
# Rollback
# ============================================================================

rollback() {
    log_warning "Rolling back deployment..."

    cd "$DESIGN_SYSTEM_DIR"

    # Get previous version
    PREVIOUS_TAG=$(git describe --tags --abbrev=0 HEAD^ 2>/dev/null || echo "v0.0.0")

    # Rollback Workers
    wrangler rollback --env $ENVIRONMENT

    # Rollback Docker images
    docker pull ghcr.io/$GITHUB_ACTOR/design-system:$PREVIOUS_TAG
    docker tag ghcr.io/$GITHUB_ACTOR/design-system:$PREVIOUS_TAG ghcr.io/$GITHUB_ACTOR/design-system:$ENVIRONMENT
    docker push ghcr.io/$GITHUB_ACTOR/design-system:$ENVIRONMENT

    log_success "Rollback completed to $PREVIOUS_TAG"
}

# ============================================================================
# Main Deployment Flow
# ============================================================================

main() {
    log_info "Starting Design System deployment to $ENVIRONMENT..."
    echo "================================================"

    # Check if rollback requested
    if [ "$2" = "rollback" ]; then
        rollback
        exit 0
    fi

    # Run deployment steps
    check_dependencies
    validate_environment
    pre_deployment_checks

    # Build and deploy
    build_docker_images
    deploy_to_cloudflare
    deploy_storybook

    # Create release and publish
    if [ "$ENVIRONMENT" = "production" ]; then
        create_github_release
        publish_to_npm
    fi

    # Verify deployment
    run_health_checks

    echo "================================================"
    log_success "Deployment completed successfully!"
    echo ""
    echo "Access your deployment at:"
    echo "  Workers: https://design-system.coreflow360.workers.dev"
    echo "  Pages: https://design-system.pages.dev"
    echo "  Storybook: https://design-system-storybook.pages.dev"
    echo "  Docker: ghcr.io/$GITHUB_ACTOR/design-system:$ENVIRONMENT"
    echo ""
    echo "To rollback this deployment, run:"
    echo "  $0 $ENVIRONMENT rollback"
}

# Run main function
main "$@"