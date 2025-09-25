#!/bin/bash

# ============================================================================
# Wrangler Setup Script for Design System
# Complete Cloudflare infrastructure setup
# ============================================================================

set -e
set -o pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Configuration
ENVIRONMENT=${1:-development}
PROJECT_NAME="future-enterprise-design-system"

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

# ============================================================================
# Check prerequisites
# ============================================================================

check_wrangler() {
    log_info "Checking Wrangler installation..."

    if ! command -v wrangler &> /dev/null; then
        log_error "Wrangler is not installed"
        log_info "Installing Wrangler..."
        npm install -g wrangler
    fi

    WRANGLER_VERSION=$(wrangler --version)
    log_success "Wrangler version: $WRANGLER_VERSION"
}

# ============================================================================
# Cloudflare Login
# ============================================================================

cloudflare_login() {
    log_info "Authenticating with Cloudflare..."

    # Check if already logged in
    if wrangler whoami &>/dev/null; then
        log_success "Already authenticated with Cloudflare"
    else
        log_info "Please login to Cloudflare:"
        wrangler login
    fi

    # Display account info
    wrangler whoami
}

# ============================================================================
# KV Namespace Setup
# ============================================================================

setup_kv_namespaces() {
    log_info "Setting up KV namespaces for $ENVIRONMENT..."

    # Create CACHE namespace
    log_info "Creating CACHE namespace..."
    CACHE_ID=$(wrangler kv:namespace create CACHE --env $ENVIRONMENT 2>&1 | grep -oP 'id = "\K[^"]+' || true)

    if [ -n "$CACHE_ID" ]; then
        log_success "CACHE namespace created with ID: $CACHE_ID"
        echo "Add this to wrangler.toml under [env.$ENVIRONMENT]:"
        echo "kv_namespaces = ["
        echo '  { binding = "CACHE", id = "'$CACHE_ID'" }'
    else
        log_warning "CACHE namespace might already exist"
    fi

    # Create TOKENS namespace
    log_info "Creating TOKENS namespace..."
    TOKENS_ID=$(wrangler kv:namespace create TOKENS --env $ENVIRONMENT 2>&1 | grep -oP 'id = "\K[^"]+' || true)

    if [ -n "$TOKENS_ID" ]; then
        log_success "TOKENS namespace created with ID: $TOKENS_ID"
        echo '  { binding = "TOKENS", id = "'$TOKENS_ID'" }'
        echo "]"
    else
        log_warning "TOKENS namespace might already exist"
    fi

    # List all KV namespaces
    log_info "Listing all KV namespaces..."
    wrangler kv:namespace list
}

# ============================================================================
# D1 Database Setup
# ============================================================================

setup_d1_database() {
    log_info "Setting up D1 database for $ENVIRONMENT..."

    DB_NAME="design-system-analytics-$ENVIRONMENT"

    # Create D1 database
    log_info "Creating D1 database: $DB_NAME..."
    DB_OUTPUT=$(wrangler d1 create $DB_NAME 2>&1 || true)

    if echo "$DB_OUTPUT" | grep -q "database_id"; then
        DB_ID=$(echo "$DB_OUTPUT" | grep -oP 'database_id = "\K[^"]+')
        log_success "D1 database created with ID: $DB_ID"
        echo "Add this to wrangler.toml:"
        echo "[[d1_databases]]"
        echo 'binding = "DB"'
        echo "database_name = \"$DB_NAME\""
        echo "database_id = \"$DB_ID\""
    else
        log_warning "D1 database might already exist"
    fi

    # Apply migrations
    if [ -f "workers/migrations/0001_init.sql" ]; then
        log_info "Applying database migrations..."
        wrangler d1 execute $DB_NAME --file=workers/migrations/0001_init.sql --env $ENVIRONMENT
        log_success "Migrations applied successfully"
    fi

    # List databases
    log_info "Listing all D1 databases..."
    wrangler d1 list
}

# ============================================================================
# R2 Bucket Setup
# ============================================================================

setup_r2_buckets() {
    log_info "Setting up R2 buckets for $ENVIRONMENT..."

    BUCKET_NAME="design-system-assets-$ENVIRONMENT"

    # Create R2 bucket
    log_info "Creating R2 bucket: $BUCKET_NAME..."
    wrangler r2 bucket create $BUCKET_NAME 2>&1 || log_warning "Bucket might already exist"

    # List buckets
    log_info "Listing all R2 buckets..."
    wrangler r2 bucket list

    echo "Add this to wrangler.toml:"
    echo "[[r2_buckets]]"
    echo 'binding = "ASSETS"'
    echo "bucket_name = \"$BUCKET_NAME\""
}

# ============================================================================
# Queues Setup
# ============================================================================

setup_queues() {
    log_info "Setting up Queues for $ENVIRONMENT..."

    QUEUE_NAME="analytics-$ENVIRONMENT"

    # Create queue
    log_info "Creating queue: $QUEUE_NAME..."
    wrangler queues create $QUEUE_NAME 2>&1 || log_warning "Queue might already exist"

    echo "Add this to wrangler.toml:"
    echo "[[queues.producers]]"
    echo 'binding = "ANALYTICS_QUEUE"'
    echo "queue = \"$QUEUE_NAME\""
    echo ""
    echo "[[queues.consumers]]"
    echo "queue = \"$QUEUE_NAME\""
    echo "max_batch_size = 25"
    echo "max_batch_timeout = 30"
}

# ============================================================================
# Secrets Configuration
# ============================================================================

setup_secrets() {
    log_info "Setting up secrets for $ENVIRONMENT..."

    # Check if .env file exists
    if [ -f ".env" ]; then
        source .env

        # Set FIGMA_TOKEN
        if [ -n "$FIGMA_TOKEN" ]; then
            log_info "Setting FIGMA_TOKEN secret..."
            echo "$FIGMA_TOKEN" | wrangler secret put FIGMA_TOKEN --env $ENVIRONMENT
        else
            log_warning "FIGMA_TOKEN not found in .env"
        fi

        # Set API_KEY
        if [ -n "$API_KEY" ]; then
            log_info "Setting API_KEY secret..."
            echo "$API_KEY" | wrangler secret put API_KEY --env $ENVIRONMENT
        else
            log_warning "API_KEY not found in .env - generating random key"
            API_KEY=$(openssl rand -hex 16)
            echo "$API_KEY" | wrangler secret put API_KEY --env $ENVIRONMENT
            echo "Generated API_KEY: $API_KEY"
        fi

        # Set JWT_SECRET
        if [ -n "$JWT_SECRET" ]; then
            log_info "Setting JWT_SECRET secret..."
            echo "$JWT_SECRET" | wrangler secret put JWT_SECRET --env $ENVIRONMENT
        else
            log_warning "JWT_SECRET not found in .env - generating random secret"
            JWT_SECRET=$(openssl rand -hex 32)
            echo "$JWT_SECRET" | wrangler secret put JWT_SECRET --env $ENVIRONMENT
            echo "Generated JWT_SECRET: $JWT_SECRET"
        fi

        log_success "Secrets configured"
    else
        log_warning ".env file not found - please set secrets manually"
        echo "Run these commands with your actual values:"
        echo "  echo 'your-figma-token' | wrangler secret put FIGMA_TOKEN --env $ENVIRONMENT"
        echo "  echo 'your-api-key' | wrangler secret put API_KEY --env $ENVIRONMENT"
        echo "  echo 'your-jwt-secret' | wrangler secret put JWT_SECRET --env $ENVIRONMENT"
    fi

    # List secrets
    log_info "Current secrets:"
    wrangler secret list --env $ENVIRONMENT
}

# ============================================================================
# Deploy Workers
# ============================================================================

deploy_workers() {
    log_info "Deploying Workers for $ENVIRONMENT..."

    # Build the project first
    if [ -f "package.json" ]; then
        log_info "Building project..."
        npm run build
    fi

    # Deploy to Cloudflare Workers
    log_info "Deploying to Cloudflare Workers..."
    wrangler deploy --env $ENVIRONMENT

    log_success "Workers deployed successfully"
}

# ============================================================================
# Deploy Pages
# ============================================================================

deploy_pages() {
    log_info "Deploying to Cloudflare Pages..."

    # Build static assets
    if [ -d "dist" ]; then
        log_info "Deploying dist folder to Pages..."
        wrangler pages deploy dist --project-name=$PROJECT_NAME-$ENVIRONMENT
    else
        log_warning "dist folder not found - skipping Pages deployment"
    fi

    # Deploy Storybook if exists
    if [ -d "storybook-static" ]; then
        log_info "Deploying Storybook to Pages..."
        wrangler pages deploy storybook-static --project-name=$PROJECT_NAME-storybook-$ENVIRONMENT
    fi
}

# ============================================================================
# Verify Deployment
# ============================================================================

verify_deployment() {
    log_info "Verifying deployment..."

    # Get deployment info
    log_info "Recent deployments:"
    wrangler deployments list

    # Test the worker
    if [ "$ENVIRONMENT" = "production" ]; then
        WORKER_URL="https://$PROJECT_NAME.coreflow360.workers.dev"
    else
        WORKER_URL="https://$PROJECT_NAME-$ENVIRONMENT.coreflow360.workers.dev"
    fi

    log_info "Testing worker at: $WORKER_URL/health"
    if curl -f "$WORKER_URL/health" &>/dev/null; then
        log_success "Worker is responding correctly"
    else
        log_warning "Worker health check failed - it may take a few moments to propagate"
    fi
}

# ============================================================================
# Main Setup Flow
# ============================================================================

main() {
    echo "================================================"
    echo "Cloudflare Wrangler Setup for Design System"
    echo "Environment: $ENVIRONMENT"
    echo "================================================"
    echo ""

    # Run setup steps
    check_wrangler
    cloudflare_login

    echo ""
    log_info "Setting up Cloudflare infrastructure..."
    echo ""

    setup_kv_namespaces
    echo ""
    setup_d1_database
    echo ""
    setup_r2_buckets
    echo ""
    setup_queues
    echo ""
    setup_secrets
    echo ""

    # Optional deployment
    read -p "Do you want to deploy now? (y/N) " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        deploy_workers
        deploy_pages
        verify_deployment
    fi

    echo ""
    echo "================================================"
    log_success "Wrangler setup completed!"
    echo ""
    echo "Next steps:"
    echo "1. Update wrangler.toml with the IDs shown above"
    echo "2. Verify your configuration: wrangler whoami"
    echo "3. Deploy manually: wrangler deploy --env $ENVIRONMENT"
    echo "4. Check logs: wrangler tail --env $ENVIRONMENT"
    echo "================================================"
}

# Run main function
main "$@"