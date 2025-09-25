#!/bin/bash
# CoreFlow360 V4 - Docker Deployment Script
# Enterprise-grade deployment automation with security and monitoring

set -euo pipefail

# ============================================================================
# Configuration
# ============================================================================
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
ENVIRONMENT="${1:-development}"
FORCE="${2:-false}"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# ============================================================================
# Helper Functions
# ============================================================================
log() {
    echo -e "${BLUE}[$(date +'%Y-%m-%d %H:%M:%S')]${NC} $1"
}

success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

error() {
    echo -e "${RED}[ERROR]${NC} $1"
    exit 1
}

# ============================================================================
# Pre-deployment Checks
# ============================================================================
check_prerequisites() {
    log "Checking prerequisites..."
    
    # Check if Docker is installed and running
    if ! command -v docker &> /dev/null; then
        error "Docker is not installed. Please install Docker first."
    fi
    
    if ! docker info &> /dev/null; then
        error "Docker is not running. Please start Docker first."
    fi
    
    # Check if Docker Compose is available
    if ! command -v docker-compose &> /dev/null && ! docker compose version &> /dev/null; then
        error "Docker Compose is not installed. Please install Docker Compose first."
    fi
    
    # Check if .env file exists
    if [ ! -f "$PROJECT_ROOT/.env" ]; then
        warning ".env file not found. Creating from example..."
        if [ -f "$PROJECT_ROOT/env.example" ]; then
            cp "$PROJECT_ROOT/env.example" "$PROJECT_ROOT/.env"
            warning "Please update .env file with your actual configuration values."
        else
            error ".env file not found and no example file available."
        fi
    fi
    
    success "Prerequisites check passed"
}

# ============================================================================
# Security Validation
# ============================================================================
validate_security() {
    log "Validating security configuration..."
    
    # Check for weak passwords in .env
    if grep -q "your_.*_password" "$PROJECT_ROOT/.env"; then
        error "Please update default passwords in .env file"
    fi
    
    # Check for required secrets
    required_secrets=("JWT_SECRET" "ENCRYPTION_KEY" "POSTGRES_PASSWORD" "REDIS_PASSWORD")
    for secret in "${required_secrets[@]}"; do
        if ! grep -q "^${secret}=" "$PROJECT_ROOT/.env" || grep -q "^${secret}=$" "$PROJECT_ROOT/.env"; then
            error "Required secret ${secret} is not set in .env file"
        fi
    done
    
    success "Security validation passed"
}

# ============================================================================
# Build and Deploy
# ============================================================================
build_and_deploy() {
    log "Building and deploying CoreFlow360 V4..."
    
    cd "$PROJECT_ROOT"
    
    # Stop existing containers
    log "Stopping existing containers..."
    docker-compose down --remove-orphans || true
    
    # Build images
    log "Building Docker images..."
    if [ "$ENVIRONMENT" = "production" ]; then
        docker-compose -f docker-compose.yml -f docker-compose.prod.yml build --no-cache
    else
        docker-compose build --no-cache
    fi
    
    # Start services
    log "Starting services..."
    if [ "$ENVIRONMENT" = "production" ]; then
        docker-compose -f docker-compose.yml -f docker-compose.prod.yml up -d
    else
        docker-compose up -d
    fi
    
    success "Deployment completed"
}

# ============================================================================
# Health Checks
# ============================================================================
run_health_checks() {
    log "Running health checks..."
    
    # Wait for services to start
    log "Waiting for services to start..."
    sleep 30
    
    # Check application health
    local max_attempts=30
    local attempt=1
    
    while [ $attempt -le $max_attempts ]; do
        if curl -f http://localhost:3000/health &> /dev/null; then
            success "Application health check passed"
            break
        fi
        
        if [ $attempt -eq $max_attempts ]; then
            error "Application health check failed after $max_attempts attempts"
        fi
        
        log "Health check attempt $attempt/$max_attempts failed, retrying in 10 seconds..."
        sleep 10
        ((attempt++))
    done
    
    # Check database connectivity
    if docker-compose exec -T postgres pg_isready -U coreflow -d coreflow360 &> /dev/null; then
        success "Database health check passed"
    else
        error "Database health check failed"
    fi
    
    # Check Redis connectivity
    if docker-compose exec -T redis redis-cli ping &> /dev/null; then
        success "Redis health check passed"
    else
        error "Redis health check failed"
    fi
}

# ============================================================================
# Post-deployment Tasks
# ============================================================================
post_deployment_tasks() {
    log "Running post-deployment tasks..."
    
    # Run database migrations
    log "Running database migrations..."
    docker-compose exec -T app npm run db:migrate || warning "Database migrations failed"
    
    # Seed initial data if needed
    if [ "$ENVIRONMENT" = "development" ]; then
        log "Seeding development data..."
        docker-compose exec -T app npm run db:seed:test || warning "Data seeding failed"
    fi
    
    # Show service status
    log "Service status:"
    docker-compose ps
    
    success "Post-deployment tasks completed"
}

# ============================================================================
# Monitoring Setup
# ============================================================================
setup_monitoring() {
    log "Setting up monitoring..."
    
    # Wait for monitoring services to start
    sleep 10
    
    # Check Prometheus
    if curl -f http://localhost:9090/-/healthy &> /dev/null; then
        success "Prometheus is running at http://localhost:9090"
    else
        warning "Prometheus health check failed"
    fi
    
    # Check Grafana
    if curl -f http://localhost:3002/api/health &> /dev/null; then
        success "Grafana is running at http://localhost:3002"
        log "Default Grafana credentials: admin / admin (change in production!)"
    else
        warning "Grafana health check failed"
    fi
}

# ============================================================================
# Cleanup
# ============================================================================
cleanup() {
    log "Cleaning up..."
    
    # Remove unused images
    docker image prune -f
    
    # Remove unused volumes (be careful in production)
    if [ "$ENVIRONMENT" = "development" ]; then
        docker volume prune -f
    fi
    
    success "Cleanup completed"
}

# ============================================================================
# Main Execution
# ============================================================================
main() {
    log "Starting CoreFlow360 V4 Docker deployment..."
    log "Environment: $ENVIRONMENT"
    log "Force mode: $FORCE"
    
    # Run deployment steps
    check_prerequisites
    
    if [ "$FORCE" != "true" ]; then
        validate_security
    fi
    
    build_and_deploy
    run_health_checks
    post_deployment_tasks
    setup_monitoring
    cleanup
    
    success "CoreFlow360 V4 deployment completed successfully!"
    
    # Show access information
    echo ""
    log "Access Information:"
    echo "  Application: http://localhost:3000"
    echo "  Frontend: http://localhost:3001"
    echo "  Grafana: http://localhost:3002 (admin/admin)"
    echo "  Prometheus: http://localhost:9090"
    echo ""
    
    if [ "$ENVIRONMENT" = "development" ]; then
        echo "  MailHog: http://localhost:8025"
        echo "  pgAdmin: http://localhost:5050 (admin@coreflow360.com/admin)"
    fi
    
    echo ""
    log "To view logs: docker-compose logs -f"
    log "To stop services: docker-compose down"
}

# ============================================================================
# Error Handling
# ============================================================================
trap 'error "Deployment failed at line $LINENO"' ERR

# ============================================================================
# Script Entry Point
# ============================================================================
if [ "${BASH_SOURCE[0]}" = "${0}" ]; then
    main "$@"
fi
