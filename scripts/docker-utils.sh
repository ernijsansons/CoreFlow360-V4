#!/bin/bash

# CoreFlow360 V4 - Docker Utilities
# Collection of helpful Docker management scripts

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Function to print colored output
print_status() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Function to check if Docker is running
check_docker() {
    if ! docker info > /dev/null 2>&1; then
        print_error "Docker is not running. Please start Docker and try again."
        exit 1
    fi
}

# Function to check if docker-compose is available
check_compose() {
    if ! command -v docker-compose &> /dev/null; then
        print_error "docker-compose is not installed. Please install it and try again."
        exit 1
    fi
}

# Function to show help
show_help() {
    echo "CoreFlow360 V4 - Docker Utilities"
    echo ""
    echo "Usage: $0 [COMMAND]"
    echo ""
    echo "Commands:"
    echo "  dev          Start development environment"
    echo "  prod         Start production environment"
    echo "  stop         Stop all containers"
    echo "  clean        Clean up Docker resources"
    echo "  logs         Show logs for all services"
    echo "  health       Check health of all services"
    echo "  build        Build all images"
    echo "  push         Push images to registry"
    echo "  pull         Pull latest images"
    echo "  backup       Backup database"
    echo "  restore      Restore database from backup"
    echo "  shell        Open shell in app container"
    echo "  test         Run tests in containers"
    echo "  help         Show this help message"
    echo ""
}

# Function to start development environment
start_dev() {
    print_status "Starting development environment..."
    check_docker
    check_compose
    
    if [ ! -f .env ]; then
        print_warning ".env file not found. Creating from template..."
        cp env.docker.example .env
        print_warning "Please edit .env file with your configuration before continuing."
        exit 1
    fi
    
    docker-compose -f docker-compose.dev.yml up -d
    print_success "Development environment started!"
    print_status "Services available at:"
    echo "  - Backend API: http://localhost:3000"
    echo "  - Frontend: http://localhost:3001"
    echo "  - PostgreSQL: localhost:5432"
    echo "  - Redis: localhost:6379"
}

# Function to start production environment
start_prod() {
    print_status "Starting production environment..."
    check_docker
    check_compose
    
    if [ ! -f .env ]; then
        print_error ".env file not found. Please create it from env.docker.example"
        exit 1
    fi
    
    docker-compose up -d
    print_success "Production environment started!"
}

# Function to stop all containers
stop_all() {
    print_status "Stopping all containers..."
    docker-compose -f docker-compose.dev.yml down 2>/dev/null || true
    docker-compose down 2>/dev/null || true
    print_success "All containers stopped!"
}

# Function to clean up Docker resources
clean_docker() {
    print_status "Cleaning up Docker resources..."
    
    # Stop all containers
    stop_all
    
    # Remove unused containers, networks, images, and build cache
    docker system prune -f
    
    # Remove unused volumes
    docker volume prune -f
    
    print_success "Docker cleanup completed!"
}

# Function to show logs
show_logs() {
    print_status "Showing logs for all services..."
    docker-compose -f docker-compose.dev.yml logs -f
}

# Function to check health
check_health() {
    print_status "Checking health of all services..."
    
    # Check if containers are running
    docker-compose -f docker-compose.dev.yml ps
    
    # Check application health
    if curl -f http://localhost:3000/health > /dev/null 2>&1; then
        print_success "Backend API is healthy"
    else
        print_error "Backend API is not responding"
    fi
    
    if curl -f http://localhost:3001 > /dev/null 2>&1; then
        print_success "Frontend is healthy"
    else
        print_error "Frontend is not responding"
    fi
}

# Function to build all images
build_images() {
    print_status "Building all Docker images..."
    
    # Build main application
    docker build -t coreflow360v4-app:latest .
    
    # Build frontend
    docker build -t coreflow360v4-frontend:latest ./frontend
    
    # Build design system
    if [ -d "./design-system" ]; then
        docker build -t design-system:latest ./design-system
    fi
    
    print_success "All images built successfully!"
}

# Function to push images
push_images() {
    print_status "Pushing images to registry..."
    
    # Tag and push main application
    docker tag coreflow360v4-app:latest ernijsansons/coreflow360v4-app:latest
    docker push ernijsansons/coreflow360v4-app:latest
    
    # Tag and push frontend
    docker tag coreflow360v4-frontend:latest ernijsansons/coreflow360v4-frontend:latest
    docker push ernijsansons/coreflow360v4-frontend:latest
    
    print_success "Images pushed to registry!"
}

# Function to pull latest images
pull_images() {
    print_status "Pulling latest images..."
    
    docker pull ernijsansons/coreflow360v4-app:latest
    docker pull ernijsansons/coreflow360v4-frontend:latest
    
    print_success "Latest images pulled!"
}

# Function to backup database
backup_database() {
    print_status "Backing up database..."
    
    BACKUP_FILE="backup_$(date +%Y%m%d_%H%M%S).sql"
    
    docker-compose -f docker-compose.dev.yml exec -T postgres pg_dump -U coreflow coreflow360 > "$BACKUP_FILE"
    
    print_success "Database backed up to $BACKUP_FILE"
}

# Function to restore database
restore_database() {
    if [ -z "$1" ]; then
        print_error "Please provide backup file path"
        echo "Usage: $0 restore <backup_file.sql>"
        exit 1
    fi
    
    print_status "Restoring database from $1..."
    
    docker-compose -f docker-compose.dev.yml exec -T postgres psql -U coreflow -d coreflow360 < "$1"
    
    print_success "Database restored from $1"
}

# Function to open shell in app container
open_shell() {
    print_status "Opening shell in app container..."
    docker-compose -f docker-compose.dev.yml exec app sh
}

# Function to run tests
run_tests() {
    print_status "Running tests..."
    
    # Run backend tests
    docker-compose -f docker-compose.dev.yml exec app npm test
    
    # Run frontend tests
    docker-compose -f docker-compose.dev.yml exec frontend npm test
    
    print_success "All tests completed!"
}

# Main script logic
case "${1:-help}" in
    dev)
        start_dev
        ;;
    prod)
        start_prod
        ;;
    stop)
        stop_all
        ;;
    clean)
        clean_docker
        ;;
    logs)
        show_logs
        ;;
    health)
        check_health
        ;;
    build)
        build_images
        ;;
    push)
        push_images
        ;;
    pull)
        pull_images
        ;;
    backup)
        backup_database
        ;;
    restore)
        restore_database "$2"
        ;;
    shell)
        open_shell
        ;;
    test)
        run_tests
        ;;
    help|--help|-h)
        show_help
        ;;
    *)
        print_error "Unknown command: $1"
        show_help
        exit 1
        ;;
esac
