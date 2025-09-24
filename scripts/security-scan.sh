#!/bin/bash
# Security Scanning Script for CoreFlow360 V4
# Comprehensive security validation for Docker containers

set -euo pipefail

# ============================================================================
# Configuration
# ============================================================================
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
SCAN_RESULTS_DIR="$PROJECT_ROOT/security-scan-results"
DATE=$(date +%Y%m%d_%H%M%S)

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
}

# ============================================================================
# Prerequisites Check
# ============================================================================
check_prerequisites() {
    log "Checking security scanning prerequisites..."
    
    # Check if Docker is running
    if ! docker info &> /dev/null; then
        error "Docker is not running. Please start Docker first."
    fi
    
    # Check for required tools
    local tools=("trivy" "docker" "docker-compose")
    for tool in "${tools[@]}"; do
        if ! command -v "$tool" &> /dev/null; then
            warning "$tool is not installed. Some scans may be skipped."
        fi
    done
    
    # Create results directory
    mkdir -p "$SCAN_RESULTS_DIR"
    
    success "Prerequisites check completed"
}

# ============================================================================
# Container Vulnerability Scanning
# ============================================================================
scan_container_vulnerabilities() {
    log "Scanning container vulnerabilities..."
    
    local images=("coreflow360-v4:latest" "postgres:15-alpine" "redis:7-alpine" "nginx:alpine")
    
    for image in "${images[@]}"; do
        log "Scanning image: $image"
        
        # Trivy vulnerability scan
        if command -v trivy &> /dev/null; then
            trivy image --format json --output "$SCAN_RESULTS_DIR/trivy_${image//[:\/]/_}_${DATE}.json" "$image" || true
            trivy image --format table --output "$SCAN_RESULTS_DIR/trivy_${image//[:\/]/_}_${DATE}.txt" "$image" || true
        fi
        
        # Docker Scout scan (if available)
        if docker scout version &> /dev/null; then
            docker scout cves "$image" --format json --output "$SCAN_RESULTS_DIR/scout_${image//[:\/]/_}_${DATE}.json" || true
        fi
    done
    
    success "Container vulnerability scanning completed"
}

# ============================================================================
# Configuration Security Scan
# ============================================================================
scan_configuration_security() {
    log "Scanning configuration security..."
    
    # Docker Compose security analysis
    if [ -f "$PROJECT_ROOT/docker-compose.yml" ]; then
        log "Analyzing docker-compose.yml security..."
        
        # Check for security issues
        local issues=()
        
        # Check for privileged containers
        if grep -q "privileged: true" "$PROJECT_ROOT/docker-compose.yml"; then
            issues+=("Privileged containers detected")
        fi
        
        # Check for root user
        if ! grep -q "user:" "$PROJECT_ROOT/docker-compose.yml"; then
            issues+=("Containers may be running as root")
        fi
        
        # Check for read-only filesystems
        if ! grep -q "read_only: true" "$PROJECT_ROOT/docker-compose.yml"; then
            issues+=("Containers not using read-only filesystems")
        fi
        
        # Save results
        if [ ${#issues[@]} -gt 0 ]; then
            printf '%s\n' "${issues[@]}" > "$SCAN_RESULTS_DIR/config_security_issues_${DATE}.txt"
            warning "Configuration security issues found: ${#issues[@]}"
        else
            echo "No configuration security issues found" > "$SCAN_RESULTS_DIR/config_security_clean_${DATE}.txt"
            success "Configuration security scan passed"
        fi
    fi
}

# ============================================================================
# Network Security Scan
# ============================================================================
scan_network_security() {
    log "Scanning network security..."
    
    # Check for exposed ports
    local exposed_ports=()
    
    if [ -f "$PROJECT_ROOT/docker-compose.yml" ]; then
        while IFS= read -r line; do
            if [[ $line =~ ^[[:space:]]*-[[:space:]]*\"([0-9]+):([0-9]+)\" ]]; then
                exposed_ports+=("${BASH_REMATCH[1]}:${BASH_REMATCH[2]}")
            fi
        done < "$PROJECT_ROOT/docker-compose.yml"
    fi
    
    # Analyze exposed ports
    local risky_ports=()
    for port in "${exposed_ports[@]}"; do
        local host_port="${port%%:*}"
        case $host_port in
            22|23|21|25|53|110|143|993|995)
                risky_ports+=("$port (potentially risky service)")
                ;;
        esac
    done
    
    # Save results
    if [ ${#risky_ports[@]} -gt 0 ]; then
        printf '%s\n' "${risky_ports[@]}" > "$SCAN_RESULTS_DIR/network_security_risks_${DATE}.txt"
        warning "Network security risks found: ${#risky_ports[@]}"
    else
        echo "No network security risks found" > "$SCAN_RESULTS_DIR/network_security_clean_${DATE}.txt"
        success "Network security scan passed"
    fi
}

# ============================================================================
# Secrets Security Scan
# ============================================================================
scan_secrets_security() {
    log "Scanning for secrets and sensitive data..."
    
    local secrets_found=()
    
    # Check for hardcoded secrets in files
    local files_to_check=("docker-compose.yml" "Dockerfile" "*.env*" "*.json" "*.js" "*.ts")
    
    for pattern in "${files_to_check[@]}"; do
        while IFS= read -r -d '' file; do
            # Check for common secret patterns
            if grep -qiE "(password|secret|key|token|api_key)" "$file"; then
                if grep -qiE "(password\s*=\s*['\"][^'\"]{8,}['\"]|secret\s*=\s*['\"][^'\"]{8,}['\"]|key\s*=\s*['\"][^'\"]{8,}['\"])" "$file"; then
                    secrets_found+=("$file: Potential hardcoded secret")
                fi
            fi
        done < <(find "$PROJECT_ROOT" -name "$pattern" -type f -print0 2>/dev/null || true)
    done
    
    # Save results
    if [ ${#secrets_found[@]} -gt 0 ]; then
        printf '%s\n' "${secrets_found[@]}" > "$SCAN_RESULTS_DIR/secrets_found_${DATE}.txt"
        warning "Potential secrets found: ${#secrets_found[@]}"
    else
        echo "No hardcoded secrets found" > "$SCAN_RESULTS_DIR/secrets_clean_${DATE}.txt"
        success "Secrets security scan passed"
    fi
}

# ============================================================================
# Runtime Security Scan
# ============================================================================
scan_runtime_security() {
    log "Scanning runtime security..."
    
    # Check if containers are running
    if docker-compose ps | grep -q "Up"; then
        log "Analyzing running containers..."
        
        # Check container security settings
        local containers=($(docker-compose ps -q))
        
        for container in "${containers[@]}"; do
            local container_name=$(docker inspect --format='{{.Name}}' "$container" | sed 's/\///')
            log "Analyzing container: $container_name"
            
            # Check if running as root
            local user=$(docker exec "$container" whoami 2>/dev/null || echo "unknown")
            if [ "$user" = "root" ]; then
                echo "$container_name: Running as root user" >> "$SCAN_RESULTS_DIR/runtime_security_issues_${DATE}.txt"
            fi
            
            # Check for privileged mode
            local privileged=$(docker inspect --format='{{.HostConfig.Privileged}}' "$container")
            if [ "$privileged" = "true" ]; then
                echo "$container_name: Running in privileged mode" >> "$SCAN_RESULTS_DIR/runtime_security_issues_${DATE}.txt"
            fi
        done
        
        success "Runtime security scan completed"
    else
        warning "No running containers found. Start containers first for runtime analysis."
    fi
}

# ============================================================================
# Generate Security Report
# ============================================================================
generate_security_report() {
    log "Generating security report..."
    
    local report_file="$SCAN_RESULTS_DIR/security_report_${DATE}.md"
    
    cat > "$report_file" << EOF
# CoreFlow360 V4 Security Scan Report

**Scan Date:** $(date)
**Scan ID:** $DATE

## Executive Summary

This report contains the results of a comprehensive security scan of the CoreFlow360 V4 Docker deployment.

## Scan Results

### Container Vulnerabilities
EOF

    # Add vulnerability scan results
    if ls "$SCAN_RESULTS_DIR"/trivy_*.txt 1> /dev/null 2>&1; then
        echo "#### Trivy Vulnerability Scan Results" >> "$report_file"
        for file in "$SCAN_RESULTS_DIR"/trivy_*.txt; do
            echo "**$(basename "$file")**" >> "$report_file"
            echo '```' >> "$report_file"
            cat "$file" >> "$report_file"
            echo '```' >> "$report_file"
            echo "" >> "$report_file"
        done
    fi

    # Add configuration security results
    if ls "$SCAN_RESULTS_DIR"/config_security_*.txt 1> /dev/null 2>&1; then
        echo "#### Configuration Security" >> "$report_file"
        for file in "$SCAN_RESULTS_DIR"/config_security_*.txt; do
            echo "**$(basename "$file")**" >> "$report_file"
            echo '```' >> "$report_file"
            cat "$file" >> "$report_file"
            echo '```' >> "$report_file"
            echo "" >> "$report_file"
        done
    fi

    # Add network security results
    if ls "$SCAN_RESULTS_DIR"/network_security_*.txt 1> /dev/null 2>&1; then
        echo "#### Network Security" >> "$report_file"
        for file in "$SCAN_RESULTS_DIR"/network_security_*.txt; do
            echo "**$(basename "$file")**" >> "$report_file"
            echo '```' >> "$report_file"
            cat "$file" >> "$report_file"
            echo '```' >> "$report_file"
            echo "" >> "$report_file"
        done
    fi

    # Add secrets scan results
    if ls "$SCAN_RESULTS_DIR"/secrets_*.txt 1> /dev/null 2>&1; then
        echo "#### Secrets Security" >> "$report_file"
        for file in "$SCAN_RESULTS_DIR"/secrets_*.txt; do
            echo "**$(basename "$file")**" >> "$report_file"
            echo '```' >> "$report_file"
            cat "$file" >> "$report_file"
            echo '```' >> "$report_file"
            echo "" >> "$report_file"
        done
    fi

    # Add runtime security results
    if ls "$SCAN_RESULTS_DIR"/runtime_security_*.txt 1> /dev/null 2>&1; then
        echo "#### Runtime Security" >> "$report_file"
        for file in "$SCAN_RESULTS_DIR"/runtime_security_*.txt; do
            echo "**$(basename "$file")**" >> "$report_file"
            echo '```' >> "$report_file"
            cat "$file" >> "$report_file"
            echo '```' >> "$report_file"
            echo "" >> "$report_file"
        done
    fi

    cat >> "$report_file" << EOF

## Recommendations

1. **Regular Scanning**: Run security scans regularly, ideally as part of CI/CD pipeline
2. **Vulnerability Management**: Keep base images updated and patch vulnerabilities promptly
3. **Secrets Management**: Use proper secrets management solutions (Docker Secrets, Kubernetes Secrets, etc.)
4. **Network Security**: Implement network policies and limit exposed ports
5. **Runtime Security**: Monitor running containers for security violations

## Next Steps

1. Review all identified issues
2. Prioritize fixes based on severity
3. Implement security best practices
4. Schedule regular security scans
5. Update security policies as needed

---
*Report generated by CoreFlow360 V4 Security Scanner*
EOF

    success "Security report generated: $report_file"
}

# ============================================================================
# Main Execution
# ============================================================================
main() {
    log "Starting CoreFlow360 V4 security scan..."
    
    check_prerequisites
    scan_container_vulnerabilities
    scan_configuration_security
    scan_network_security
    scan_secrets_security
    scan_runtime_security
    generate_security_report
    
    success "Security scan completed successfully!"
    log "Results saved to: $SCAN_RESULTS_DIR"
    
    # Show summary
    echo ""
    log "Scan Summary:"
    echo "  - Results directory: $SCAN_RESULTS_DIR"
    echo "  - Report file: security_report_${DATE}.md"
    echo "  - Scan ID: $DATE"
    echo ""
}

# ============================================================================
# Error Handling
# ============================================================================
trap 'error "Security scan failed at line $LINENO"' ERR

# ============================================================================
# Script Entry Point
# ============================================================================
if [ "${BASH_SOURCE[0]}" = "${0}" ]; then
    main "$@"
fi
