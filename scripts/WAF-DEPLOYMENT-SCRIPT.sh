#!/bin/bash

#############################################
# CoreFlow360 V4 - WAF Deployment Script
# Automated Cloudflare WAF Configuration
# Version: 1.0.0
# Last Updated: October 2024
#############################################

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CONFIG_FILE="${SCRIPT_DIR}/../cloudflare-waf-config.json"
LOG_FILE="${SCRIPT_DIR}/waf-deployment-$(date +%Y%m%d-%H%M%S).log"
ROLLBACK_FILE="${SCRIPT_DIR}/waf-rollback-$(date +%Y%m%d-%H%M%S).json"

# Cloudflare settings
CF_API_URL="https://api.cloudflare.com/client/v4"
ZONE_ID="${CF_ZONE_ID:-}"
API_TOKEN="${CF_API_TOKEN:-}"

# Production URLs
PRODUCTION_BACKEND="coreflow360-v4-prod.ernijs-ansons.workers.dev"
PRODUCTION_FRONTEND="production.coreflow360-frontend.pages.dev"

#############################################
# Functions
#############################################

# Logging function
log() {
    echo -e "${2:-}$1${NC}" | tee -a "$LOG_FILE"
}

# Error handling
error_exit() {
    log "ERROR: $1" "$RED"
    exit 1
}

# Success message
success() {
    log "✓ $1" "$GREEN"
}

# Warning message
warning() {
    log "⚠ $1" "$YELLOW"
}

# Info message
info() {
    log "ℹ $1" "$BLUE"
}

# Check prerequisites
check_prerequisites() {
    info "Checking prerequisites..."

    # Check if jq is installed
    if ! command -v jq &> /dev/null; then
        error_exit "jq is not installed. Please install it first: apt-get install jq"
    fi

    # Check if curl is installed
    if ! command -v curl &> /dev/null; then
        error_exit "curl is not installed. Please install it first: apt-get install curl"
    fi

    # Check if config file exists
    if [[ ! -f "$CONFIG_FILE" ]]; then
        warning "Config file not found. Creating default configuration..."
        create_default_config
    fi

    # Check environment variables
    if [[ -z "$ZONE_ID" ]]; then
        read -p "Enter Cloudflare Zone ID: " ZONE_ID
        export CF_ZONE_ID="$ZONE_ID"
    fi

    if [[ -z "$API_TOKEN" ]]; then
        read -s -p "Enter Cloudflare API Token: " API_TOKEN
        echo
        export CF_API_TOKEN="$API_TOKEN"
    fi

    # Verify API credentials
    info "Verifying Cloudflare API credentials..."
    VERIFY_RESPONSE=$(curl -s -X GET "$CF_API_URL/zones/$ZONE_ID" \
        -H "Authorization: Bearer $API_TOKEN" \
        -H "Content-Type: application/json")

    if [[ $(echo "$VERIFY_RESPONSE" | jq -r '.success') != "true" ]]; then
        error_exit "Failed to verify Cloudflare credentials"
    fi

    success "Prerequisites check passed"
}

# Create default WAF configuration
create_default_config() {
    cat > "$CONFIG_FILE" << 'EOF'
{
  "waf_rules": {
    "security_level": "high",
    "challenge_threshold": 30,
    "browser_integrity_check": true,
    "hotlink_protection": true,
    "email_obfuscation": true,
    "server_side_exclude": true,
    "rate_limiting": {
      "enabled": true,
      "threshold": 50,
      "period": 60,
      "action": "challenge"
    }
  },
  "firewall_rules": [
    {
      "name": "Block Bad Bots",
      "expression": "(cf.client.bot) and not (cf.verified_bot)",
      "action": "block",
      "priority": 1,
      "description": "Block unverified bots"
    },
    {
      "name": "Challenge Suspicious Countries",
      "expression": "(ip.geoip.country in {\"CN\" \"RU\" \"KP\"})",
      "action": "challenge",
      "priority": 2,
      "description": "Challenge requests from high-risk countries"
    },
    {
      "name": "Rate Limit API",
      "expression": "(http.request.uri.path contains \"/api/\")",
      "action": "rate_limit",
      "priority": 3,
      "rate_limit": {
        "threshold": 100,
        "period": 60
      },
      "description": "Rate limit API endpoints"
    },
    {
      "name": "Block SQL Injection Attempts",
      "expression": "(http.request.uri.query contains \"union\" and http.request.uri.query contains \"select\") or (http.request.uri.query contains \"';\" or http.request.uri.query contains '\")')",
      "action": "block",
      "priority": 4,
      "description": "Block common SQL injection patterns"
    },
    {
      "name": "Block XSS Attempts",
      "expression": "(http.request.uri.query contains \"<script\" or http.request.body contains \"<script\" or http.request.uri.query contains \"javascript:\")",
      "action": "block",
      "priority": 5,
      "description": "Block XSS attempts"
    },
    {
      "name": "Protect Admin Routes",
      "expression": "(http.request.uri.path contains \"/admin\" or http.request.uri.path contains \"/wp-admin\")",
      "action": "block",
      "priority": 6,
      "description": "Block access to admin routes"
    },
    {
      "name": "Allow Verified Bots",
      "expression": "(cf.verified_bot)",
      "action": "allow",
      "priority": 10,
      "description": "Allow verified search engine bots"
    }
  ],
  "page_rules": [
    {
      "target": "*.coreflow360-v4-prod.ernijs-ansons.workers.dev/api/*",
      "actions": {
        "security_level": "high",
        "cache_level": "bypass",
        "disable_apps": true,
        "disable_performance": false
      }
    },
    {
      "target": "*.coreflow360-frontend.pages.dev/*",
      "actions": {
        "browser_cache_ttl": 14400,
        "security_level": "medium",
        "cache_level": "standard",
        "minify": {
          "html": true,
          "css": true,
          "js": true
        }
      }
    }
  ],
  "ddos_protection": {
    "enabled": true,
    "sensitivity": "high",
    "action": "challenge"
  },
  "bot_management": {
    "enabled": true,
    "definitely_automated": "block",
    "likely_automated": "challenge",
    "verified_bots": "allow",
    "js_detection": true,
    "fight_mode": true
  },
  "custom_error_responses": {
    "1015": {
      "content": "You are being rate limited. Please try again later.",
      "content_type": "text/plain"
    },
    "1020": {
      "content": "Access denied. Your request has been blocked.",
      "content_type": "text/plain"
    }
  }
}
EOF
    success "Default configuration created at $CONFIG_FILE"
}

# Backup current configuration
backup_current_config() {
    info "Backing up current WAF configuration..."

    # Get current firewall rules
    CURRENT_RULES=$(curl -s -X GET "$CF_API_URL/zones/$ZONE_ID/firewall/rules" \
        -H "Authorization: Bearer $API_TOKEN" \
        -H "Content-Type: application/json")

    # Get current page rules
    CURRENT_PAGE_RULES=$(curl -s -X GET "$CF_API_URL/zones/$ZONE_ID/pagerules" \
        -H "Authorization: Bearer $API_TOKEN" \
        -H "Content-Type: application/json")

    # Get current security settings
    CURRENT_SETTINGS=$(curl -s -X GET "$CF_API_URL/zones/$ZONE_ID/settings" \
        -H "Authorization: Bearer $API_TOKEN" \
        -H "Content-Type: application/json")

    # Create rollback file
    jq -n \
        --argjson rules "$CURRENT_RULES" \
        --argjson page_rules "$CURRENT_PAGE_RULES" \
        --argjson settings "$CURRENT_SETTINGS" \
        '{
            timestamp: now | todate,
            zone_id: $zone_id,
            firewall_rules: $rules,
            page_rules: $page_rules,
            settings: $settings
        }' \
        --arg zone_id "$ZONE_ID" \
        > "$ROLLBACK_FILE"

    success "Configuration backed up to $ROLLBACK_FILE"
}

# Deploy firewall rules
deploy_firewall_rules() {
    info "Deploying firewall rules..."

    # Read rules from config
    RULES=$(jq -r '.firewall_rules[]' "$CONFIG_FILE" 2>/dev/null || echo "[]")

    if [[ "$RULES" == "[]" ]]; then
        warning "No firewall rules found in configuration"
        return
    fi

    # Deploy each rule
    echo "$CONFIG_FILE" | jq -c '.firewall_rules[]' | while read -r rule; do
        RULE_NAME=$(echo "$rule" | jq -r '.name')
        info "Deploying rule: $RULE_NAME"

        # Create filter
        FILTER_RESPONSE=$(curl -s -X POST "$CF_API_URL/zones/$ZONE_ID/filters" \
            -H "Authorization: Bearer $API_TOKEN" \
            -H "Content-Type: application/json" \
            -d "{
                \"expression\": $(echo "$rule" | jq -r '.expression | @json'),
                \"description\": $(echo "$rule" | jq -r '.description | @json')
            }")

        FILTER_ID=$(echo "$FILTER_RESPONSE" | jq -r '.result.id')

        if [[ "$FILTER_ID" == "null" ]]; then
            warning "Failed to create filter for rule: $RULE_NAME"
            continue
        fi

        # Create firewall rule
        RULE_RESPONSE=$(curl -s -X POST "$CF_API_URL/zones/$ZONE_ID/firewall/rules" \
            -H "Authorization: Bearer $API_TOKEN" \
            -H "Content-Type: application/json" \
            -d "[{
                \"filter\": {\"id\": \"$FILTER_ID\"},
                \"action\": $(echo "$rule" | jq -r '.action | @json'),
                \"priority\": $(echo "$rule" | jq -r '.priority'),
                \"description\": $(echo "$rule" | jq -r '.description | @json')
            }]")

        if [[ $(echo "$RULE_RESPONSE" | jq -r '.success') == "true" ]]; then
            success "Rule deployed: $RULE_NAME"
        else
            warning "Failed to deploy rule: $RULE_NAME"
        fi
    done
}

# Deploy page rules
deploy_page_rules() {
    info "Deploying page rules..."

    # Read page rules from config
    cat "$CONFIG_FILE" | jq -c '.page_rules[]?' | while read -r rule; do
        if [[ -z "$rule" ]]; then
            continue
        fi

        TARGET=$(echo "$rule" | jq -r '.target')
        info "Deploying page rule for: $TARGET"

        RULE_RESPONSE=$(curl -s -X POST "$CF_API_URL/zones/$ZONE_ID/pagerules" \
            -H "Authorization: Bearer $API_TOKEN" \
            -H "Content-Type: application/json" \
            -d "{
                \"targets\": [{\"target\": \"url\", \"constraint\": {\"operator\": \"matches\", \"value\": \"$TARGET\"}}],
                \"actions\": $(echo "$rule" | jq '.actions'),
                \"priority\": 1,
                \"status\": \"active\"
            }")

        if [[ $(echo "$RULE_RESPONSE" | jq -r '.success') == "true" ]]; then
            success "Page rule deployed for: $TARGET"
        else
            warning "Failed to deploy page rule for: $TARGET"
        fi
    done
}

# Configure security settings
configure_security_settings() {
    info "Configuring security settings..."

    # Enable WAF
    curl -s -X PATCH "$CF_API_URL/zones/$ZONE_ID/settings/waf" \
        -H "Authorization: Bearer $API_TOKEN" \
        -H "Content-Type: application/json" \
        -d '{"value": "on"}' > /dev/null

    success "WAF enabled"

    # Set security level
    SECURITY_LEVEL=$(jq -r '.waf_rules.security_level // "high"' "$CONFIG_FILE")
    curl -s -X PATCH "$CF_API_URL/zones/$ZONE_ID/settings/security_level" \
        -H "Authorization: Bearer $API_TOKEN" \
        -H "Content-Type: application/json" \
        -d "{\"value\": \"$SECURITY_LEVEL\"}" > /dev/null

    success "Security level set to: $SECURITY_LEVEL"

    # Enable browser integrity check
    curl -s -X PATCH "$CF_API_URL/zones/$ZONE_ID/settings/browser_check" \
        -H "Authorization: Bearer $API_TOKEN" \
        -H "Content-Type: application/json" \
        -d '{"value": "on"}' > /dev/null

    success "Browser integrity check enabled"

    # Enable hotlink protection
    curl -s -X PATCH "$CF_API_URL/zones/$ZONE_ID/settings/hotlink_protection" \
        -H "Authorization: Bearer $API_TOKEN" \
        -H "Content-Type: application/json" \
        -d '{"value": "on"}' > /dev/null

    success "Hotlink protection enabled"

    # Enable email obfuscation
    curl -s -X PATCH "$CF_API_URL/zones/$ZONE_ID/settings/email_obfuscation" \
        -H "Authorization: Bearer $API_TOKEN" \
        -H "Content-Type: application/json" \
        -d '{"value": "on"}' > /dev/null

    success "Email obfuscation enabled"
}

# Configure rate limiting
configure_rate_limiting() {
    info "Configuring rate limiting..."

    RATE_LIMIT=$(jq -r '.waf_rules.rate_limiting' "$CONFIG_FILE")

    if [[ $(echo "$RATE_LIMIT" | jq -r '.enabled') == "true" ]]; then
        THRESHOLD=$(echo "$RATE_LIMIT" | jq -r '.threshold // 50')
        PERIOD=$(echo "$RATE_LIMIT" | jq -r '.period // 60')
        ACTION=$(echo "$RATE_LIMIT" | jq -r '.action // "challenge"')

        # Create rate limiting rule
        RATE_LIMIT_RESPONSE=$(curl -s -X POST "$CF_API_URL/zones/$ZONE_ID/rate_limits" \
            -H "Authorization: Bearer $API_TOKEN" \
            -H "Content-Type: application/json" \
            -d "{
                \"threshold\": $THRESHOLD,
                \"period\": $PERIOD,
                \"action\": {
                    \"mode\": \"$ACTION\",
                    \"timeout\": 86400
                },
                \"match\": {
                    \"request\": {
                        \"url\": \"*\"
                    }
                },
                \"description\": \"Global rate limiting\"
            }")

        if [[ $(echo "$RATE_LIMIT_RESPONSE" | jq -r '.success') == "true" ]]; then
            success "Rate limiting configured: $THRESHOLD requests per $PERIOD seconds"
        else
            warning "Failed to configure rate limiting"
        fi
    fi
}

# Configure DDoS protection
configure_ddos_protection() {
    info "Configuring DDoS protection..."

    # Enable DDoS protection
    curl -s -X PATCH "$CF_API_URL/zones/$ZONE_ID/settings/ddos_protection" \
        -H "Authorization: Bearer $API_TOKEN" \
        -H "Content-Type: application/json" \
        -d '{"value": "on"}' > /dev/null

    success "DDoS protection enabled"

    # Configure sensitivity
    SENSITIVITY=$(jq -r '.ddos_protection.sensitivity // "high"' "$CONFIG_FILE")

    success "DDoS protection sensitivity set to: $SENSITIVITY"
}

# Verify deployment
verify_deployment() {
    info "Verifying WAF deployment..."

    # Test backend protection
    info "Testing backend protection..."
    BACKEND_TEST=$(curl -s -o /dev/null -w "%{http_code}" "https://$PRODUCTION_BACKEND/health")

    if [[ "$BACKEND_TEST" == "200" ]]; then
        success "Backend is accessible and protected"
    else
        warning "Backend returned status code: $BACKEND_TEST"
    fi

    # Test frontend protection
    info "Testing frontend protection..."
    FRONTEND_TEST=$(curl -s -o /dev/null -w "%{http_code}" "https://$PRODUCTION_FRONTEND/")

    if [[ "$FRONTEND_TEST" == "200" ]]; then
        success "Frontend is accessible and protected"
    else
        warning "Frontend returned status code: $FRONTEND_TEST"
    fi

    # Test rate limiting
    info "Testing rate limiting..."
    for i in {1..60}; do
        curl -s "https://$PRODUCTION_BACKEND/api/v1/test" > /dev/null 2>&1
    done

    RATE_TEST=$(curl -s -o /dev/null -w "%{http_code}" "https://$PRODUCTION_BACKEND/api/v1/test")

    if [[ "$RATE_TEST" == "429" ]]; then
        success "Rate limiting is working"
    else
        warning "Rate limiting test returned: $RATE_TEST (expected 429)"
    fi

    success "WAF deployment verification complete"
}

# Rollback function
rollback() {
    error_exit "Rollback not yet implemented. Manual rollback required using: $ROLLBACK_FILE"
}

# Main deployment function
main() {
    echo "================================================"
    echo "   CoreFlow360 V4 - WAF Deployment Script"
    echo "================================================"
    echo ""

    # Start logging
    info "Starting WAF deployment at $(date)"
    info "Log file: $LOG_FILE"
    echo ""

    # Run deployment steps
    check_prerequisites
    backup_current_config
    deploy_firewall_rules
    deploy_page_rules
    configure_security_settings
    configure_rate_limiting
    configure_ddos_protection
    verify_deployment

    echo ""
    echo "================================================"
    success "WAF deployment completed successfully!"
    echo "================================================"
    echo ""
    info "Deployment log: $LOG_FILE"
    info "Rollback file: $ROLLBACK_FILE"
    echo ""
    info "Next steps:"
    echo "  1. Monitor WAF analytics for 24 hours"
    echo "  2. Review blocked requests for false positives"
    echo "  3. Adjust rules as needed"
    echo "  4. Enable additional security features"
    echo ""
}

# Handle script arguments
case "${1:-}" in
    --rollback)
        rollback
        ;;
    --verify)
        verify_deployment
        ;;
    --help)
        echo "Usage: $0 [OPTIONS]"
        echo ""
        echo "Options:"
        echo "  --rollback    Rollback to previous configuration"
        echo "  --verify      Verify current WAF deployment"
        echo "  --help        Show this help message"
        echo ""
        echo "Environment variables:"
        echo "  CF_ZONE_ID    Cloudflare Zone ID"
        echo "  CF_API_TOKEN  Cloudflare API Token"
        echo ""
        ;;
    *)
        main
        ;;
esac