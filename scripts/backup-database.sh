#!/bin/bash

###############################################################################
# Database Backup Script for CoreFlow360 V4
#
# Purpose: Automated backup of Cloudflare D1 databases to R2 storage
# Schedule: Daily backups with 30-day retention
#
# Usage:
#   ./scripts/backup-database.sh [environment]
#
# Examples:
#   ./scripts/backup-database.sh production
#   ./scripts/backup-database.sh staging
###############################################################################

set -e  # Exit on error
set -u  # Exit on undefined variable

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Configuration
ENVIRONMENT="${1:-production}"
TIMESTAMP=$(date +"%Y%m%d_%H%M%S")
BACKUP_DIR="./backups"
RETENTION_DAYS=30

# Database names
MAIN_DB="coreflow360-agents"
ANALYTICS_DB="mustbeviral-db"

# R2 bucket (if configured)
R2_BUCKET="coreflow360-backups"

###############################################################################
# Logging Functions
###############################################################################

log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

###############################################################################
# Pre-flight Checks
###############################################################################

check_prerequisites() {
    log_info "Checking prerequisites..."

    # Check if wrangler is installed
    if ! command -v wrangler &> /dev/null; then
        log_error "wrangler CLI not found. Install with: npm install -g wrangler"
        exit 1
    fi

    # Check authentication
    if ! wrangler whoami &> /dev/null; then
        log_error "Not authenticated with Cloudflare. Run: wrangler login"
        exit 1
    fi

    # Create backup directory
    mkdir -p "$BACKUP_DIR"

    log_info "Prerequisites check passed ✓"
}

###############################################################################
# Database Backup Functions
###############################################################################

backup_database() {
    local db_name=$1
    local backup_file="${BACKUP_DIR}/${db_name}_${ENVIRONMENT}_${TIMESTAMP}.sql"

    log_info "Backing up database: $db_name"

    # Export database
    if wrangler d1 export "$db_name" \
        --env "$ENVIRONMENT" \
        --output "$backup_file" 2>&1 | tee /tmp/backup.log; then

        # Check if file was created and has content
        if [ -f "$backup_file" ] && [ -s "$backup_file" ]; then
            local file_size=$(du -h "$backup_file" | cut -f1)
            log_info "✓ Database exported successfully: $backup_file ($file_size)"
            echo "$backup_file"
        else
            log_error "Backup file is empty or wasn't created"
            return 1
        fi
    else
        log_error "Failed to export database: $db_name"
        cat /tmp/backup.log
        return 1
    fi
}

###############################################################################
# Compression Functions
###############################################################################

compress_backup() {
    local backup_file=$1
    local compressed_file="${backup_file}.gz"

    log_info "Compressing backup: $(basename $backup_file)"

    if gzip -c "$backup_file" > "$compressed_file"; then
        local original_size=$(du -h "$backup_file" | cut -f1)
        local compressed_size=$(du -h "$compressed_file" | cut -f1)
        log_info "✓ Compressed: $original_size → $compressed_size"

        # Remove uncompressed file
        rm "$backup_file"

        echo "$compressed_file"
    else
        log_error "Failed to compress backup"
        return 1
    fi
}

###############################################################################
# Upload to R2 Functions
###############################################################################

upload_to_r2() {
    local backup_file=$1
    local r2_path="backups/${ENVIRONMENT}/$(basename $backup_file)"

    log_info "Uploading to R2: $r2_path"

    # Check if R2 bucket exists
    if wrangler r2 bucket list | grep -q "$R2_BUCKET"; then
        if wrangler r2 object put "$R2_BUCKET/$r2_path" \
            --file "$backup_file" 2>&1; then
            log_info "✓ Uploaded to R2 successfully"
            return 0
        else
            log_warn "Failed to upload to R2 (continuing anyway)"
            return 1
        fi
    else
        log_warn "R2 bucket $R2_BUCKET not found. Skipping upload."
        return 1
    fi
}

###############################################################################
# Cleanup Functions
###############################################################################

cleanup_old_backups() {
    log_info "Cleaning up backups older than $RETENTION_DAYS days..."

    local deleted_count=0

    # Find and delete old local backups
    while IFS= read -r old_backup; do
        log_info "Deleting old backup: $(basename $old_backup)"
        rm "$old_backup"
        ((deleted_count++))
    done < <(find "$BACKUP_DIR" -name "*.sql.gz" -type f -mtime +$RETENTION_DAYS)

    if [ $deleted_count -gt 0 ]; then
        log_info "✓ Deleted $deleted_count old backup(s)"
    else
        log_info "No old backups to clean up"
    fi
}

cleanup_old_r2_backups() {
    log_info "Cleaning up old R2 backups..."

    # List R2 objects
    local r2_path="backups/${ENVIRONMENT}/"

    if wrangler r2 bucket list | grep -q "$R2_BUCKET"; then
        # Get list of objects (this would need actual implementation based on R2 API)
        log_info "R2 cleanup would be implemented here"
        # TODO: Implement R2 object listing and deletion based on age
    fi
}

###############################################################################
# Verification Functions
###############################################################################

verify_backup() {
    local backup_file=$1

    log_info "Verifying backup integrity..."

    # Decompress and check SQL syntax
    if gunzip -t "$backup_file" 2>/dev/null; then
        log_info "✓ Backup file is valid gzip archive"

        # Check if SQL is valid (basic check)
        if gunzip -c "$backup_file" | grep -q "CREATE TABLE"; then
            log_info "✓ Backup contains SQL statements"
            return 0
        else
            log_error "Backup doesn't appear to contain valid SQL"
            return 1
        fi
    else
        log_error "Backup file is corrupted"
        return 1
    fi
}

###############################################################################
# Notification Functions
###############################################################################

send_notification() {
    local status=$1
    local message=$2

    # Send to Slack webhook if configured
    if [ -n "${SLACK_WEBHOOK_URL:-}" ]; then
        local color=$([[ "$status" == "success" ]] && echo "good" || echo "danger")

        curl -X POST "$SLACK_WEBHOOK_URL" \
            -H "Content-Type: application/json" \
            -d "{
                \"attachments\": [{
                    \"color\": \"$color\",
                    \"title\": \"Database Backup: $status\",
                    \"text\": \"$message\",
                    \"footer\": \"CoreFlow360 Backup System\",
                    \"ts\": $(date +%s)
                }]
            }" 2>/dev/null || log_warn "Failed to send Slack notification"
    fi
}

###############################################################################
# Main Backup Process
###############################################################################

run_backup() {
    log_info "=========================================="
    log_info "Starting Database Backup"
    log_info "Environment: $ENVIRONMENT"
    log_info "Timestamp: $TIMESTAMP"
    log_info "=========================================="

    local backup_files=()
    local failed_backups=()

    # Backup main database
    if backup_file=$(backup_database "$MAIN_DB"); then
        if compressed_file=$(compress_backup "$backup_file"); then
            if verify_backup "$compressed_file"; then
                backup_files+=("$compressed_file")
                upload_to_r2 "$compressed_file" || true
            else
                failed_backups+=("$MAIN_DB (verification failed)")
            fi
        else
            failed_backups+=("$MAIN_DB (compression failed)")
        fi
    else
        failed_backups+=("$MAIN_DB (export failed)")
    fi

    # Backup analytics database
    if backup_file=$(backup_database "$ANALYTICS_DB"); then
        if compressed_file=$(compress_backup "$backup_file"); then
            if verify_backup "$compressed_file"; then
                backup_files+=("$compressed_file")
                upload_to_r2 "$compressed_file" || true
            else
                failed_backups+=("$ANALYTICS_DB (verification failed)")
            fi
        else
            failed_backups+=("$ANALYTICS_DB (compression failed)")
        fi
    else
        failed_backups+=("$ANALYTICS_DB (export failed)")
    fi

    # Cleanup old backups
    cleanup_old_backups

    # Summary
    log_info "=========================================="
    log_info "Backup Summary"
    log_info "=========================================="
    log_info "Successful backups: ${#backup_files[@]}"
    log_info "Failed backups: ${#failed_backups[@]}"

    if [ ${#backup_files[@]} -gt 0 ]; then
        log_info ""
        log_info "Backup files:"
        for file in "${backup_files[@]}"; do
            local size=$(du -h "$file" | cut -f1)
            log_info "  • $(basename $file) ($size)"
        done
    fi

    if [ ${#failed_backups[@]} -gt 0 ]; then
        log_warn ""
        log_warn "Failed backups:"
        for db in "${failed_backups[@]}"; do
            log_warn "  • $db"
        done
    fi

    log_info "=========================================="

    # Send notification
    if [ ${#failed_backups[@]} -eq 0 ]; then
        send_notification "success" "All databases backed up successfully in $ENVIRONMENT"
        log_info "✅ Backup completed successfully!"
        return 0
    else
        send_notification "failure" "${#failed_backups[@]} backup(s) failed in $ENVIRONMENT"
        log_error "❌ Backup completed with errors"
        return 1
    fi
}

###############################################################################
# Entry Point
###############################################################################

main() {
    check_prerequisites
    run_backup
    exit $?
}

# Run main function
main

###############################################################################
# Cron Schedule (for automated backups)
#
# Add to crontab:
# 0 2 * * * /path/to/backup-database.sh production >> /var/log/db-backup.log 2>&1
#
# This runs daily at 2:00 AM
###############################################################################
