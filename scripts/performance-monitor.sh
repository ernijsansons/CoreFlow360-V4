#!/bin/bash

################################################################################
# CoreFlow360 V4 - Continuous Performance Monitoring
#
# Monitors production performance metrics and alerts on degradation
# - Core Web Vitals tracking
# - API response time monitoring
# - Database query performance
# - Cache hit rate analysis
# - Error rate tracking
# - Resource utilization
#
# Usage:
#   ./scripts/performance-monitor.sh [environment] [duration_minutes]
#
# Examples:
#   ./scripts/performance-monitor.sh production 60
#   ./scripts/performance-monitor.sh staging 30
################################################################################

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Configuration
ENVIRONMENT="${1:-production}"
DURATION_MINUTES="${2:-60}"
CHECK_INTERVAL=60  # Check every 60 seconds

# Environment URLs
if [ "$ENVIRONMENT" = "production" ]; then
    BASE_URL="https://api.coreflow360.com"
    FRONTEND_URL="https://coreflow360.com"
elif [ "$ENVIRONMENT" = "staging" ]; then
    BASE_URL="https://staging-api.coreflow360.com"
    FRONTEND_URL="https://staging.coreflow360.com"
else
    echo -e "${RED}❌ Invalid environment: $ENVIRONMENT${NC}"
    exit 1
fi

# Metrics storage
METRICS_FILE="performance-metrics-${ENVIRONMENT}-$(date +%Y%m%d-%H%M%S).json"
echo "[]" > "$METRICS_FILE"

# Alert thresholds
RESPONSE_TIME_WARN=200      # ms
RESPONSE_TIME_CRITICAL=500  # ms
ERROR_RATE_WARN=0.05        # 5%
ERROR_RATE_CRITICAL=0.10    # 10%
CACHE_HIT_RATE_WARN=0.60    # 60%

################################################################################
# Helper Functions
################################################################################

print_header() {
    echo ""
    echo -e "${BLUE}================================================${NC}"
    echo -e "${BLUE}$1${NC}"
    echo -e "${BLUE}================================================${NC}"
    echo ""
}

print_metric() {
    echo -e "${YELLOW}📊 $1${NC}"
}

print_alert() {
    echo -e "${RED}🚨 ALERT: $1${NC}"
}

print_warn() {
    echo -e "${YELLOW}⚠️  WARNING: $1${NC}"
}

print_ok() {
    echo -e "${GREEN}✅ $1${NC}"
}

# Get current timestamp
get_timestamp() {
    date +"%Y-%m-%d %H:%M:%S"
}

# Measure endpoint response time
measure_response_time() {
    local endpoint=$1
    local response_time=$(curl -s -w "%{time_total}" -o /dev/null "$BASE_URL$endpoint" 2>&1)
    local response_time_ms=$(echo "$response_time * 1000" | bc | cut -d'.' -f1)
    echo "$response_time_ms"
}

# Check API health
check_api_health() {
    local response=$(curl -s "$BASE_URL/api/health" 2>&1)
    echo "$response"
}

# Store metric
store_metric() {
    local metric_name=$1
    local metric_value=$2
    local timestamp=$(get_timestamp)

    local metric_json=$(jq -n \
        --arg name "$metric_name" \
        --arg value "$metric_value" \
        --arg time "$timestamp" \
        '{name: $name, value: $value, timestamp: $time}')

    jq ". += [$metric_json]" "$METRICS_FILE" > "${METRICS_FILE}.tmp"
    mv "${METRICS_FILE}.tmp" "$METRICS_FILE"
}

# Calculate average
calculate_average() {
    local metric_name=$1
    local avg=$(jq -r "[.[] | select(.name == \"$metric_name\") | .value | tonumber] | add / length" "$METRICS_FILE")
    echo "$avg"
}

# Send alert
send_alert() {
    local severity=$1
    local message=$2

    print_alert "$message"

    if [ -n "$SLACK_WEBHOOK_URL" ]; then
        local color="danger"
        if [ "$severity" = "warning" ]; then
            color="warning"
        fi

        curl -X POST "$SLACK_WEBHOOK_URL" \
            -H 'Content-Type: application/json' \
            -d "{
                \"text\": \"🚨 Performance Alert: $ENVIRONMENT\",
                \"attachments\": [{
                    \"color\": \"$color\",
                    \"text\": \"$message\",
                    \"footer\": \"Performance Monitor\",
                    \"ts\": $(date +%s)
                }]
            }" \
            --silent > /dev/null
    fi
}

################################################################################
# Monitoring Functions
################################################################################

monitor_api_response_times() {
    print_metric "API Response Times"

    local endpoints=(
        "/health"
        "/api/status"
        "/api/users/me"
        "/api/dashboard"
        "/api/agents/status"
    )

    local total_time=0
    local count=0

    for endpoint in "${endpoints[@]}"; do
        local response_time=$(measure_response_time "$endpoint")

        if [ -n "$response_time" ] && [ "$response_time" -gt 0 ]; then
            store_metric "response_time_${endpoint//\//_}" "$response_time"
            total_time=$((total_time + response_time))
            count=$((count + 1))

            echo "  ${endpoint}: ${response_time}ms"

            # Alert on slow response
            if [ "$response_time" -gt "$RESPONSE_TIME_CRITICAL" ]; then
                send_alert "critical" "Critical: $endpoint response time ${response_time}ms (threshold: ${RESPONSE_TIME_CRITICAL}ms)"
            elif [ "$response_time" -gt "$RESPONSE_TIME_WARN" ]; then
                send_alert "warning" "Warning: $endpoint response time ${response_time}ms (threshold: ${RESPONSE_TIME_WARN}ms)"
            fi
        fi
    done

    if [ $count -gt 0 ]; then
        local avg_time=$((total_time / count))
        store_metric "avg_response_time" "$avg_time"
        echo "  Average: ${avg_time}ms"

        if [ "$avg_time" -lt 100 ]; then
            print_ok "Excellent response times (<100ms)"
        elif [ "$avg_time" -lt 200 ]; then
            print_ok "Good response times (<200ms)"
        else
            print_warn "Slow response times (${avg_time}ms)"
        fi
    fi
}

monitor_error_rate() {
    print_metric "Error Rate"

    local health_data=$(check_api_health)

    if [ -n "$health_data" ]; then
        local total_requests=$(echo "$health_data" | jq -r '.metrics.totalRequests // 0')
        local error_count=$(echo "$health_data" | jq -r '.metrics.errorCount // 0')

        if [ "$total_requests" -gt 0 ]; then
            local error_rate=$(echo "scale=4; $error_count / $total_requests" | bc)
            local error_rate_percent=$(echo "$error_rate * 100" | bc | cut -d'.' -f1)

            store_metric "error_rate" "$error_rate"

            echo "  Total Requests: $total_requests"
            echo "  Errors: $error_count"
            echo "  Error Rate: ${error_rate_percent}%"

            # Compare error_rate as float
            if (( $(echo "$error_rate > $ERROR_RATE_CRITICAL" | bc -l) )); then
                send_alert "critical" "Critical: Error rate ${error_rate_percent}% exceeds threshold"
            elif (( $(echo "$error_rate > $ERROR_RATE_WARN" | bc -l) )); then
                send_alert "warning" "Warning: Error rate ${error_rate_percent}% elevated"
            else
                print_ok "Error rate within normal range"
            fi
        else
            echo "  No requests recorded yet"
        fi
    fi
}

monitor_cache_performance() {
    print_metric "Cache Performance"

    local health_data=$(check_api_health)

    if [ -n "$health_data" ]; then
        local cache_hits=$(echo "$health_data" | jq -r '.cache.hits // 0')
        local cache_misses=$(echo "$health_data" | jq -r '.cache.misses // 0')
        local total_cache_requests=$((cache_hits + cache_misses))

        if [ $total_cache_requests -gt 0 ]; then
            local hit_rate=$(echo "scale=4; $cache_hits / $total_cache_requests" | bc)
            local hit_rate_percent=$(echo "$hit_rate * 100" | bc | cut -d'.' -f1)

            store_metric "cache_hit_rate" "$hit_rate"

            echo "  Cache Hits: $cache_hits"
            echo "  Cache Misses: $cache_misses"
            echo "  Hit Rate: ${hit_rate_percent}%"

            if (( $(echo "$hit_rate < $CACHE_HIT_RATE_WARN" | bc -l) )); then
                send_alert "warning" "Warning: Cache hit rate ${hit_rate_percent}% below target (60%)"
            else
                print_ok "Cache performing well"
            fi
        else
            echo "  No cache activity recorded"
        fi
    fi
}

monitor_database_performance() {
    print_metric "Database Performance"

    local health_data=$(check_api_health)

    if [ -n "$health_data" ]; then
        local db_status=$(echo "$health_data" | jq -r '.database.status // "unknown"')
        local query_time=$(echo "$health_data" | jq -r '.database.avgQueryTime // 0')

        echo "  Status: $db_status"
        echo "  Avg Query Time: ${query_time}ms"

        store_metric "db_query_time" "$query_time"

        if [ "$db_status" != "healthy" ]; then
            send_alert "critical" "Critical: Database status is $db_status"
        elif [ "$query_time" -gt 50 ]; then
            send_alert "warning" "Warning: Database queries slow (${query_time}ms avg)"
        else
            print_ok "Database performing well"
        fi
    fi
}

monitor_frontend_vitals() {
    print_metric "Frontend Core Web Vitals"

    # Fetch Core Web Vitals from analytics endpoint
    local vitals_response=$(curl -s "$BASE_URL/api/analytics/web-vitals" 2>&1)

    if [ -n "$vitals_response" ]; then
        local lcp=$(echo "$vitals_response" | jq -r '.lcp.p75 // 0')
        local fid=$(echo "$vitals_response" | jq -r '.fid.p75 // 0')
        local cls=$(echo "$vitals_response" | jq -r '.cls.p75 // 0')

        echo "  LCP (p75): ${lcp}ms"
        echo "  FID (p75): ${fid}ms"
        echo "  CLS (p75): ${cls}"

        store_metric "lcp" "$lcp"
        store_metric "fid" "$fid"
        store_metric "cls" "$cls"

        # Check thresholds
        if [ "$lcp" -gt 2500 ]; then
            send_alert "warning" "Warning: LCP ${lcp}ms exceeds 2.5s threshold"
        fi

        if [ "$fid" -gt 100 ]; then
            send_alert "warning" "Warning: FID ${fid}ms exceeds 100ms threshold"
        fi
    fi
}

monitor_ai_agents() {
    print_metric "AI Agent Performance"

    local agent_response=$(curl -s "$BASE_URL/api/agents/status" 2>&1)

    if [ -n "$agent_response" ]; then
        local orchestrator_status=$(echo "$agent_response" | jq -r '.orchestrator.status // "unknown"')
        local active_tasks=$(echo "$agent_response" | jq -r '.orchestrator.activeTasks // 0')
        local avg_task_time=$(echo "$agent_response" | jq -r '.orchestrator.avgTaskTime // 0')

        echo "  Orchestrator Status: $orchestrator_status"
        echo "  Active Tasks: $active_tasks"
        echo "  Avg Task Time: ${avg_task_time}ms"

        store_metric "ai_agent_status" "$([ "$orchestrator_status" = "operational" ] && echo "1" || echo "0")"
        store_metric "ai_active_tasks" "$active_tasks"

        if [ "$orchestrator_status" != "operational" ]; then
            send_alert "critical" "Critical: AI Agent orchestrator is $orchestrator_status"
        elif [ "$active_tasks" -gt 100 ]; then
            send_alert "warning" "Warning: High AI agent task queue ($active_tasks tasks)"
        else
            print_ok "AI agents operating normally"
        fi
    fi
}

################################################################################
# Main Monitoring Loop
################################################################################

print_header "CoreFlow360 V4 Performance Monitor"
echo "Environment: $ENVIRONMENT"
echo "Duration: ${DURATION_MINUTES} minutes"
echo "Check Interval: ${CHECK_INTERVAL} seconds"
echo "Metrics File: $METRICS_FILE"
echo ""

# Calculate end time
END_TIME=$(($(date +%s) + DURATION_MINUTES * 60))
CHECK_COUNT=0

echo "Starting monitoring at $(get_timestamp)"
echo "Will run until $(date -d "@$END_TIME" "+%Y-%m-%d %H:%M:%S")"
echo ""

while [ $(date +%s) -lt $END_TIME ]; do
    CHECK_COUNT=$((CHECK_COUNT + 1))

    print_header "Check #$CHECK_COUNT - $(get_timestamp)"

    # Run all monitoring checks
    monitor_api_response_times
    echo ""

    monitor_error_rate
    echo ""

    monitor_cache_performance
    echo ""

    monitor_database_performance
    echo ""

    monitor_frontend_vitals
    echo ""

    monitor_ai_agents
    echo ""

    # Sleep until next check
    REMAINING_TIME=$((END_TIME - $(date +%s)))
    if [ $REMAINING_TIME -gt 0 ]; then
        SLEEP_TIME=$CHECK_INTERVAL
        if [ $REMAINING_TIME -lt $CHECK_INTERVAL ]; then
            SLEEP_TIME=$REMAINING_TIME
        fi

        echo "Next check in ${SLEEP_TIME}s..."
        sleep $SLEEP_TIME
    fi
done

################################################################################
# Generate Summary Report
################################################################################

print_header "Performance Monitoring Summary"

echo "Environment: $ENVIRONMENT"
echo "Duration: ${DURATION_MINUTES} minutes"
echo "Total Checks: $CHECK_COUNT"
echo "Metrics File: $METRICS_FILE"
echo ""

# Calculate summary statistics
echo "📊 Summary Statistics:"
echo ""

# Average response time
AVG_RESPONSE=$(calculate_average "avg_response_time")
if [ -n "$AVG_RESPONSE" ] && [ "$AVG_RESPONSE" != "null" ]; then
    AVG_RESPONSE_INT=$(echo "$AVG_RESPONSE" | cut -d'.' -f1)
    echo "  Average Response Time: ${AVG_RESPONSE_INT}ms"
fi

# Average error rate
AVG_ERROR=$(calculate_average "error_rate")
if [ -n "$AVG_ERROR" ] && [ "$AVG_ERROR" != "null" ]; then
    AVG_ERROR_PERCENT=$(echo "$AVG_ERROR * 100" | bc | cut -d'.' -f1)
    echo "  Average Error Rate: ${AVG_ERROR_PERCENT}%"
fi

# Average cache hit rate
AVG_CACHE=$(calculate_average "cache_hit_rate")
if [ -n "$AVG_CACHE" ] && [ "$AVG_CACHE" != "null" ]; then
    AVG_CACHE_PERCENT=$(echo "$AVG_CACHE * 100" | bc | cut -d'.' -f1)
    echo "  Average Cache Hit Rate: ${AVG_CACHE_PERCENT}%"
fi

# Database performance
AVG_DB=$(calculate_average "db_query_time")
if [ -n "$AVG_DB" ] && [ "$AVG_DB" != "null" ]; then
    AVG_DB_INT=$(echo "$AVG_DB" | cut -d'.' -f1)
    echo "  Average DB Query Time: ${AVG_DB_INT}ms"
fi

# Generate detailed report
REPORT_FILE="performance-report-${ENVIRONMENT}-$(date +%Y%m%d-%H%M%S).html"

cat > "$REPORT_FILE" <<EOF
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Performance Report - $ENVIRONMENT</title>
    <script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.0/dist/chart.umd.min.js"></script>
    <style>
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; margin: 20px; background: #f5f5f5; }
        .container { max-width: 1200px; margin: 0 auto; background: white; padding: 30px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
        h1 { color: #333; border-bottom: 3px solid #007bff; padding-bottom: 10px; }
        .metric { margin: 20px 0; padding: 15px; background: #f8f9fa; border-left: 4px solid #007bff; }
        .chart-container { width: 100%; height: 400px; margin: 30px 0; }
        .stats { display: grid; grid-template-columns: repeat(auto-fit, minmax(250px, 1fr)); gap: 20px; margin: 30px 0; }
        .stat-card { padding: 20px; background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; border-radius: 8px; }
        .stat-value { font-size: 2em; font-weight: bold; }
        .stat-label { opacity: 0.9; margin-top: 5px; }
    </style>
</head>
<body>
    <div class="container">
        <h1>Performance Report - $ENVIRONMENT</h1>
        <p><strong>Date:</strong> $(date)</p>
        <p><strong>Duration:</strong> ${DURATION_MINUTES} minutes</p>
        <p><strong>Total Checks:</strong> $CHECK_COUNT</p>

        <div class="stats">
            <div class="stat-card">
                <div class="stat-value">${AVG_RESPONSE_INT}ms</div>
                <div class="stat-label">Avg Response Time</div>
            </div>
            <div class="stat-card" style="background: linear-gradient(135deg, #f093fb 0%, #f5576c 100%);">
                <div class="stat-value">${AVG_ERROR_PERCENT}%</div>
                <div class="stat-label">Avg Error Rate</div>
            </div>
            <div class="stat-card" style="background: linear-gradient(135deg, #4facfe 0%, #00f2fe 100%);">
                <div class="stat-value">${AVG_CACHE_PERCENT}%</div>
                <div class="stat-label">Avg Cache Hit Rate</div>
            </div>
            <div class="stat-card" style="background: linear-gradient(135deg, #43e97b 0%, #38f9d7 100%);">
                <div class="stat-value">${AVG_DB_INT}ms</div>
                <div class="stat-label">Avg DB Query Time</div>
            </div>
        </div>

        <div class="metric">
            <h2>Response Time Trend</h2>
            <div class="chart-container">
                <canvas id="responseTimeChart"></canvas>
            </div>
        </div>

        <div class="metric">
            <h2>Error Rate Trend</h2>
            <div class="chart-container">
                <canvas id="errorRateChart"></canvas>
            </div>
        </div>

        <div class="metric">
            <h2>Cache Performance</h2>
            <div class="chart-container">
                <canvas id="cacheChart"></canvas>
            </div>
        </div>

        <div class="metric">
            <h2>Raw Data</h2>
            <pre id="rawData"></pre>
        </div>
    </div>

    <script>
        // Load metrics data
        const metrics = $(cat "$METRICS_FILE");

        // Extract response time data
        const responseTimes = metrics.filter(m => m.name === 'avg_response_time');
        const responseTimeLabels = responseTimes.map(m => m.timestamp);
        const responseTimeValues = responseTimes.map(m => parseFloat(m.value));

        // Response Time Chart
        new Chart(document.getElementById('responseTimeChart'), {
            type: 'line',
            data: {
                labels: responseTimeLabels,
                datasets: [{
                    label: 'Response Time (ms)',
                    data: responseTimeValues,
                    borderColor: 'rgb(75, 192, 192)',
                    tension: 0.1
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                scales: {
                    y: {
                        beginAtZero: true
                    }
                }
            }
        });

        // Error Rate Chart
        const errorRates = metrics.filter(m => m.name === 'error_rate');
        new Chart(document.getElementById('errorRateChart'), {
            type: 'line',
            data: {
                labels: errorRates.map(m => m.timestamp),
                datasets: [{
                    label: 'Error Rate (%)',
                    data: errorRates.map(m => parseFloat(m.value) * 100),
                    borderColor: 'rgb(255, 99, 132)',
                    tension: 0.1
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                scales: {
                    y: {
                        beginAtZero: true
                    }
                }
            }
        });

        // Cache Hit Rate Chart
        const cacheRates = metrics.filter(m => m.name === 'cache_hit_rate');
        new Chart(document.getElementById('cacheChart'), {
            type: 'line',
            data: {
                labels: cacheRates.map(m => m.timestamp),
                datasets: [{
                    label: 'Cache Hit Rate (%)',
                    data: cacheRates.map(m => parseFloat(m.value) * 100),
                    borderColor: 'rgb(54, 162, 235)',
                    tension: 0.1
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                scales: {
                    y: {
                        beginAtZero: true,
                        max: 100
                    }
                }
            }
        });

        // Display raw data
        document.getElementById('rawData').textContent = JSON.stringify(metrics, null, 2);
    </script>
</body>
</html>
EOF

echo ""
echo "📄 Detailed HTML report generated: $REPORT_FILE"
echo "📊 Metrics data saved: $METRICS_FILE"
echo ""

# Send final summary
if [ -n "$SLACK_WEBHOOK_URL" ]; then
    curl -X POST "$SLACK_WEBHOOK_URL" \
        -H 'Content-Type: application/json' \
        -d "{
            \"text\": \"📊 Performance Monitoring Complete: $ENVIRONMENT\",
            \"attachments\": [{
                \"color\": \"good\",
                \"fields\": [
                    {\"title\": \"Duration\", \"value\": \"${DURATION_MINUTES} minutes\", \"short\": true},
                    {\"title\": \"Checks\", \"value\": \"$CHECK_COUNT\", \"short\": true},
                    {\"title\": \"Avg Response\", \"value\": \"${AVG_RESPONSE_INT}ms\", \"short\": true},
                    {\"title\": \"Error Rate\", \"value\": \"${AVG_ERROR_PERCENT}%\", \"short\": true}
                ]
            }]
        }" \
        --silent > /dev/null
fi

print_header "Monitoring Complete"
echo -e "${GREEN}✅ Performance monitoring completed successfully${NC}"
echo "Open $REPORT_FILE in a browser to view detailed charts"
