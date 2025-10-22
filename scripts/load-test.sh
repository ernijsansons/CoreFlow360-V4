#!/bin/bash

################################################################################
# CoreFlow360 V4 - Load Testing Script
#
# Simulates concurrent user load to test system scalability and performance
# - Configurable concurrent users
# - Configurable request duration
# - Random endpoint selection
# - Response time tracking
# - Error rate calculation
# - Throughput measurement
#
# Usage:
#   ./scripts/load-test.sh [environment] [concurrent_users] [duration_seconds]
#
# Examples:
#   ./scripts/load-test.sh staging 10 60
#   ./scripts/load-test.sh production 50 300
################################################################################

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Configuration
ENVIRONMENT="${1:-staging}"
CONCURRENT_USERS="${2:-10}"
DURATION="${3:-60}"

# Environment URLs
if [ "$ENVIRONMENT" = "production" ]; then
    BASE_URL="https://api.coreflow360.com"
elif [ "$ENVIRONMENT" = "staging" ]; then
    BASE_URL="https://staging-api.coreflow360.com"
else
    echo -e "${RED}❌ Invalid environment: $ENVIRONMENT${NC}"
    exit 1
fi

# Test configuration
TEST_ID="load-test-$(date +%Y%m%d-%H%M%S)"
RESULTS_DIR="load-test-results"
mkdir -p "$RESULTS_DIR"

# Endpoints to test
ENDPOINTS=(
    "/health"
    "/api/status"
    "/api/agents/status"
)

# Metrics
TOTAL_REQUESTS=0
SUCCESSFUL_REQUESTS=0
FAILED_REQUESTS=0
TOTAL_RESPONSE_TIME=0

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

print_info() {
    echo -e "${YELLOW}ℹ️  $1${NC}"
}

print_success() {
    echo -e "${GREEN}✅ $1${NC}"
}

print_error() {
    echo -e "${RED}❌ $1${NC}"
}

# Simulate a single user session
simulate_user() {
    local user_id=$1
    local start_time=$(date +%s)
    local end_time=$((start_time + DURATION))
    local user_requests=0
    local user_errors=0
    local user_response_time=0

    while [ $(date +%s) -lt $end_time ]; do
        # Random endpoint selection
        local endpoint=${ENDPOINTS[$RANDOM % ${#ENDPOINTS[@]}]}

        # Make request
        local request_start=$(date +%s%N)
        local response=$(curl -s -w "\n%{http_code}\n%{time_total}" -o /dev/null "$BASE_URL$endpoint" 2>&1)
        local request_end=$(date +%s%N)

        local status_code=$(echo "$response" | sed -n '1p')
        local response_time=$(echo "$response" | sed -n '2p')
        local response_time_ms=$(echo "$response_time * 1000" | bc | cut -d'.' -f1)

        # Update metrics
        user_requests=$((user_requests + 1))
        TOTAL_REQUESTS=$((TOTAL_REQUESTS + 1))

        if [ "$status_code" = "200" ]; then
            SUCCESSFUL_REQUESTS=$((SUCCESSFUL_REQUESTS + 1))
            user_response_time=$((user_response_time + response_time_ms))
            TOTAL_RESPONSE_TIME=$((TOTAL_RESPONSE_TIME + response_time_ms))
        else
            FAILED_REQUESTS=$((FAILED_REQUESTS + 1))
            user_errors=$((user_errors + 1))
        fi

        # Log request
        echo "$(date +%s),$user_id,$endpoint,$status_code,$response_time_ms" >> "$RESULTS_DIR/${TEST_ID}-requests.csv"

        # Random think time (0.5-2 seconds)
        sleep $(echo "scale=2; ($RANDOM % 15 + 5) / 10" | bc)
    done

    # Calculate user metrics
    local avg_response_time=0
    if [ $user_requests -gt 0 ]; then
        avg_response_time=$((user_response_time / user_requests))
    fi

    echo "$user_id,$user_requests,$user_errors,$avg_response_time" >> "$RESULTS_DIR/${TEST_ID}-users.csv"
}

################################################################################
# Main Load Test
################################################################################

print_header "CoreFlow360 V4 Load Test"
echo "Test ID: $TEST_ID"
echo "Environment: $ENVIRONMENT"
echo "Base URL: $BASE_URL"
echo "Concurrent Users: $CONCURRENT_USERS"
echo "Duration: ${DURATION}s"
echo ""

# Confirm production load test
if [ "$ENVIRONMENT" = "production" ]; then
    echo -e "${RED}⚠️  WARNING: This will run a load test against PRODUCTION${NC}"
    read -p "Are you sure you want to continue? (yes/no): " -r
    if [[ ! $REPLY =~ ^[Yy]es$ ]]; then
        echo "Load test cancelled"
        exit 1
    fi
fi

# Initialize CSV files
echo "timestamp,user_id,endpoint,status_code,response_time_ms" > "$RESULTS_DIR/${TEST_ID}-requests.csv"
echo "user_id,total_requests,errors,avg_response_time_ms" > "$RESULTS_DIR/${TEST_ID}-users.csv"

# Start test
print_info "Starting load test with $CONCURRENT_USERS concurrent users..."
START_TIME=$(date +%s)

# Launch concurrent user simulations
for i in $(seq 1 $CONCURRENT_USERS); do
    simulate_user "$i" &
done

# Monitor progress
print_info "Test running for ${DURATION}s..."

# Progress bar
for ((i=1; i<=DURATION; i++)); do
    sleep 1
    PERCENT=$((i * 100 / DURATION))
    BAR_FILLED=$((PERCENT / 2))
    BAR_EMPTY=$((50 - BAR_FILLED))
    printf "\rProgress: ["
    printf "%${BAR_FILLED}s" | tr ' ' '='
    printf "%${BAR_EMPTY}s" | tr ' ' '-'
    printf "] %d%%" $PERCENT
done
echo ""

# Wait for all background jobs
wait

END_TIME=$(date +%s)
ACTUAL_DURATION=$((END_TIME - START_TIME))

################################################################################
# Calculate Results
################################################################################

print_header "Load Test Results"

# Basic metrics
echo "Test ID: $TEST_ID"
echo "Duration: ${ACTUAL_DURATION}s"
echo ""

echo "📊 Request Statistics:"
echo "  Total Requests: $TOTAL_REQUESTS"
echo "  Successful: $SUCCESSFUL_REQUESTS"
echo "  Failed: $FAILED_REQUESTS"

# Calculate rates
if [ $TOTAL_REQUESTS -gt 0 ]; then
    ERROR_RATE=$(echo "scale=2; $FAILED_REQUESTS * 100 / $TOTAL_REQUESTS" | bc)
    SUCCESS_RATE=$(echo "scale=2; $SUCCESSFUL_REQUESTS * 100 / $TOTAL_REQUESTS" | bc)
    echo "  Success Rate: ${SUCCESS_RATE}%"
    echo "  Error Rate: ${ERROR_RATE}%"
fi

# Throughput
REQUESTS_PER_SEC=$(echo "scale=2; $TOTAL_REQUESTS / $ACTUAL_DURATION" | bc)
echo ""
echo "⚡ Throughput:"
echo "  Requests/second: $REQUESTS_PER_SEC"
echo "  Requests/minute: $(echo "$REQUESTS_PER_SEC * 60" | bc | cut -d'.' -f1)"

# Response times
if [ $SUCCESSFUL_REQUESTS -gt 0 ]; then
    AVG_RESPONSE_TIME=$((TOTAL_RESPONSE_TIME / SUCCESSFUL_REQUESTS))
    echo ""
    echo "⏱️  Response Times:"
    echo "  Average: ${AVG_RESPONSE_TIME}ms"

    # Calculate percentiles from CSV
    if command -v awk &> /dev/null; then
        P50=$(awk -F',' 'NR>1 && $4==200 {print $5}' "$RESULTS_DIR/${TEST_ID}-requests.csv" | sort -n | awk '{a[NR]=$1} END {print a[int(NR*0.5)]}')
        P95=$(awk -F',' 'NR>1 && $4==200 {print $5}' "$RESULTS_DIR/${TEST_ID}-requests.csv" | sort -n | awk '{a[NR]=$1} END {print a[int(NR*0.95)]}')
        P99=$(awk -F',' 'NR>1 && $4==200 {print $5}' "$RESULTS_DIR/${TEST_ID}-requests.csv" | sort -n | awk '{a[NR]=$1} END {print a[int(NR*0.99)]}')

        if [ -n "$P50" ]; then
            echo "  P50: ${P50}ms"
            echo "  P95: ${P95}ms"
            echo "  P99: ${P99}ms"
        fi
    fi
fi

# Per-user statistics
echo ""
echo "👥 Per-User Statistics:"
if [ -f "$RESULTS_DIR/${TEST_ID}-users.csv" ]; then
    TOTAL_USER_REQUESTS=$(awk -F',' 'NR>1 {sum+=$2} END {print sum}' "$RESULTS_DIR/${TEST_ID}-users.csv")
    AVG_REQUESTS_PER_USER=$(echo "scale=2; $TOTAL_USER_REQUESTS / $CONCURRENT_USERS" | bc)
    echo "  Avg requests/user: $AVG_REQUESTS_PER_USER"
fi

################################################################################
# Performance Assessment
################################################################################

echo ""
print_header "Performance Assessment"

# Check against targets
TARGETS_MET=0
TARGETS_FAILED=0

# Target: Error rate < 1%
if (( $(echo "$ERROR_RATE < 1" | bc -l) )); then
    print_success "Error rate ${ERROR_RATE}% < 1% target"
    TARGETS_MET=$((TARGETS_MET + 1))
else
    print_error "Error rate ${ERROR_RATE}% exceeds 1% target"
    TARGETS_FAILED=$((TARGETS_FAILED + 1))
fi

# Target: P95 response time < 200ms
if [ -n "$P95" ] && [ "$P95" -lt 200 ]; then
    print_success "P95 response time ${P95}ms < 200ms target"
    TARGETS_MET=$((TARGETS_MET + 1))
elif [ -n "$P95" ]; then
    print_error "P95 response time ${P95}ms exceeds 200ms target"
    TARGETS_FAILED=$((TARGETS_FAILED + 1))
fi

# Target: Throughput > 10 req/s
if (( $(echo "$REQUESTS_PER_SEC > 10" | bc -l) )); then
    print_success "Throughput ${REQUESTS_PER_SEC} req/s > 10 req/s target"
    TARGETS_MET=$((TARGETS_MET + 1))
else
    print_error "Throughput ${REQUESTS_PER_SEC} req/s below 10 req/s target"
    TARGETS_FAILED=$((TARGETS_FAILED + 1))
fi

echo ""
echo "Targets Met: $TARGETS_MET"
echo "Targets Failed: $TARGETS_FAILED"

################################################################################
# Generate HTML Report
################################################################################

REPORT_FILE="$RESULTS_DIR/${TEST_ID}-report.html"

cat > "$REPORT_FILE" <<EOF
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Load Test Report - $TEST_ID</title>
    <script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.0/dist/chart.umd.min.js"></script>
    <style>
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            margin: 0;
            padding: 20px;
            background: #f5f5f5;
        }
        .container {
            max-width: 1400px;
            margin: 0 auto;
            background: white;
            padding: 30px;
            border-radius: 8px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }
        h1 {
            color: #333;
            border-bottom: 3px solid #007bff;
            padding-bottom: 10px;
        }
        .stats {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin: 30px 0;
        }
        .stat-card {
            padding: 20px;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            border-radius: 8px;
            text-align: center;
        }
        .stat-value {
            font-size: 2.5em;
            font-weight: bold;
            margin: 10px 0;
        }
        .stat-label {
            opacity: 0.9;
            font-size: 0.9em;
        }
        .chart-container {
            width: 100%;
            height: 400px;
            margin: 30px 0;
        }
        .metric {
            margin: 20px 0;
            padding: 15px;
            background: #f8f9fa;
            border-left: 4px solid #007bff;
        }
        table {
            width: 100%;
            border-collapse: collapse;
            margin: 20px 0;
        }
        th, td {
            padding: 12px;
            text-align: left;
            border-bottom: 1px solid #ddd;
        }
        th {
            background: #007bff;
            color: white;
        }
        tr:hover {
            background: #f5f5f5;
        }
        .pass { color: #28a745; font-weight: bold; }
        .fail { color: #dc3545; font-weight: bold; }
    </style>
</head>
<body>
    <div class="container">
        <h1>Load Test Report</h1>
        <p><strong>Test ID:</strong> $TEST_ID</p>
        <p><strong>Environment:</strong> $ENVIRONMENT</p>
        <p><strong>Target:</strong> $BASE_URL</p>
        <p><strong>Date:</strong> $(date)</p>

        <div class="stats">
            <div class="stat-card">
                <div class="stat-label">Total Requests</div>
                <div class="stat-value">$TOTAL_REQUESTS</div>
            </div>
            <div class="stat-card" style="background: linear-gradient(135deg, #f093fb 0%, #f5576c 100%);">
                <div class="stat-label">Success Rate</div>
                <div class="stat-value">${SUCCESS_RATE}%</div>
            </div>
            <div class="stat-card" style="background: linear-gradient(135deg, #4facfe 0%, #00f2fe 100%);">
                <div class="stat-label">Throughput</div>
                <div class="stat-value">$REQUESTS_PER_SEC</div>
                <div class="stat-label">req/s</div>
            </div>
            <div class="stat-card" style="background: linear-gradient(135deg, #43e97b 0%, #38f9d7 100%);">
                <div class="stat-label">Avg Response</div>
                <div class="stat-value">${AVG_RESPONSE_TIME}ms</div>
            </div>
            <div class="stat-card" style="background: linear-gradient(135deg, #fa709a 0%, #fee140 100%);">
                <div class="stat-label">P95 Response</div>
                <div class="stat-value">${P95}ms</div>
            </div>
            <div class="stat-card" style="background: linear-gradient(135deg, #30cfd0 0%, #330867 100%);">
                <div class="stat-label">Concurrent Users</div>
                <div class="stat-value">$CONCURRENT_USERS</div>
            </div>
        </div>

        <div class="metric">
            <h2>Performance Targets</h2>
            <table>
                <thead>
                    <tr>
                        <th>Metric</th>
                        <th>Target</th>
                        <th>Actual</th>
                        <th>Status</th>
                    </tr>
                </thead>
                <tbody>
                    <tr>
                        <td>Error Rate</td>
                        <td>&lt; 1%</td>
                        <td>${ERROR_RATE}%</td>
                        <td class="$([ $(echo "$ERROR_RATE < 1" | bc -l) -eq 1 ] && echo 'pass' || echo 'fail')">
                            $([ $(echo "$ERROR_RATE < 1" | bc -l) -eq 1 ] && echo '✅ PASS' || echo '❌ FAIL')
                        </td>
                    </tr>
                    <tr>
                        <td>P95 Response Time</td>
                        <td>&lt; 200ms</td>
                        <td>${P95}ms</td>
                        <td class="$([ "$P95" -lt 200 ] && echo 'pass' || echo 'fail')">
                            $([ "$P95" -lt 200 ] && echo '✅ PASS' || echo '❌ FAIL')
                        </td>
                    </tr>
                    <tr>
                        <td>Throughput</td>
                        <td>&gt; 10 req/s</td>
                        <td>$REQUESTS_PER_SEC req/s</td>
                        <td class="$([ $(echo "$REQUESTS_PER_SEC > 10" | bc -l) -eq 1 ] && echo 'pass' || echo 'fail')">
                            $([ $(echo "$REQUESTS_PER_SEC > 10" | bc -l) -eq 1 ] && echo '✅ PASS' || echo '❌ FAIL')
                        </td>
                    </tr>
                </tbody>
            </table>
        </div>

        <div class="metric">
            <h2>Response Time Distribution</h2>
            <div class="chart-container">
                <canvas id="responseTimeChart"></canvas>
            </div>
        </div>

        <div class="metric">
            <h2>Request Timeline</h2>
            <div class="chart-container">
                <canvas id="timelineChart"></canvas>
            </div>
        </div>

        <div class="metric">
            <h2>Test Configuration</h2>
            <ul>
                <li><strong>Concurrent Users:</strong> $CONCURRENT_USERS</li>
                <li><strong>Duration:</strong> ${DURATION}s</li>
                <li><strong>Endpoints Tested:</strong> ${#ENDPOINTS[@]}</li>
                <li><strong>Total Requests:</strong> $TOTAL_REQUESTS</li>
                <li><strong>Avg Requests/User:</strong> $AVG_REQUESTS_PER_USER</li>
            </ul>
        </div>
    </div>

    <script>
        // Response time histogram
        new Chart(document.getElementById('responseTimeChart'), {
            type: 'bar',
            data: {
                labels: ['0-50ms', '50-100ms', '100-200ms', '200-500ms', '500ms+'],
                datasets: [{
                    label: 'Request Count',
                    data: [0, 0, 0, 0, 0], // Placeholder
                    backgroundColor: 'rgba(54, 162, 235, 0.5)',
                    borderColor: 'rgba(54, 162, 235, 1)',
                    borderWidth: 1
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

        // Timeline chart
        new Chart(document.getElementById('timelineChart'), {
            type: 'line',
            data: {
                labels: [], // Time buckets
                datasets: [{
                    label: 'Requests/sec',
                    data: [],
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
    </script>
</body>
</html>
EOF

echo ""
print_success "HTML report generated: $REPORT_FILE"
print_success "Request data: $RESULTS_DIR/${TEST_ID}-requests.csv"
print_success "User data: $RESULTS_DIR/${TEST_ID}-users.csv"

# Send results to Slack
if [ -n "$SLACK_WEBHOOK_URL" ]; then
    print_info "Sending results to Slack"

    STATUS_COLOR="good"
    if [ "$TARGETS_FAILED" -gt 0 ]; then
        STATUS_COLOR="danger"
    fi

    curl -X POST "$SLACK_WEBHOOK_URL" \
        -H 'Content-Type: application/json' \
        -d "{
            \"text\": \"📊 Load Test Complete: $ENVIRONMENT\",
            \"attachments\": [{
                \"color\": \"$STATUS_COLOR\",
                \"fields\": [
                    {\"title\": \"Concurrent Users\", \"value\": \"$CONCURRENT_USERS\", \"short\": true},
                    {\"title\": \"Total Requests\", \"value\": \"$TOTAL_REQUESTS\", \"short\": true},
                    {\"title\": \"Success Rate\", \"value\": \"${SUCCESS_RATE}%\", \"short\": true},
                    {\"title\": \"Avg Response\", \"value\": \"${AVG_RESPONSE_TIME}ms\", \"short\": true},
                    {\"title\": \"P95 Response\", \"value\": \"${P95}ms\", \"short\": true},
                    {\"title\": \"Throughput\", \"value\": \"$REQUESTS_PER_SEC req/s\", \"short\": true},
                    {\"title\": \"Targets Met\", \"value\": \"$TARGETS_MET/$((TARGETS_MET + TARGETS_FAILED))\", \"short\": true}
                ]
            }]
        }" \
        --silent > /dev/null

    print_success "Results sent to Slack"
fi

# Exit
echo ""
if [ "$TARGETS_FAILED" -gt 0 ]; then
    print_error "Load test completed with $TARGETS_FAILED failed targets"
    exit 1
else
    print_success "Load test completed - all targets met!"
    exit 0
fi
