#!/bin/bash

###############################################################################
# CoreFlow360 V4 - Parallel Agent Test Execution Script
#
# Description: Launches 8 terminals running agent tests in parallel
# Reduces test execution time from ~32 seconds to ~7 seconds
#
# Usage: ./run-parallel-tests.sh
#
# Requirements:
#   - Bash 4+
#   - Node.js 20+
#   - Terminal emulator (gnome-terminal, xterm, konsole, or macOS Terminal)
#
# Author: CoreFlow360 Engineering Team
# Copyright 2025 CoreFlow360
###############################################################################

# Colors
CYAN='\033[0;36m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
MAGENTA='\033[0;35m'
RED='\033[0;31m'
GRAY='\033[0;90m'
WHITE='\033[1;37m'
NC='\033[0m' # No Color

# Display banner
echo ""
echo -e "${CYAN}╔═══════════════════════════════════════════════════════════╗${NC}"
echo -e "${CYAN}║                                                           ║${NC}"
echo -e "${CYAN}║   CoreFlow360 V4 - Parallel Agent Test Execution         ║${NC}"
echo -e "${CYAN}║                                                           ║${NC}"
echo -e "${CYAN}╚═══════════════════════════════════════════════════════════╝${NC}"
echo ""
echo -e "${GREEN}🚀 Starting Parallel Test Execution...${NC}"
echo -e "${YELLOW}Opening 8 terminals for agent test suites...${NC}"
echo ""

# Get current directory
CURRENT_DIR=$(pwd)

# Define test suites
declare -a tests=(
    "Claude Agent|npm test -- --run src/modules/agents/__tests__/claude-agent.test.ts|38|P0"
    "Finance Agent|npm test -- --run src/modules/agents/__tests__/finance-agent.test.ts|90|P0"
    "Support Ticket|npm test -- --run src/modules/agents/__tests__/support-ticket-agent.test.ts|43|P0"
    "Chat Support|npm test -- --run src/modules/agents/__tests__/chat-support-agent.test.ts|39|P1"
    "Qualification|npm test -- --run src/modules/agents/__tests__/qualification-agent.test.ts|37|P1"
    "Knowledge Base|npm test -- --run src/modules/agents/__tests__/knowledge-base-agent.test.ts|34|P2"
    "Onboarding|npm test -- --run src/modules/agents/__tests__/onboarding-agent.test.ts|18|P2"
    "Company Knowledge|npm test -- --run src/modules/agents/__tests__/company-knowledge-agent.test.ts|19|P2"
)

# Counter for launched terminals
launched_count=0
total_tests=0

# Function to detect terminal emulator
detect_terminal() {
    if command -v gnome-terminal &> /dev/null; then
        echo "gnome-terminal"
    elif command -v konsole &> /dev/null; then
        echo "konsole"
    elif command -v xterm &> /dev/null; then
        echo "xterm"
    elif [[ "$OSTYPE" == "darwin"* ]]; then
        echo "macos"
    else
        echo "unknown"
    fi
}

# Detect terminal type
TERMINAL_TYPE=$(detect_terminal)

# Launch each test suite
for test in "${tests[@]}"; do
    IFS='|' read -r name command test_count priority <<< "$test"
    total_tests=$((total_tests + test_count))

    echo -e "${GRAY}📋 Launching:${NC} ${BLUE}$name${NC} ${GRAY}[$priority]${NC} ${GRAY}($test_count tests)${NC}"

    # Create startup script for this test
    startup_script="
echo '═══════════════════════════════════════════════════'
echo ' $name Test Suite'
echo ' Tests: $test_count | Priority: $priority'
echo '═══════════════════════════════════════════════════'
echo ''
cd '$CURRENT_DIR' && $command
echo ''
echo 'Press Enter to close this window...'
read
"

    # Launch terminal based on detected type
    case $TERMINAL_TYPE in
        gnome-terminal)
            gnome-terminal --title="$name Tests" -- bash -c "$startup_script" 2>/dev/null &
            ;;
        konsole)
            konsole --new-tab --title "$name Tests" -e bash -c "$startup_script" &
            ;;
        xterm)
            xterm -title "$name Tests" -hold -e bash -c "$startup_script" &
            ;;
        macos)
            osascript -e "
                tell application \"Terminal\"
                    do script \"$startup_script\"
                    set custom title of front window to \"$name Tests\"
                end tell
            " &
            ;;
        unknown)
            echo -e "${RED}   ⚠️  No supported terminal emulator found for: $name${NC}"
            echo -e "${YELLOW}   💡 Install gnome-terminal, konsole, xterm, or run on macOS${NC}"
            continue
            ;;
    esac

    launched_count=$((launched_count + 1))
    sleep 0.5  # Stagger launches
done

echo ""
echo -e "${GREEN}✅ Successfully launched $launched_count/${#tests[@]} test terminals!${NC}"
echo ""
echo -e "${CYAN}╔═══════════════════════════════════════════════════════════╗${NC}"
echo -e "${CYAN}║  Expected Results:                                        ║${NC}"
echo -e "${WHITE}║    • Total Tests: $total_tests (318 with 1 skipped)               ║${NC}"
echo -e "${WHITE}║    • Completion Time: ~7-10 seconds                       ║${NC}"
echo -e "${WHITE}║    • Sequential Time: ~32 seconds                         ║${NC}"
echo -e "${GREEN}║    • Speed Improvement: 78% faster                        ║${NC}"
echo -e "${CYAN}╚═══════════════════════════════════════════════════════════╝${NC}"
echo ""
echo -e "${YELLOW}💡 Tips:${NC}"
echo -e "${GRAY}   • Watch each terminal for real-time progress${NC}"
echo -e "${GRAY}   • All tests should show ✓ (passing) status${NC}"
echo -e "${GRAY}   • Slowest suite (Claude Agent) determines total time${NC}"
echo ""
echo -e "${CYAN}📊 Monitor terminals for results...${NC}"
echo ""

# Optional: Display terminal type info
if [ "$TERMINAL_TYPE" != "unknown" ]; then
    echo -e "${GRAY}Using terminal emulator: $TERMINAL_TYPE${NC}"
    echo ""
fi

# Wait for user to review before exiting
echo -e "${GRAY}Press Enter to exit this launcher...${NC}"
read
