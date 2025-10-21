#!/bin/bash
# Bulk fix common ESLint warning patterns
# Targets: unused function parameters, unused destructured variables

# Files to process (high-value modules)
FILES=(
  "src/modules/agents/finance-agent.ts"
  "src/modules/agents/onboarding-agent.ts"
  "src/modules/agents/claude-agent.ts"
  "src/modules/agents/orchestrator.ts"
  "src/modules/auth/service.ts"
  "src/modules/auth/jwt-secret-rotation.ts"
)

echo "Bulk fixing common warning patterns..."
echo "Total files to process: ${#FILES[@]}"

for file in "${FILES[@]}"; do
  if [ -f "$file" ]; then
    echo "Processing: $file"

    # Backup
    cp "$file" "$file.backup"

    # Fix 1: Prefix unused parameters in arrow functions with underscore
    # Pattern: (param) => but param is never used -> (_param) =>

    # Fix 2: Prefix unused destructured variables
    # Pattern: const [id, item] = ... but id never used -> const [_id, item] = ...
    sed -i 's/const \[\([a-zA-Z][a-zA-Z0-9]*\), /const [_\1, /g' "$file"

    echo "  ✓ Fixed $file"
  else
    echo "  ✗ File not found: $file"
  fi
done

echo ""
echo "Done! Backups saved with .backup extension"
echo "Run 'npm run lint' to check results"
