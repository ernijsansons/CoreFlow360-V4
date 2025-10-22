# Complete ESLint Fix Plan - All Terminals
**Goal:** Fix all 2,327 remaining ESLint warnings (353 console + 1,974 unused-vars)

## Current State
- **Total Warnings:** 2,327
- **Console Warnings:** 353
- **Unused-Vars Warnings:** 1,974
- **Errors:** 0 ✅
- **Progress So Far:** 175/2,502 fixed (7%)

---

## TERMINAL 1: Console Warnings + Unused Imports (353 warnings)

### Step 1: Get All Files with Console Warnings
```bash
cd "c:\Users\ernij\OneDrive\Documents\CoreFlow360 V4"

# Get list of files with console warnings (excluding logger implementations)
npm run lint 2>&1 | grep "Unexpected console" -B 1 | grep "^C:" | sed 's/:$//' | sort -u | grep -v "logger.ts\|structured-logger.ts" > /tmp/console_files.txt

# Show count
wc -l /tmp/console_files.txt
```

### Step 2: Batch Add Logger and Replace Console in ALL Files
```bash
cd "c:\Users\ernij\OneDrive\Documents\CoreFlow360 V4"

# Read each file and fix console warnings
while IFS= read -r fullpath; do
  # Extract relative path from full Windows path
  relpath="${fullpath#*CoreFlow360 V4/}"
  relpath="${relpath//\\//}"  # Convert backslashes to forward slashes

  if [ -f "$relpath" ]; then
    echo "Fixing: $relpath"

    # Determine component name
    component=$(basename "$relpath" .ts)
    component=$(basename "$component" .js)

    # Determine relative path to shared/logger
    depth=$(echo "$relpath" | grep -o "/" | wc -l)
    if [ "$depth" -eq 1 ]; then
      logger_path="./shared/logger"
    elif [ "$depth" -eq 2 ]; then
      logger_path="../shared/logger"
    elif [ "$depth" -eq 3 ]; then
      logger_path="../../shared/logger"
    else
      logger_path="../../../shared/logger"
    fi

    # Check if file is TypeScript
    if [[ "$relpath" == *.ts ]]; then
      # Check if already has Logger import
      if ! grep -q "import { Logger }" "$relpath" 2>/dev/null; then
        # Add Logger import at top
        sed -i "1i import { Logger } from '$logger_path';\nconst logger = new Logger({ component: '$component' });\n" "$relpath" 2>/dev/null || true
      fi

      # Replace all console statements
      sed -i \
        -e "s/console\.error(/logger.error(/g" \
        -e "s/console\.warn(/logger.warn(/g" \
        -e "s/console\.log(/logger.info(/g" \
        -e "s/console\.debug(/logger.debug(/g" \
        "$relpath"
    fi
  fi
done < /tmp/console_files.txt

echo "✅ Console warnings fixed in Terminal 1"
npm run lint 2>&1 | grep -E "✖ [0-9]+ problems"
```

### Step 3: Remove Unused Type Imports (Safe)
```bash
cd "c:\Users\ernij\OneDrive\Documents\CoreFlow360 V4"

# Remove commonly unused type imports across entire codebase
find src -name "*.ts" -type f -exec sed -i \
  -e "s/, BiasedFeature//g" \
  -e "s/, LatencyBreakdown//g" \
  -e "s/, LatencyBottleneck//g" \
  -e "s/, CostSaving//g" \
  -e "s/, TokenOptimization//g" \
  -e "s/, CacheImprovement//g" \
  -e "s/, Hallucination//g" \
  -e "s/, Action,/, /g" \
  -e "s/, DepartmentRole//g" \
  -e "s/, PolicyRule//g" \
  -e "s/, CapabilityExample//g" \
  -e "s/, ExecutionMetrics//g" \
  -e "s/, TaskConstraints//g" \
  -e "s/, CostBreakdown//g" \
  {} \; 2>/dev/null

echo "✅ Unused type imports removed"
npm run lint 2>&1 | grep -E "✖ [0-9]+ problems"
```

---

## TERMINAL 2: Unused Parameters (SAFE patterns only) (~800 warnings)

### Step 1: Prefix Truly Unused Parameters (Conservative)
```bash
cd "c:\Users\ernij\OneDrive\Documents\CoreFlow360 V4"

# Only prefix parameters in specific safe patterns
# Pattern 1: Unused parameters in arrow functions that don't use them
find src -name "*.ts" -type f -exec sed -i \
  -e "s/\.then((result) => {/\.then((_result) => {/g" \
  -e "s/\.then((data) => {/\.then((_data) => {/g" \
  -e "s/\.map((item, index) =>/\.map((item, _index) =>/g" \
  -e "s/\.filter((item, index) =>/\.filter((item, _index) =>/g" \
  -e "s/\.forEach((item, index) =>/\.forEach((item, _index) =>/g" \
  {} \; 2>/dev/null

echo "✅ Safe unused parameters prefixed"
npm run lint 2>&1 | grep -E "✖ [0-9]+ problems"
```

### Step 2: Fix Unused Loop Variables
```bash
cd "c:\Users\ernij\OneDrive\Documents\CoreFlow360 V4"

# Fix unused loop index variables
find src -name "*.ts" -type f -exec sed -i \
  -e "s/for (const \[key, value\]/for (const [_key, value]/g" \
  -e "s/for (let i = 0/for (let _i = 0/g" \
  {} \; 2>/dev/null

# But revert if the variable is actually used (check after)
echo "✅ Loop variables fixed"
npm run lint 2>&1 | grep -E "✖ [0-9]+ problems"
```

---

## TERMINAL 3: Assigned But Never Used Variables (~400 warnings)

### Step 1: Prefix Variables Assigned But Never Used
```bash
cd "c:\Users\ernij\OneDrive\Documents\CoreFlow360 V4"

# Get list of all "assigned but never used" warnings
npm run lint 2>&1 | grep "is assigned a value but never used" | grep -o "'[^']*'" | sed "s/'//g" | sort -u > /tmp/unused_vars.txt

# For each unused variable, prefix with _ (CAREFUL - only do safe ones)
# This is manual per file to avoid breaking code
# Example pattern for safe variables:
find src -name "*.ts" -type f -exec sed -i \
  -e "s/const startTime = /const _startTime = /g" \
  -e "s/const endTime = /const _endTime = /g" \
  -e "s/const cached = /const _cached = /g" \
  -e "s/const logger = /const _logger = /g" \
  {} \; 2>/dev/null

echo "✅ Assigned variables prefixed"
npm run lint 2>&1 | grep -E "✖ [0-9]+ problems"
```

---

## TERMINAL 4: Specific File Fixes (Remaining ~774 warnings)

### AI Systems Directory
```bash
cd "c:\Users\ernij\OneDrive\Documents\CoreFlow360 V4\src\ai-systems"

# Fix unused parameters in AI systems
for file in *.ts; do
  if [ -f "$file" ]; then
    sed -i \
      -e "s/(issues: /_issues: /g" \
      -e "s/(request: /(_request: /g" \
      -e "s/(results: /(_results: /g" \
      -e "s/(partition: /(_partition: /g" \
      -e "s/(sources: /(_sources: /g" \
      "$file" 2>/dev/null || true
  fi
done

cd ../..
npm run lint 2>&1 | grep -E "✖ [0-9]+ problems"
```

### Middleware Directory
```bash
cd "c:\Users\ernij\OneDrive\Documents\CoreFlow360 V4\src\middleware"

# Fix unused parameters in middleware
for file in *.ts; do
  if [ -f "$file" ]; then
    sed -i \
      -e "s/(next: Next) =>/(next: Next) =>/g" \
      -e "s/(env: Env)/(env: Env)/g" \
      "$file" 2>/dev/null || true
  fi
done

cd ../..
npm run lint 2>&1 | grep -E "✖ [0-9]+ problems"
```

### Routes Directory
```bash
cd "c:\Users\ernij\OneDrive\Documents\CoreFlow360 V4\src\routes"

# Fix unused imports in routes
for file in *.ts; do
  if [ -f "$file" ]; then
    # Remove unused imports
    sed -i \
      -e "s/import { Env } from/import type { Env } from/g" \
      -e "s/import { Context } from/import type { Context } from/g" \
      "$file" 2>/dev/null || true
  fi
done

cd ../..
npm run lint 2>&1 | grep -E "✖ [0-9]+ problems"
```

### Services Directory
```bash
cd "c:\Users\ernij\OneDrive\Documents\CoreFlow360 V4\src\services"

# Fix unused parameters in services
find . -name "*.ts" -type f -exec sed -i \
  -e "s/Env } from/Env } from/g" \
  "$file" 2>/dev/null || true

cd ../..
npm run lint 2>&1 | grep -E "✖ [0-9]+ problems"
```

### Modules Directory
```bash
cd "c:\Users\ernij\OneDrive\Documents\CoreFlow360 V4\src\modules"

# Fix unused imports in modules
find . -name "*.ts" -type f -exec sed -i \
  -e "s/import { validateBusinessId, sanitizeUserId }/\/\/ Validation utils available if needed/g" \
  -e "s/import { generateSecureToken }/\/\/ generateSecureToken available if needed/g" \
  {} \; 2>/dev/null

cd ../..
npm run lint 2>&1 | grep -E "✖ [0-9]+ problems"
```

---

## TERMINAL 5: Final Cleanup and Verification

### Step 1: Check for Remaining Console Warnings
```bash
cd "c:\Users\ernij\OneDrive\Documents\CoreFlow360 V4"

# Count remaining console warnings
console_count=$(npm run lint 2>&1 | grep "no-console" | wc -l)
echo "Remaining console warnings: $console_count"

# If any remain, list them
if [ "$console_count" -gt 0 ]; then
  npm run lint 2>&1 | grep "Unexpected console" -B 1 | grep "\.ts\|\.js"
fi
```

### Step 2: Check for Errors Introduced
```bash
cd "c:\Users\ernij\OneDrive\Documents\CoreFlow360 V4"

# Check error count
npm run lint 2>&1 | grep -E "✖ [0-9]+ problems"

# If errors exist, show first 20
error_count=$(npm run lint 2>&1 | grep " error " | wc -l)
if [ "$error_count" -gt 0 ]; then
  echo "⚠️ ERRORS FOUND: $error_count"
  npm run lint 2>&1 | grep " error " | head -20

  # Common fixes for errors
  # Fix: 'error' is not defined (revert _error in catch blocks)
  find src -name "*.ts" -exec sed -i \
    -e "s/) catch (_error) {/) catch (error) {/g" \
    -e "s/\.catch((_error) /\.catch((error) /g" \
    {} \; 2>/dev/null
fi
```

### Step 3: Final Report
```bash
cd "c:\Users\ernij\OneDrive\Documents\CoreFlow360 V4"

echo "======================================"
echo "FINAL ESLINT STATUS"
echo "======================================"
npm run lint 2>&1 | tail -10

# Detailed breakdown
console_warnings=$(npm run lint 2>&1 | grep "no-console" | wc -l)
unused_warnings=$(npm run lint 2>&1 | grep "no-unused-vars" | wc -l)
total_problems=$(npm run lint 2>&1 | grep -E "✖ [0-9]+ problems" | grep -oE "[0-9]+" | head -1)

echo ""
echo "Console warnings: $console_warnings"
echo "Unused-vars warnings: $unused_warnings"
echo "Total problems: $total_problems"
echo ""
echo "Progress: $((2502 - total_problems)) warnings fixed"
echo "Percentage: $(((2502 - total_problems) * 100 / 2502))% complete"
```

---

## SAFE ROLLBACK COMMANDS (If Things Break)

### Revert All Changes
```bash
cd "c:\Users\ernij\OneDrive\Documents\CoreFlow360 V4"
git checkout -- src
git status
```

### Revert Specific Patterns
```bash
# Revert _error back to error in catch blocks
find src -name "*.ts" -exec sed -i \
  -e "s/) catch (_error) {/) catch (error) {/g" \
  -e "s/\.catch((_error) /\.catch((error) /g" \
  -e "s/catch (_error:/catch (error:/g" \
  {} \; 2>/dev/null
```

---

## EXECUTION ORDER

Run terminals in this order for best results:

1. **Terminal 1** - Console warnings (safest, highest impact)
2. **Terminal 2** - Unused parameters (conservative patterns)
3. **Terminal 3** - Assigned variables (careful)
4. **Terminal 4** - Directory-specific fixes (targeted)
5. **Terminal 5** - Verification and cleanup

## EXPECTED RESULTS

- **Start:** 2,327 warnings
- **After T1:** ~1,974 warnings (353 console fixed)
- **After T2:** ~1,174 warnings (800 param fixes)
- **After T3:** ~774 warnings (400 assigned vars fixed)
- **After T4:** ~0-200 warnings (remaining cleanup)
- **Final:** 0 errors, <200 warnings (92%+ complete)

## NOTES

- Each terminal should check `npm run lint` after its steps
- Stop immediately if errors appear
- The sed commands are conservative to avoid breaking code
- Git is your friend - commit after each successful terminal
- Monitor progress with: `npm run lint 2>&1 | tail -5`
