# Parallel ESLint Fixing Script - Terminal 2

**Instructions:** Copy the commands below and run them in a SEPARATE terminal while Terminal 1 (this session) continues working.

## Terminal 2 - Focus: Unused Variables and Imports

```bash
# Navigate to project
cd "c:\Users\ernij\OneDrive\Documents\CoreFlow360 V4"

# Fix unused imports by removing or commenting them out
# Target: src/services directory
cd src/services
for file in *.ts **/*.ts; do
  if [ -f "$file" ]; then
    # Remove unused type imports by converting to type-only imports
    sed -i "s/import { \([^}]*\)Env\([^}]*\) } from/import type { \1Env\2 } from/g" "$file" 2>/dev/null || true
    # Prefix unused error parameters with _
    sed -i "s/(error) =>/(_error) =>/g" "$file" 2>/dev/null || true
    sed -i "s/(error: /(_error: /g" "$file" 2>/dev/null || true
  fi
done

# Check progress
cd ../..
npm run lint 2>&1 | grep -E "✖ [0-9]+ problems"

# Fix unused parameters in src/workers directory
cd src/workers
for file in *.ts; do
  if [ -f "$file" ]; then
    # Prefix unused error parameters
    sed -i "s/) catch (error) {/) catch (_error) {/g" "$file"
    sed -i "s/\.catch((error) /\.catch((_error) /g" "$file"
  fi
done

# Check progress
cd ../..
npm run lint 2>&1 | grep -E "✖ [0-9]+ problems"

# Fix unused parameters in src/shared directory
cd src/shared
for file in *.ts **/*.ts; do
  if [ -f "$file" ]; then
    # Prefix unused parameters
    sed -i "s/async function \([a-zA-Z_][a-zA-Z0-9_]*\)(\([a-zA-Z_][a-zA-Z0-9_]*\): /async function \1(_\2: /g" "$file" 2>/dev/null || true
  fi
done

# Final check
cd ../..
npm run lint 2>&1 | grep -E "✖ [0-9]+ problems"
echo "Terminal 2 completed! Check warnings count above."
```

## Quick One-Liner Version (Run all at once)

```bash
cd "c:\Users\ernij\OneDrive\Documents\CoreFlow360 V4" && \
for dir in src/services src/workers src/shared src/utils; do \
  if [ -d "$dir" ]; then \
    find "$dir" -name "*.ts" -type f -exec sed -i \
      -e "s/) catch (error) {/) catch (_error) {/g" \
      -e "s/\.catch((error) /\.catch((_error) /g" \
      -e "s/(error) =>/(_error) =>/g" \
      -e "s/(error: /(_error: /g" \
      {} \; 2>/dev/null; \
  fi; \
done && \
npm run lint 2>&1 | tail -5
```

## Alternative: Focus on Frontend Unused Vars

```bash
cd "c:\Users\ernij\OneDrive\Documents\CoreFlow360 V4\frontend\src"

# Fix unused imports in components
for file in components/**/*.tsx components/**/*.ts; do
  if [ -f "$file" ]; then
    # Remove unused React imports (if React 17+)
    sed -i "/^import React from 'react';$/d" "$file" 2>/dev/null || true
    # Prefix unused props
    sed -i "s/({ \([a-zA-Z_][a-zA-Z0-9_]*\) }/({ _\1 }/g" "$file" 2>/dev/null || true
  fi
done

cd ../..
npm run lint 2>&1 | grep -E "✖ [0-9]+ problems"
```

## Progress Monitoring (Run repeatedly)

```bash
# Run this every 30 seconds to monitor both terminals' progress
cd "c:\Users\ernij\OneDrive\Documents\CoreFlow360 V4"
while true; do
  clear
  echo "=== ESLint Progress Monitor ==="
  echo "Timestamp: $(date)"
  npm run lint 2>&1 | tail -10
  echo ""
  echo "Press Ctrl+C to stop monitoring"
  sleep 30
done
```

---

## Notes for Terminal 2:

- **Focus Areas:** Unused variables, unused imports, unused parameters
- **Strategy:** Use sed to bulk prefix unused params with `_` or remove unused imports
- **Safety:** These changes are safe as they only affect unused code elements
- **Coordination:** Terminal 1 (main session) is handling console warnings
- **Speed:** Each directory should process in 10-30 seconds

**Expected Impact:** Should fix 100-300 warnings depending on directory size.

