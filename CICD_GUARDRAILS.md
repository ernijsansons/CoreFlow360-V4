# CI/CD Guardrails for Repository Size Control
## Preventing Repository Bloat Through Automation

**Purpose:** Implement automated checks in CI/CD pipelines to prevent the reintroduction of large files, build artifacts, and other bloat into the repository.

---

## GitHub Actions Workflow

### 1. Pre-Commit Size Check

Create `.github/workflows/size-check.yml`:

```yaml
name: Repository Size Guard

on:
  pull_request:
    types: [opened, synchronize]
  push:
    branches: [main, master, develop]

jobs:
  size-check:
    name: Check File Sizes
    runs-on: ubuntu-latest

    steps:
      - name: Checkout code
        uses: actions/checkout@v4
        with:
          fetch-depth: 0

      - name: Check for large files
        run: |
          # Set size limit (5MB)
          SIZE_LIMIT=5242880

          # Find files larger than limit
          LARGE_FILES=$(find . -type f -size +5M ! -path "./.git/*" ! -path "./node_modules/*" 2>/dev/null)

          if [ ! -z "$LARGE_FILES" ]; then
            echo "❌ ERROR: Large files detected (>5MB):"
            echo "$LARGE_FILES" | while read file; do
              size=$(stat -c%s "$file" 2>/dev/null || stat -f%z "$file" 2>/dev/null)
              size_mb=$((size / 1048576))
              echo "  - $file (${size_mb}MB)"
            done
            exit 1
          fi

          echo "✅ No large files detected"

      - name: Check for prohibited file types
        run: |
          # Define prohibited patterns
          PROHIBITED_PATTERNS="*.msi *.exe *.dll *.pdb *.pyc __pycache__ .venv venv .env.local"

          FOUND_PROHIBITED=false
          for pattern in $PROHIBITED_PATTERNS; do
            FILES=$(find . -name "$pattern" ! -path "./.git/*" ! -path "./node_modules/*" 2>/dev/null)
            if [ ! -z "$FILES" ]; then
              echo "❌ Prohibited files found matching pattern: $pattern"
              echo "$FILES"
              FOUND_PROHIBITED=true
            fi
          done

          if [ "$FOUND_PROHIBITED" = true ]; then
            exit 1
          fi

          echo "✅ No prohibited file types found"

      - name: Check for build artifacts
        run: |
          # Check for common build output directories
          BUILD_DIRS="dist build .next .turbo coverage storybook-static .wrangler"

          FOUND_BUILD=false
          for dir in $BUILD_DIRS; do
            if [ -d "$dir" ]; then
              echo "❌ Build directory found: $dir"
              echo "   This should be in .gitignore"
              FOUND_BUILD=true
            fi
          done

          # Check for dist/ directories anywhere
          DIST_DIRS=$(find . -type d -name "dist" ! -path "./.git/*" ! -path "./node_modules/*" 2>/dev/null)
          if [ ! -z "$DIST_DIRS" ]; then
            echo "❌ Found dist directories:"
            echo "$DIST_DIRS"
            FOUND_BUILD=true
          fi

          if [ "$FOUND_BUILD" = true ]; then
            exit 1
          fi

          echo "✅ No build artifacts detected"

      - name: Calculate total size delta
        if: github.event_name == 'pull_request'
        run: |
          # Get the size of new files in the PR
          git diff --name-only --diff-filter=A origin/${{ github.base_ref }}..HEAD | while read file; do
            if [ -f "$file" ]; then
              size=$(stat -c%s "$file" 2>/dev/null || stat -f%z "$file" 2>/dev/null)
              echo "$file: $(($size / 1024))KB"
            fi
          done > new_files.txt

          # Calculate total addition
          TOTAL_KB=0
          while IFS=: read file size; do
            kb=$(echo $size | sed 's/KB//')
            TOTAL_KB=$((TOTAL_KB + kb))
          done < new_files.txt

          echo "📊 Total size added: ${TOTAL_KB}KB"

          # Warn if adding more than 10MB
          if [ $TOTAL_KB -gt 10240 ]; then
            echo "⚠️ WARNING: Adding more than 10MB of files"
            echo "Please consider:"
            echo "  - Moving large assets to CDN or R2"
            echo "  - Using Git LFS for binary files"
            echo "  - Ensuring build artifacts are gitignored"
          fi
```

### 2. Pre-Merge Validation

Create `.github/workflows/pre-merge-validation.yml`:

```yaml
name: Pre-Merge Repository Health

on:
  pull_request:
    branches: [main, master]
    types: [opened, synchronize]

jobs:
  validate-repo-health:
    name: Validate Repository Health
    runs-on: ubuntu-latest

    steps:
      - uses: actions/checkout@v4

      - name: Validate .gitignore
        run: |
          # Ensure critical patterns are in .gitignore
          REQUIRED_PATTERNS="node_modules .env dist build coverage .wrangler"

          for pattern in $REQUIRED_PATTERNS; do
            if ! grep -q "^$pattern" .gitignore; then
              echo "⚠️ WARNING: '$pattern' not found in .gitignore"
            fi
          done

      - name: Check for secrets
        run: |
          # Scan for potential secrets
          PATTERNS="password= api_key= secret= token= private_key="

          for pattern in $PATTERNS; do
            FOUND=$(grep -r "$pattern" . --exclude-dir=.git --exclude-dir=node_modules 2>/dev/null || true)
            if [ ! -z "$FOUND" ]; then
              echo "🚨 POTENTIAL SECRET DETECTED with pattern: $pattern"
              echo "Please review and use environment variables instead"
              exit 1
            fi
          done

          echo "✅ No obvious secrets detected"

      - name: Enforce file naming conventions
        run: |
          # Check for temporary file patterns
          TEMP_FILES=$(find . \( -name "*.tmp" -o -name "*.temp" -o -name "*.bak" -o -name "*.backup" \) ! -path "./.git/*" ! -path "./node_modules/*" 2>/dev/null)

          if [ ! -z "$TEMP_FILES" ]; then
            echo "⚠️ Temporary files detected:"
            echo "$TEMP_FILES"
            echo "These should not be committed"
          fi
```

### 3. Post-Merge Monitoring

Create `.github/workflows/post-merge-monitor.yml`:

```yaml
name: Post-Merge Size Monitor

on:
  push:
    branches: [main, master]

jobs:
  monitor-size:
    name: Monitor Repository Size
    runs-on: ubuntu-latest

    steps:
      - uses: actions/checkout@v4

      - name: Calculate repository metrics
        run: |
          # Calculate total repo size (excluding .git)
          TOTAL_SIZE=$(du -sb . --exclude=.git --exclude=node_modules | cut -f1)
          TOTAL_SIZE_MB=$((TOTAL_SIZE / 1048576))

          # Count files
          FILE_COUNT=$(find . -type f ! -path "./.git/*" ! -path "./node_modules/*" | wc -l)

          # Find largest files
          echo "📊 Repository Metrics:"
          echo "   Total size: ${TOTAL_SIZE_MB}MB"
          echo "   File count: ${FILE_COUNT}"
          echo ""
          echo "🔝 Top 10 largest files:"
          find . -type f ! -path "./.git/*" ! -path "./node_modules/*" -exec du -h {} + | sort -rh | head -10

          # Alert if repo is too large
          if [ $TOTAL_SIZE_MB -gt 100 ]; then
            echo "⚠️ WARNING: Repository exceeds 100MB (excluding .git and node_modules)"
            echo "Consider running cleanup: npm run repo:cleanup"
          fi

      - name: Create size report
        run: |
          cat > size-report.json <<EOF
          {
            "timestamp": "$(date -u +"%Y-%m-%dT%H:%M:%SZ")",
            "total_size_mb": $TOTAL_SIZE_MB,
            "file_count": $FILE_COUNT,
            "commit": "${{ github.sha }}",
            "branch": "${{ github.ref_name }}"
          }
          EOF

      - name: Upload metrics
        uses: actions/upload-artifact@v4
        with:
          name: size-metrics
          path: size-report.json
```

---

## Local Git Hooks

### Pre-Commit Hook

Create `.husky/pre-commit`:

```bash
#!/bin/sh
. "$(dirname "$0")/_/husky.sh"

# Check for large files
echo "Checking for large files..."
LARGE_FILES=$(find . -type f -size +5M ! -path "./.git/*" ! -path "./node_modules/*" 2>/dev/null)

if [ ! -z "$LARGE_FILES" ]; then
  echo "❌ Large files detected (>5MB):"
  echo "$LARGE_FILES"
  echo ""
  echo "Consider:"
  echo "  - Using Git LFS for large binary files"
  echo "  - Moving assets to CDN/R2"
  echo "  - Ensuring build outputs are gitignored"
  echo ""
  echo "To bypass (NOT RECOMMENDED): git commit --no-verify"
  exit 1
fi

# Check for common mistakes
echo "Checking for common issues..."

# Check for .env files
if git diff --cached --name-only | grep -E "\.env(\.|$)"; then
  echo "❌ Attempting to commit .env file!"
  exit 1
fi

# Check for node_modules
if git diff --cached --name-only | grep "node_modules/"; then
  echo "❌ Attempting to commit node_modules!"
  exit 1
fi

# Run linting
npm run lint-staged

echo "✅ Pre-commit checks passed"
```

---

## Package.json Scripts

Add these scripts to `package.json`:

```json
{
  "scripts": {
    "repo:check": "node scripts/repo-health-check.js",
    "repo:cleanup": "node scripts/safe_cleanup.ps1 -DryRun:$false",
    "repo:audit": "node scripts/repo_size_audit.ps1",
    "ci:size-check": "node scripts/ci-size-check.js",
    "pre-commit": "npm run repo:check && npm run lint-staged",
    "prepare": "husky install"
  }
}
```

---

## Repository Health Check Script

Create `scripts/repo-health-check.js`:

```javascript
#!/usr/bin/env node

const fs = require('fs');
const path = require('path');
const { execSync } = require('child_process');

const MAX_FILE_SIZE = 5 * 1024 * 1024; // 5MB
const MAX_REPO_SIZE = 100 * 1024 * 1024; // 100MB
const PROHIBITED_EXTENSIONS = ['.exe', '.msi', '.dll', '.pdb', '.pyc'];
const PROHIBITED_DIRS = ['dist', 'build', '.next', 'coverage', '.venv'];

function checkFileSize(filePath, stats) {
  if (stats.size > MAX_FILE_SIZE) {
    return `File too large: ${filePath} (${(stats.size / 1024 / 1024).toFixed(2)}MB)`;
  }
  return null;
}

function checkProhibitedFiles(filePath) {
  const ext = path.extname(filePath).toLowerCase();
  if (PROHIBITED_EXTENSIONS.includes(ext)) {
    return `Prohibited file type: ${filePath}`;
  }
  return null;
}

function walkDir(dir, callback) {
  fs.readdirSync(dir).forEach(file => {
    const filePath = path.join(dir, file);

    // Skip .git and node_modules
    if (filePath.includes('.git') || filePath.includes('node_modules')) {
      return;
    }

    const stats = fs.statSync(filePath);
    if (stats.isDirectory()) {
      walkDir(filePath, callback);
    } else {
      callback(filePath, stats);
    }
  });
}

function main() {
  console.log('🔍 Checking repository health...\n');

  const issues = [];
  let totalSize = 0;
  let fileCount = 0;

  // Check for prohibited directories
  PROHIBITED_DIRS.forEach(dir => {
    if (fs.existsSync(dir)) {
      issues.push(`Prohibited directory exists: ${dir}`);
    }
  });

  // Walk through files
  walkDir('.', (filePath, stats) => {
    fileCount++;
    totalSize += stats.size;

    // Check file size
    const sizeIssue = checkFileSize(filePath, stats);
    if (sizeIssue) issues.push(sizeIssue);

    // Check prohibited files
    const prohibitedIssue = checkProhibitedFiles(filePath);
    if (prohibitedIssue) issues.push(prohibitedIssue);
  });

  // Report results
  console.log(`📊 Repository Statistics:`);
  console.log(`   Total files: ${fileCount}`);
  console.log(`   Total size: ${(totalSize / 1024 / 1024).toFixed(2)}MB`);
  console.log('');

  if (issues.length > 0) {
    console.log('❌ Issues found:');
    issues.forEach(issue => console.log(`   - ${issue}`));
    process.exit(1);
  } else {
    console.log('✅ Repository health check passed!');
  }

  // Warning for large repo
  if (totalSize > MAX_REPO_SIZE) {
    console.log(`\n⚠️  WARNING: Repository size (${(totalSize / 1024 / 1024).toFixed(2)}MB) exceeds recommended limit (100MB)`);
  }
}

main();
```

---

## Enforcement Rules Summary

### Automatic Rejection
- Files larger than 5MB
- Binary executables (.exe, .msi, .dll)
- Python bytecode (.pyc, __pycache__)
- Virtual environments (.venv, venv)
- Build outputs (dist/, build/)
- Environment files (.env, .env.local)

### Warnings
- Repository size > 100MB
- PR adding > 10MB of files
- Temporary files (.tmp, .bak)
- Missing .gitignore entries

### Monitoring
- Track repository size over time
- Alert on significant size increases
- Regular audit reports
- Metrics dashboard

---

## Implementation Steps

1. **Phase 1: Local Hooks**
   - Install husky: `npm install --save-dev husky`
   - Setup hooks: `npx husky install`
   - Add pre-commit hook

2. **Phase 2: CI/CD Workflows**
   - Add GitHub Actions workflows
   - Configure branch protection rules
   - Require status checks to pass

3. **Phase 3: Monitoring**
   - Setup size tracking
   - Create dashboard
   - Configure alerts

4. **Phase 4: Enforcement**
   - Make checks required
   - Block merges on failure
   - Regular audits

---

## Maintenance

### Weekly
- Review size metrics
- Check for new large files
- Update prohibited patterns

### Monthly
- Run full repository audit
- Review and update limits
- Clean up if needed

### Quarterly
- Review Git history size
- Consider history rewrite if needed
- Update documentation