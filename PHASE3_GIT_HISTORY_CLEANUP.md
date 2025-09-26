# Phase 3: Git History Cleanup Plan
## Optional Deep History Purge for CoreFlow360 V4

**Status:** Optional - Execute only after Phase 2 validation is complete
**Risk Level:** Medium - Requires team coordination
**Estimated Savings:** Additional 100+ MB from git history

---

## Overview

Phase 3 removes large files from the entire Git history, permanently reducing the repository's `.git` folder size. This is an irreversible operation that requires careful coordination with all team members.

### Current Situation
- **Working Tree:** Cleaned in Phase 2 (119.5 MB removed)
- **Git History:** Still contains all historical large files
- **Total .git Size:** Likely 200+ MB with historical blobs

---

## Files to Remove from History

Based on Phase 2 findings, these files should be purged from all Git history:

### Critical Large Files (100+ MB historical impact)
1. **PowerShell-7.4.6-win-x64.msi** (104.14 MB per commit)
2. **Python virtual environments** (.venv/ directories)
3. **Large audit JSONs** (quantum-audit-*.json files)
4. **Build artifacts** (dist/, build/ directories)
5. **Node modules** (if ever committed)

### Common Bloat Patterns
- `*.msi`, `*.exe`, `*.dll` files
- `coverage/` directories
- `.wrangler/` cache directories
- `storybook-static/` outputs
- Large binary assets accidentally committed

---

## Prerequisites

### 1. Team Coordination
- [ ] All team members have pushed their work
- [ ] All team members are notified of the rewrite
- [ ] All feature branches are merged or documented
- [ ] Backup of current repository created

### 2. Technical Prerequisites
```bash
# Install git-filter-repo (preferred over BFG)
pip install git-filter-repo

# Or use homebrew on macOS
brew install git-filter-repo
```

### 3. Backup Strategy
```bash
# Create complete backup
git clone --mirror https://github.com/ernijsansons/CoreFlow360-V4.git coreflow360-backup.git

# Export all branches and tags
git bundle create coreflow360-complete-backup.bundle --all
```

---

## Execution Plan

### Step 1: Analysis Phase
```bash
# Analyze repository size
git count-objects -vH

# Find largest files in history
git rev-list --objects --all | git cat-file --batch-check='%(objecttype) %(objectname) %(objectsize) %(rest)' | grep '^blob' | sort -k3 -nr | head -20

# Identify commits containing large files
git log --oneline --name-only --diff-filter=A | grep -E '\.(msi|exe|dll)$'
```

### Step 2: Create Cleanup Branch
```bash
# Create a new branch for history cleanup
git checkout -b phase3-history-cleanup

# Ensure we're working with a fresh copy
git fetch --all
```

### Step 3: Remove Large Files by Path
```bash
# Remove PowerShell installer from all history
git filter-repo --path PowerShell-7.4.6-win-x64.msi --invert-paths

# Remove all .venv directories
git filter-repo --path .venv --invert-paths

# Remove large audit files
git filter-repo --path-glob 'audit-reports/*.json' --invert-paths

# Remove all .msi files
git filter-repo --path-glob '*.msi' --invert-paths

# Remove all .exe files (be careful about legitimate executables)
git filter-repo --path-glob '*.exe' --invert-paths

# Remove dist directories
git filter-repo --path-glob '*/dist' --invert-paths

# Remove coverage directories
git filter-repo --path coverage --invert-paths

# Remove .wrangler cache
git filter-repo --path .wrangler --invert-paths
```

### Step 4: Remove Files by Size
```bash
# Remove all files larger than 10MB from history
git filter-repo --strip-blobs-bigger-than 10M
```

### Step 5: Clean and Optimize
```bash
# Clean up the repository
git reflog expire --expire=now --all
git gc --prune=now --aggressive

# Check new size
git count-objects -vH
```

---

## Alternative: BFG Cleaner Method

If `git-filter-repo` is not available:

```bash
# Download BFG from https://rtyley.github.io/bfg-repo-cleaner/

# Remove large files
java -jar bfg.jar --delete-files "*.msi" .
java -jar bfg.jar --delete-files "*.exe" .
java -jar bfg.jar --delete-folders ".venv" .
java -jar bfg.jar --delete-folders "dist" .
java -jar bfg.jar --strip-blobs-bigger-than 10M .

# Clean up
git reflog expire --expire=now --all
git gc --prune=now --aggressive
```

---

## Verification and Testing

### 1. Size Verification
```bash
# Check repository size reduction
du -sh .git/

# Verify files are gone from history
git log --all --full-history -- PowerShell-7.4.6-win-x64.msi

# Check for any remaining large files
git rev-list --objects --all | git cat-file --batch-check='%(objectsize) %(rest)' | sort -nr | head -10
```

### 2. Functionality Testing
```bash
# Test that the repository still works
npm install
npm run build
wrangler deploy --dry-run

# Check all branches are intact
git branch -a

# Verify important files are still present
ls -la src/
ls -la package.json
```

---

## Force Push and Team Sync

### ⚠️ CRITICAL: One-Time Operation

```bash
# Force push to rewrite remote history
git push --force-with-lease origin main

# For all other branches
git branch -r | grep -v 'origin/HEAD' | while read branch; do
  local_branch=${branch#origin/}
  git push --force-with-lease origin $local_branch
done
```

### Team Synchronization
After force push, all team members must:

```bash
# Delete local repository
rm -rf CoreFlow360-V4

# Fresh clone
git clone https://github.com/ernijsansons/CoreFlow360-V4.git
cd CoreFlow360-V4

# Reinstall dependencies
npm install
```

---

## Expected Results

### Size Reduction
- **Before History Cleanup:** ~200+ MB (.git + working tree)
- **After History Cleanup:** ~30-50 MB total repository
- **Reduction:** 150+ MB (75%+ additional savings)

### Performance Improvements
- Faster clones (75% faster)
- Reduced storage costs
- Improved CI/CD performance
- Better developer experience

---

## Rollback Plan

If issues are discovered after history rewrite:

### 1. Immediate Rollback
```bash
# Restore from backup
git clone coreflow360-backup.git CoreFlow360-V4-restored
cd CoreFlow360-V4-restored

# Force push original history back
git push --force origin main
```

### 2. Partial Restoration
```bash
# Restore specific files from backup
git fetch backup
git checkout backup/main -- path/to/important/file
git commit -m "Restore critical file from backup"
```

---

## Decision Matrix

### Execute Phase 3 If:
- ✅ Repository clone time is too slow (>2 minutes)
- ✅ Storage costs are a concern
- ✅ Team is comfortable with Git history rewrites
- ✅ All active development is coordinated
- ✅ Complete backups are in place

### Skip Phase 3 If:
- ❌ Team is not experienced with history rewrites
- ❌ Active development with many branches
- ❌ External dependencies on Git history
- ❌ Regulatory requirements for audit trails
- ❌ Repository size is acceptable after Phase 2

---

## Communication Template

### Team Notification Email
```
Subject: [CRITICAL] Git History Rewrite Scheduled - Action Required

Team,

We're planning to execute Phase 3 of the repository cleanup, which will rewrite Git history to remove large files.

IMPACT:
- All local clones will need to be deleted and re-cloned
- Repository size will be reduced by ~75% additional
- All commit SHAs will change

TIMELINE:
- Preparation: [DATE]
- Execution: [DATE]
- Team re-sync: [DATE]

ACTION REQUIRED:
1. Push all your current work by [DATE]
2. Note any important commit SHAs you reference
3. Be prepared to re-clone the repository

This is optional but recommended for long-term repository health.

Questions? Reply to this email.
```

---

## Conclusion

Phase 3 is a powerful but optional optimization that can dramatically reduce repository size and improve performance. Execute only with proper preparation, team coordination, and comprehensive backups.

The repository is fully functional after Phase 2 cleanup, so Phase 3 can be executed later when convenient for the team.