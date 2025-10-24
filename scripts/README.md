# Automation Scripts

This directory contains automation scripts for CoreFlow360 V4 deployment, monitoring, and maintenance.

---

## 📜 Available Scripts

### Deployment Scripts

#### `deploy-pages.sh` / `deploy-pages.ps1`
Deploys the frontend to Cloudflare Pages with pre-deployment checks.

**Usage (Bash)**:
```bash
./scripts/deploy-pages.sh
```

**Usage (PowerShell)**:
```powershell
.\scripts\deploy-pages.ps1
```

**What it does**:
1. Checks for circular dependencies
2. Validates TypeScript compilation
3. Checks git status
4. Builds production bundle
5. Deploys to Cloudflare Pages
6. Verifies deployment

**Requirements**:
- `CLOUDFLARE_API_TOKEN` environment variable set
- Clean git working tree (or confirmation to proceed)

---

### Health Check Scripts

#### `health-check.sh` / `health-check.ps1`
Runs comprehensive system health checks.

**Usage (Bash)**:
```bash
./scripts/health-check.sh
```

**Usage (PowerShell)**:
```powershell
.\scripts\health-check.ps1
```

**What it checks**:
- ✅ Production URL accessibility
- ✅ Circular dependencies
- ✅ TypeScript compilation
- ✅ Production build
- ⚠️ NPM security audit
- ⚠️ Git working tree status
- ⚠️ Remote sync status

**Exit Codes**:
- `0`: All checks passed
- `1`: One or more critical checks failed

**Recommended Schedule**:
- Run daily before starting work
- Run before every deployment
- Run after major changes

---

## 🚀 Quick Start

### First Time Setup

1. **Make scripts executable** (Linux/Mac):
   ```bash
   chmod +x scripts/*.sh
   ```

2. **Set environment variables**:
   ```bash
   # Linux/Mac
   export CLOUDFLARE_API_TOKEN="your_token_here"

   # Windows PowerShell
   $env:CLOUDFLARE_API_TOKEN="your_token_here"
   ```

3. **Test health check**:
   ```bash
   ./scripts/health-check.sh
   ```

---

## 📊 Usage Examples

### Daily Health Check
```bash
# Run health check before starting work
./scripts/health-check.sh

# If all checks pass, you're good to go!
```

### Deployment Workflow
```bash
# 1. Ensure all changes are committed
git status

# 2. Run health check
./scripts/health-check.sh

# 3. Deploy to Cloudflare Pages
./scripts/deploy-pages.sh

# 4. Verify production
curl -I https://8eb14753.coreflow360-frontend.pages.dev/
```

### Automated Monitoring
```bash
# Add to cron job for daily health checks
# (crontab -e)
0 9 * * * cd /path/to/CoreFlow360-V4 && ./scripts/health-check.sh >> logs/health-$(date +\%Y-\%m-\%d).log 2>&1
```

---

## 🛡️ Safeguards

All scripts include built-in safeguards:

### Deployment Script Safeguards
- ✅ Pre-deployment circular dependency check
- ✅ Pre-deployment TypeScript check
- ✅ Git status verification
- ✅ Build verification
- ✅ Post-deployment verification

### Health Check Safeguards
- ✅ Production accessibility check
- ✅ Build integrity check
- ✅ Security audit check
- ✅ Git repository health check

---

## 🔧 Customization

### Adding Custom Checks

Edit `health-check.sh` or `health-check.ps1`:

```bash
# Add a new check
run_check "My Custom Check" "my-command --arg" "critical"
```

### Modifying Deployment Process

Edit `deploy-pages.sh` or `deploy-pages.ps1`:

```bash
# Add pre-deployment step
echo "Running custom pre-deployment check..."
my-custom-command || exit 1
```

---

## 📝 Script Details

### Deployment Script Features
- **Pre-checks**: Prevents bad deployments
- **Build verification**: Ensures clean build
- **Size reporting**: Reports bundle size
- **Verification**: Confirms deployment success
- **Colored output**: Easy to read status

### Health Check Features
- **Comprehensive**: Checks all critical systems
- **Fast**: Completes in < 1 minute
- **Informative**: Clear pass/fail status
- **Exit codes**: CI/CD compatible
- **Severity levels**: Critical vs warnings

---

## 🐛 Troubleshooting

### Scripts Won't Execute (Permission Denied)

**Linux/Mac**:
```bash
chmod +x scripts/*.sh
```

### PowerShell Script Blocked

**Windows**:
```powershell
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
```

### CLOUDFLARE_API_TOKEN Not Set

**Set the token**:
```bash
# Linux/Mac
export CLOUDFLARE_API_TOKEN="your_token_here"

# Windows PowerShell
$env:CLOUDFLARE_API_TOKEN="your_token_here"

# Or add to .env file
echo "CLOUDFLARE_API_TOKEN=your_token_here" >> .env
```

### Health Check Fails

1. **Review the output** - Identifies which check failed
2. **Fix the issue** - Address the specific failure
3. **Re-run** - Verify the fix worked
4. **Commit** - Once all checks pass

---

## 📊 Monitoring Integration

### CI/CD Integration

Add to `.github/workflows/ci.yml`:

```yaml
- name: Run Health Check
  run: ./scripts/health-check.sh
```

### Slack Notifications

Wrap scripts with notification:

```bash
#!/bin/bash
./scripts/health-check.sh && \
  curl -X POST -H 'Content-type: application/json' \
  --data '{"text":"✅ Health check passed"}' \
  YOUR_SLACK_WEBHOOK_URL
```

---

## 🎯 Best Practices

1. **Run health check daily** - Catch issues early
2. **Always use deploy script** - Don't deploy manually
3. **Review script output** - Don't ignore warnings
4. **Keep scripts updated** - Update as system evolves
5. **Test changes** - Test script modifications

---

## 📞 Support

- **Documentation**: See MAINTENANCE_GUIDE.md
- **Monitoring**: See MONITORING_CHECKLIST.md
- **Deployment**: See DEPLOYMENT_VERIFICATION.md

---

**Scripts Created**: October 24, 2025
**Last Updated**: October 24, 2025
**Status**: ✅ Production Ready
