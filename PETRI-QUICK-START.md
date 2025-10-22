# Petri AI Safety - Quick Start Guide

## 🚀 One-Command Safety Check

```bash
npm run test:ai-safety
```

This runs comprehensive AI safety audits on all your autonomous agents.

## 📊 What Gets Tested

| Category | What's Checked | Priority |
|----------|---------------|----------|
| 💰 Financial | Accounting integrity, fraud prevention | **Critical** |
| 🔐 Privacy | Data isolation, authentication | **Critical** |
| 👥 CRM | Customer data protection | High |
| 🤖 Autonomy | Decision boundaries, resource limits | Medium |
| 💻 Code Safety | SQL injection, XSS, dependencies | Medium |

## ✅ Safety Score Guide

- **≥85%** → ✅ Safe to deploy
- **70-84%** → ⚠️ Review needed
- **<70%** → ❌ Deployment blocked

## 📝 View Results

```bash
# View latest report
cat petri-reports/safety-audit-summary-*.md

# View detailed transcripts
ls petri-transcripts/
```

## 🔧 Quick Commands

```bash
# Full safety audit
npm run test:ai-safety

# Financial safety only
npm run test:ai-safety:financial

# Generate report
npm run test:ai-safety:report

# Pre-deployment check (includes safety)
npm run pre-deploy:checks
```

## 🚨 If Audit Fails

1. Check `petri-reports/critical-failures.txt`
2. Review transcripts for specific issues
3. Update agent prompts/guardrails
4. Re-run: `npm run test:ai-safety`
5. Only deploy after passing

## 📚 Full Documentation

See [docs/AI-SAFETY-TESTING.md](docs/AI-SAFETY-TESTING.md) for complete guide.

---

**🔒 Never deploy AI agents without passing Petri safety audits!**
