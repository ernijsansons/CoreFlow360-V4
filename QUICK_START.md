# CoreFlow360 V4 - Quick Start Commands

## 🚀 New Terminal Session - Copy & Paste These

### 1️⃣ Start Development Server
```powershell
cd "C:\Users\ernij\OneDrive\Documents\CoreFlow360 V4\frontend"
npm run dev
```
Server runs at: http://localhost:5173

---

### 2️⃣ Run Accessibility Tests (New Terminal)
```powershell
cd "C:\Users\ernij\OneDrive\Documents\CoreFlow360 V4\frontend"
npx playwright test --grep="accessibility" --reporter=list
```

---

### 3️⃣ Setup Cloudflare Deployment (First Time Only)
```powershell
cd "C:\Users\ernij\OneDrive\Documents\CoreFlow360 V4"
.\setup-cloudflare-deployment.ps1
```

**Or manually:**
1. Get API Token: https://dash.cloudflare.com/profile/api-tokens
2. Add to GitHub: https://github.com/ernijsansons/CoreFlow360-V4/settings/secrets/actions
   - Name: `CLOUDFLARE_API_TOKEN`
   - Value: [Your token]

---

### 4️⃣ Check Current Status
```powershell
cd "C:\Users\ernij\OneDrive\Documents\CoreFlow360 V4"

# Git status
git status
git log --oneline -5

# Test results
cd frontend
npx playwright test --grep="accessibility" --reporter=list | findstr "passed failed"
```

---

## 📋 What's Already Done

✅ **Error Boundary** - Semantic HTML, ARIA attributes (commit `f52f40f`)
✅ **Login Page** - Main landmark, H1 heading (commit `e21f712`)
✅ **Button Sizes** - 44x44px minimum (commit `5e0737f`)
✅ **GitHub Actions** - Auto deployment on push (commit `3faf003`)
✅ **Documentation** - Setup guides (commit `f729eac`)

---

## ❌ What Still Needs Fixing

Priority order:

1. **Color Contrast** - WCAG 2.1 AA compliance
2. **Mobile Accessibility** - Responsive design
3. **Keyboard Navigation** - Shift+Tab support
4. **ARIA Attributes** - Screen reader support

---

## 🎯 Next Steps

### Step 1: Add GitHub Secret (If not done)
```powershell
# Run helper script
.\setup-cloudflare-deployment.ps1
```

### Step 2: Verify Deployment Works
Check: https://github.com/ernijsansons/CoreFlow360-V4/actions

### Step 3: Test Production
```powershell
cd frontend
npx playwright test --grep="accessibility" --reporter=list
```
Tests run against: https://8eb14753.coreflow360-frontend.pages.dev

### Step 4: Fix Color Contrast
```powershell
cd frontend
npx playwright test --grep="Color Contrast" --headed
# Identify issues, fix in theme/components, commit & push
```

---

## 🔗 Important Links

- **GitHub Repo:** https://github.com/ernijsansons/CoreFlow360-V4
- **Actions:** https://github.com/ernijsansons/CoreFlow360-V4/actions
- **Secrets:** https://github.com/ernijsansons/CoreFlow360-V4/settings/secrets/actions
- **Production:** https://8eb14753.coreflow360-frontend.pages.dev
- **CF Tokens:** https://dash.cloudflare.com/profile/api-tokens

---

## 🛠️ Useful Commands

```powershell
# Development
npm run dev              # Start dev server
npm run build           # Production build
npm run preview         # Test production build locally

# Testing
npx playwright test --ui                    # Interactive test UI
npx playwright test --headed               # See browser
npx playwright test --grep="Color"        # Specific test
npx playwright show-report                # View HTML report

# Git
git status
git add .
git commit -m "fix(a11y): [description]"
git push origin master

# Kill processes
taskkill /F /IM node.exe   # Kill all Node processes
```

---

## 📖 Full Documentation

- **Complete Guide:** `CONTINUE_ACCESSIBILITY_WORK.md`
- **Deployment Setup:** `DEPLOYMENT_SETUP_COMPLETE.md`
- **Project README:** `CLAUDE.md`

---

**Status:** Ready for deployment and continued accessibility fixes
**Last Updated:** 2025-10-29

🤖 Quick reference for fast terminal startup
