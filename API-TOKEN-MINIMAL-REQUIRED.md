# Cloudflare API Token - MINIMAL REQUIRED Permissions
## CoreFlow360 V4 - Stripped Down to Essentials

---

## 🎯 ABSOLUTELY REQUIRED (Cannot deploy without these)

### 1. **Workers Scripts** - Edit ✅ REQUIRED
```
Account | Workers Scripts | Edit
```
**Why**: Deploy backend Cloudflare Worker
**Used for**: Main API, all backend endpoints

---

### 2. **Cloudflare Pages** - Edit ✅ REQUIRED
```
Account | Cloudflare Pages | Edit
```
**Why**: Deploy frontend React application
**Used for**: Frontend hosting and deployments

---

### 3. **D1** - Edit ✅ REQUIRED
```
Account | D1 | Edit
```
**Why**: Access databases (already created)
**Used for**: Main database, agents database, analytics database

---

### 4. **Workers KV Storage** - Edit ✅ REQUIRED
```
Account | Workers KV Storage | Edit
```
**Why**: Access KV namespaces (already created)
**Used for**: Cache, sessions, rate limits, auth tokens

---

## 🟡 RECOMMENDED (For full functionality)

### 5. **Workers R2 Storage** - Edit 🟡 RECOMMENDED
```
Account | Workers R2 Storage | Edit
```
**Why**: File storage (documents, backups)
**Impact if missing**: File uploads won't work, backups won't work
**Can skip if**: Not using file uploads initially

---

## ❌ NOT NEEDED (Optional/Not Used)

### ❌ Account Analytics - NOT NEEDED
**Why not**: Can view analytics in dashboard without API token
**Skip this**: We don't need programmatic analytics access

### ❌ Workers Routes (Zones) - NOT NEEDED
**Why not**: Only needed if configuring custom domains via API
**Skip this**: Can configure domains manually in dashboard if needed

### ❌ User Provisioning - NOT NEEDED
**Why not**: Only for enterprise user management
**Skip this**: Not managing team members via API

### ❌ Zone Settings - NOT NEEDED
**Why not**: Only for DNS/domain configuration
**Skip this**: Not touching DNS via API

---

## 🎯 RECOMMENDED TOKEN CONFIGURATION

### Minimal Production Deployment Token

**Token Name**: `CoreFlow360-Deployment`

**Permissions** (5 total):
```
✅ Account | Workers Scripts          | Edit
✅ Account | Cloudflare Pages         | Edit
✅ Account | D1                        | Edit
✅ Account | Workers KV Storage       | Edit
✅ Account | Workers R2 Storage       | Edit
```

**Account Resources**:
```
Include: Specific account
Account: Ernijs.ansons@gmail.com's Account
```

**TTL**: 1 year

---

## 🚀 SUPER MINIMAL (Bare bones - might have issues)

If you want absolute minimum to test:

```
✅ Account | Workers Scripts          | Edit
✅ Account | Cloudflare Pages         | Edit
✅ Account | D1                        | Edit
✅ Account | Workers KV Storage       | Edit
```

**Warning**: Without R2 Storage, file uploads and backups won't work.

---

## ✅ WHAT YOU DON'T NEED

### Excluded Permissions (Safe to skip):

❌ **Account Analytics** → Can view in dashboard
❌ **Workers Routes** → Only for custom domain API config
❌ **Zone Settings** → Only for DNS changes
❌ **User Provisioning** → Only for team management
❌ **Access** → Only for Cloudflare Access product
❌ **Stream** → Only for video streaming
❌ **Images** → Only for image optimization service
❌ **Load Balancing** → Not using load balancers
❌ **Page Rules** → Not needed for Workers/Pages
❌ **DNS** → Not managing DNS via API
❌ **SSL/Certificates** → Automatic in Pages/Workers
❌ **Firewall** → Not managing via API
❌ **Cache Purge** → Not needed
❌ **Logs** → Can view in dashboard

---

## 🎯 FINAL RECOMMENDATION

### Create Token With These 5 Permissions:

1. ✅ **Workers Scripts** - Edit
2. ✅ **Cloudflare Pages** - Edit
3. ✅ **D1** - Edit
4. ✅ **Workers KV Storage** - Edit
5. ✅ **Workers R2 Storage** - Edit

**That's it! Nothing else needed.**

---

## 📋 QUICK SETUP CHECKLIST

### Step 1: Create Token
- Go to: https://dash.cloudflare.com/profile/api-tokens
- Click "Create Token"
- Click "Create Custom Token"

### Step 2: Add Permissions
Select **Account** level permissions:
- [x] Workers Scripts → Edit
- [x] Cloudflare Pages → Edit
- [x] D1 → Edit
- [x] Workers KV Storage → Edit
- [x] Workers R2 Storage → Edit

### Step 3: Set Account
- Account Resources: "Include → Specific account"
- Select: "Ernijs.ansons@gmail.com's Account"

### Step 4: Finalize
- TTL: 1 year
- Click "Continue to summary"
- Click "Create Token"
- **COPY TOKEN IMMEDIATELY** (shown only once)

---

## 🚀 USAGE

### Set Token (Windows PowerShell):
```powershell
$env:CLOUDFLARE_API_TOKEN="your-token-here"
```

### Verify:
```bash
wrangler whoami
```

### Deploy:
```bash
# Backend
wrangler deploy --env production

# Frontend
cd frontend
npx wrangler pages deploy dist --project-name=coreflow360-frontend
```

---

## ❓ FAQ

### Q: Do I need Analytics permission?
**A**: No. You can view analytics in the Cloudflare dashboard without API access.

### Q: Do I need Zone/DNS permissions?
**A**: No. Workers and Pages don't require zone-level permissions unless you're configuring custom domains via API.

### Q: Do I need User provisioning?
**A**: No. That's only for managing team members programmatically.

### Q: What if I skip R2 Storage permission?
**A**: File uploads and backups won't work. Everything else will work fine.

### Q: Can I add permissions later?
**A**: Yes! You can edit the token and add more permissions anytime.

---

## 🎊 SUMMARY

**Need**: 5 permissions (Workers, Pages, D1, KV, R2)
**Don't need**: Analytics, Zones, Users, DNS, etc.
**Total**: Simple, clean, focused token

---

*CoreFlow360 V4 - Minimal API Token Requirements*
*Only what you actually need, nothing extra*
