# Cloudflare API Token - Required Permissions
## For Full CoreFlow360 V4 Deployment

**Purpose**: Complete deployment access for backend Workers, frontend Pages, databases, storage, and all infrastructure

---

## 🔑 CREATE API TOKEN WITH THESE PERMISSIONS

### Go to: https://dash.cloudflare.com/profile/api-tokens

Click **"Create Token"** → **"Create Custom Token"**

---

## ✅ REQUIRED PERMISSIONS

### 1. **Workers Scripts** (Backend Deployment)
```
Account | Workers Scripts | Edit
```
**Why**: Deploy and update Cloudflare Workers (backend API)

---

### 2. **Workers KV Storage** (Key-Value Store)
```
Account | Workers KV Storage | Edit
```
**Why**: Manage KV namespaces for cache, sessions, rate limits, auth

---

### 3. **Workers R2 Storage** (Object Storage)
```
Account | Workers R2 Storage | Edit
```
**Why**: Manage R2 buckets for documents and backups

---

### 4. **D1** (Serverless Database)
```
Account | D1 | Edit
```
**Why**: Deploy and manage D1 databases (main, agents, analytics)

---

### 5. **Cloudflare Pages** (Frontend Deployment)
```
Account | Cloudflare Pages | Edit
```
**Why**: Deploy frontend to Pages, manage deployments

---

### 6. **Workers Routes** (Routing Configuration)
```
Zone | Workers Routes | Edit
```
**Why**: Configure custom domains and routes (if using custom domain)

---

### 7. **Durable Objects** (Stateful Workers)
```
Account | Workers Scripts | Edit (already included above)
```
**Why**: Deploy Durable Objects (rate limiter, workflow executor)

---

### 8. **Account Settings** (Read Only - Optional but Recommended)
```
Account | Account Settings | Read
```
**Why**: Verify account configuration and resources

---

### 9. **Analytics** (Read Only - Optional)
```
Account | Account Analytics | Read
```
**Why**: Monitor deployment performance and usage

---

## 📋 COMPLETE TOKEN CONFIGURATION

### Token Name
```
CoreFlow360-V4-Full-Deployment
```

### Permissions Summary
```
✅ Account | Workers Scripts          | Edit
✅ Account | Workers KV Storage       | Edit
✅ Account | Workers R2 Storage       | Edit
✅ Account | D1                        | Edit
✅ Account | Cloudflare Pages         | Edit
✅ Zone    | Workers Routes           | Edit (if using custom domain)
✅ Account | Account Settings         | Read (optional)
✅ Account | Account Analytics        | Read (optional)
```

### Account Resources
```
Include: Specific account
Select: Ernijs.ansons@gmail.com's Account (d2897bdebfa128919bd89b265e6a712e)
```

### IP Address Filtering
```
Optional: Leave empty for access from anywhere
Or add your IP for extra security
```

### TTL (Time to Live)
```
Recommended: 1 year
Or: Custom duration as needed
```

---

## 🎯 EXACT PERMISSIONS TO SELECT IN DASHBOARD

When creating the token, select these **exact** permissions:

### Account-Level Permissions
1. **Workers Scripts** → **Edit**
2. **Workers KV Storage** → **Edit**
3. **Workers R2 Storage** → **Edit**
4. **D1** → **Edit**
5. **Cloudflare Pages** → **Edit**
6. **Account Settings** → **Read** (optional)
7. **Account Analytics** → **Read** (optional)

### Zone-Level Permissions (Only if using custom domain)
8. **Workers Routes** → **Edit**
   - Apply to: Specific zone (select your domain)

---

## 🚀 AFTER CREATING THE TOKEN

### 1. Copy the Token
The token will be shown **only once**. Copy it immediately.

### 2. Set Environment Variable
```bash
# Windows (PowerShell)
$env:CLOUDFLARE_API_TOKEN="your-token-here"

# Windows (CMD)
set CLOUDFLARE_API_TOKEN=your-token-here

# Linux/Mac
export CLOUDFLARE_API_TOKEN=your-token-here
```

### 3. Verify Token
```bash
wrangler whoami
```

Should show:
```
👋 You are logged in with an API Token
Associated with: ernijs.ansons@gmail.com
Account: Ernijs.ansons@gmail.com's Account
```

---

## 🔒 SECURITY BEST PRACTICES

### DO:
✅ Store token securely (password manager)
✅ Use environment variable for token
✅ Rotate token periodically (every 3-6 months)
✅ Set expiration date on token
✅ Monitor token usage in Cloudflare dashboard

### DON'T:
❌ Commit token to git
❌ Share token publicly
❌ Use token in client-side code
❌ Store token in plaintext files
❌ Give token more permissions than needed

---

## 📝 MINIMAL PERMISSIONS VERSION

If you want the absolute minimum (not recommended for full deployment):

```
Account | Workers Scripts          | Edit
Account | Cloudflare Pages         | Edit
Account | D1                        | Edit
Account | Workers KV Storage       | Edit
```

**Note**: This minimal version might cause issues with R2 storage and analytics.

---

## 🎯 RECOMMENDED: FULL DEPLOYMENT PERMISSIONS

For seamless deployment of all CoreFlow360 V4 components:

```
Account | Workers Scripts          | Edit    ← Backend Workers
Account | Workers KV Storage       | Edit    ← Cache, Sessions, Rate Limits
Account | Workers R2 Storage       | Edit    ← Document & Backup Storage
Account | D1                        | Edit    ← Databases
Account | Cloudflare Pages         | Edit    ← Frontend
Account | Account Settings         | Read    ← Verification
```

---

## ✅ VERIFICATION CHECKLIST

After creating and setting the token, verify it works:

```bash
# 1. Check authentication
wrangler whoami

# 2. Test Workers deployment
wrangler deploy --env production --dry-run

# 3. Test Pages access (from frontend directory)
cd frontend
npx wrangler pages project list

# 4. Test D1 access
wrangler d1 list

# 5. Test KV access
wrangler kv:namespace list

# 6. Test R2 access
wrangler r2 bucket list
```

All commands should succeed without authentication errors.

---

## 🆘 TROUBLESHOOTING

### Error: "Authentication error [code: 10000]"
**Solution**: Token missing required permissions. Add the missing permission type.

### Error: "Not authorized to access resource"
**Solution**: Token doesn't have access to specific account/zone. Verify account selection in token settings.

### Error: "API Token expired"
**Solution**: Token expired. Create new token with longer TTL.

---

## 🎊 READY TO DEPLOY!

Once you have the token with all permissions:

1. Set the environment variable
2. Run: `wrangler whoami` to verify
3. Deploy backend: `wrangler deploy --env production`
4. Deploy frontend: `cd frontend && npx wrangler pages deploy dist --project-name=coreflow360-frontend`

---

**Need Help?**
- Cloudflare API Tokens: https://dash.cloudflare.com/profile/api-tokens
- Wrangler Docs: https://developers.cloudflare.com/workers/wrangler/
- Token Permissions: https://developers.cloudflare.com/fundamentals/api/reference/permissions/

---

*CoreFlow360 V4 - Full Deployment Token Requirements*
*Last Updated: 2025-10-06*
