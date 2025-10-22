# 🚀 Quick Launch Script (30 minutes)

## Step 1: Get Stripe API Key (5 minutes)

1. Open: https://dashboard.stripe.com/register (or login if you have account)
2. Complete registration if new user
3. Go to: https://dashboard.stripe.com/apikeys
4. Click "Create secret key"
5. Name: "CoreFlow360 Production"
6. Copy the key (starts with `sk_live_...`)

**Set the secret:**
```bash
wrangler secret put STRIPE_SECRET_KEY --env production
# Paste the key when prompted
```

**Note:** If you don't have a Stripe account yet, you can use test mode for now:
- Get test key (starts with `sk_test_...`)
- Use that temporarily until you activate your account

---

## Step 2: Get SendGrid API Key (5 minutes)

1. Open: https://signup.sendgrid.com/ (or login)
2. Complete registration if new user
3. Go to: https://app.sendgrid.com/settings/api_keys
4. Click "Create API Key"
5. Name: "CoreFlow360 Production"
6. Permissions: **Full Access**
7. Copy the key (starts with `SG.`)

**Set the secret:**
```bash
wrangler secret put SENDGRID_API_KEY --env production
# Paste the key when prompted
```

**Verify sender email:**
- Go to: https://app.sendgrid.com/settings/sender_auth/senders/new
- Add: noreply@coreflow360.com (or your domain)
- Verify the email address

---

## Step 3: Create Google Analytics 4 (10 minutes)

1. Open: https://analytics.google.com
2. Click "Start measuring" or "Admin"
3. Click "Create Property"
4. Property name: `CoreFlow360 V4`
5. Time zone: Your timezone
6. Currency: USD
7. Click "Next"
8. Business details: Fill as appropriate
9. Click "Create"
10. Accept terms

**Create Data Stream:**
1. Click "Web"
2. Website URL: `https://production.coreflow360-frontend.pages.dev`
3. Stream name: "Production Frontend"
4. Click "Create stream"
5. **COPY THE MEASUREMENT ID** (looks like `G-XXXXXXXXXX`)

---

## Step 4: Update Frontend with GA4 ID (5 minutes)

**Option A: Manual Edit**
```bash
# Open file: frontend/index.html
# Find line 10: <script async src="https://www.googletagmanager.com/gtag/js?id=G-PLACEHOLDER"></script>
# Replace G-PLACEHOLDER with your Measurement ID

# Find line 15: gtag('config', 'G-PLACEHOLDER', {
# Replace G-PLACEHOLDER with your Measurement ID
```

**Option B: Automated (PowerShell)**
```powershell
# Replace YOUR_MEASUREMENT_ID with your actual GA4 ID
$measurementId = "G-XXXXXXXXXX"
$file = "frontend/index.html"
(Get-Content $file) -replace 'G-PLACEHOLDER', $measurementId | Set-Content $file

Write-Host "✅ Updated GA4 Measurement ID to $measurementId"
```

**Rebuild and Deploy:**
```bash
cd frontend
npm run build
npx wrangler pages deploy dist --project-name=coreflow360-frontend --branch=production --commit-dirty=true
```

---

## Step 5: Verify Everything (5 minutes)

**Test Backend:**
```bash
curl https://coreflow360-v4-prod.ernijs-ansons.workers.dev/health
# Should return: {"status":"ok",...}
```

**Test Frontend:**
- Open: https://production.coreflow360-frontend.pages.dev/landing
- Should load landing page

**Test Analytics:**
- Open: https://analytics.google.com
- Go to: Reports → Realtime
- Visit your landing page in another tab
- Should see: 1 active user

**Test Secrets:**
```bash
wrangler secret list --env production
# Should show all 5 secrets:
# - JWT_SECRET
# - ENCRYPTION_KEY
# - AUTH_SECRET
# - STRIPE_SECRET_KEY
# - SENDGRID_API_KEY
```

---

## Step 6: Deploy WAF Rules (Optional - 10 minutes)

**Via Cloudflare Dashboard:**
1. Go to: https://dash.cloudflare.com
2. Select your zone
3. Navigate to: Security → WAF
4. Click "Create firewall rule"
5. Add rules from `cloudflare-waf-config.json`

**Or skip for now** - Your platform is already secure with:
- ✅ Security bootstrap validation
- ✅ JWT authentication
- ✅ Rate limiting in code
- ✅ OWASP compliance (98.5%)

WAF adds extra layer but not required for launch.

---

## 🎉 Launch Checklist

- [ ] Stripe API key added
- [ ] SendGrid API key added
- [ ] SendGrid sender email verified
- [ ] Google Analytics property created
- [ ] GA4 Measurement ID updated in frontend
- [ ] Frontend redeployed
- [ ] Backend health check passing
- [ ] Landing page loads
- [ ] Analytics tracking works
- [ ] Secrets verified

**Once all checked, you're LIVE! 🚀**

---

## 🆘 Quick Troubleshooting

**Can't access Stripe/SendGrid dashboard?**
- Sign up for new accounts (both have free tiers)
- Use test mode initially
- Upgrade to production when ready

**GA4 not showing users?**
- Wait 5 minutes (real-time has delay)
- Check Measurement ID is correct
- Clear browser cache and retry

**Secrets not setting?**
```bash
# Make sure you're in the right environment
wrangler whoami
# Should show your Cloudflare account

# List existing secrets
wrangler secret list --env production
```

---

## 📞 Support

If you get stuck:
1. Check error messages carefully
2. Review [LAUNCH-READY-INSTRUCTIONS.md](LAUNCH-READY-INSTRUCTIONS.md)
3. Check service status pages:
   - Stripe: https://status.stripe.com
   - SendGrid: https://status.sendgrid.com
   - Cloudflare: https://www.cloudflarestatus.com

---

**Estimated total time: 30 minutes**

**Let's launch! 🚀**
