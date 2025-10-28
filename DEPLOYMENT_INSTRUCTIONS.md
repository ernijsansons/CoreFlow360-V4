# Cloudflare Pages Deployment Instructions

## Current Status

✅ **Production build is ready and working perfectly!**

The frontend has been built and tested successfully:
- Production build: 227 kB main bundle
- Dev mode: Working correctly
- No JavaScript errors
- All components rendering properly

## Issue: Authentication Required

The deployment is blocked because the current Cloudflare API token is invalid/expired.

## Solution: Authenticate with Cloudflare

You have **two options** to authenticate:

### Option 1: OAuth Login (Recommended)

1. **Logout from current session:**
   ```bash
   wrangler logout
   ```

2. **Login via browser (OAuth):**
   ```bash
   wrangler login
   ```

   This will:
   - Open your default browser
   - Redirect to Cloudflare's OAuth page
   - Ask you to grant permissions
   - Store authentication credentials locally

3. **Deploy:**
   ```bash
   cd frontend
   npx wrangler pages deploy dist --project-name=coreflow360-v4-prod
   ```

### Option 2: Generate New API Token

1. **Go to Cloudflare Dashboard:**
   - Visit: https://dash.cloudflare.com/profile/api-tokens
   - Click "Create Token"

2. **Use "Edit Cloudflare Workers" template or create custom:**
   - **Permissions needed:**
     - Account: Cloudflare Pages: Edit
     - Zone: Cloudflare Pages: Edit
     - Account: D1: Edit (if using D1 databases)
     - Account: Workers R2 Storage: Edit (if using R2)

3. **Copy the token and set environment variable:**

   **PowerShell:**
   ```powershell
   $env:CLOUDFLARE_API_TOKEN="your_new_token_here"
   ```

   **CMD:**
   ```cmd
   set CLOUDFLARE_API_TOKEN=your_new_token_here
   ```

   **Permanent (System Environment Variables):**
   - Open System Properties → Environment Variables
   - Edit or create `CLOUDFLARE_API_TOKEN` variable
   - Paste your new token
   - Restart terminal

4. **Deploy:**
   ```bash
   cd frontend
   npx wrangler pages deploy dist --project-name=coreflow360-v4-prod
   ```

## Quick Deploy Script

I've created a deployment script for you at `deploy-frontend.js`.

**To use it:**
```bash
node deploy-frontend.js
```

This script will:
1. Build the frontend (ensures latest code)
2. Deploy to Cloudflare Pages
3. Handle authentication (will prompt for OAuth if needed)

## What Happens Next

Once authenticated and deployed, you'll see:

```
✨ Success! Uploaded 6 files (X seconds)

✨ Deployment complete! Take a peek over at
   https://your-deployment-url.pages.dev
```

## Verification Steps

After deployment:

1. **Test the deployment URL:**
   - Visit the provided pages.dev URL
   - Verify the Dashboard loads
   - Check browser console for errors

2. **Run production tests:**
   ```bash
   cd frontend
   node test-dev-mode.js  # Change port to deployment URL
   ```

## Troubleshooting

### Error: "Authentication error [code: 10000]"
- **Cause:** API token is invalid or expired
- **Fix:** Use Option 1 (OAuth Login) above

### Error: "Invalid access token [code: 9109]"
- **Cause:** Token lacks required permissions
- **Fix:** Generate new token with correct permissions (Option 2)

### Error: "Project not found"
- **Fix:** The project will be created automatically on first deploy
- Or create it manually at: https://dash.cloudflare.com/pages

### Browser doesn't open for OAuth
- **Fix:** Copy the URL from terminal and open manually

## Current Account Configuration

From `wrangler.toml`:
- **Account ID:** d2897bdebfa128919bd89b265e6a712e
- **Project Name:** coreflow360-v4-prod

## Next Steps After Deployment

1. ✅ Deploy to Cloudflare Pages
2. 🧪 Test production deployment
3. 🔗 Set up custom domain (optional)
4. 📊 Monitor performance
5. 🚀 Continue with feature development

---

**Note:** The production build is already created in `frontend/dist/` and is ready to deploy!
