# 🚀 Wrangler Setup Guide for Design System

## ✅ Wrangler Installation Complete

Wrangler has been successfully installed and configured for your account:
- **Email**: ernijs.ansons@gmail.com
- **Account ID**: d2897bdebfa128919bd89b265e6a712e
- **Wrangler Version**: 4.39.0

## 📋 Quick Setup Commands

Run these commands to set up your Cloudflare infrastructure:

### 1. Create KV Namespaces
```bash
# Development environment
wrangler kv:namespace create CACHE --env development
wrangler kv:namespace create TOKENS --env development

# Staging environment
wrangler kv:namespace create CACHE --env staging
wrangler kv:namespace create TOKENS --env staging

# Production environment
wrangler kv:namespace create CACHE --env production
wrangler kv:namespace create TOKENS --env production
```

### 2. Create D1 Database
```bash
# Create databases for each environment
wrangler d1 create design-system-analytics-dev
wrangler d1 create design-system-analytics-staging
wrangler d1 create design-system-analytics-prod

# Apply migrations
wrangler d1 execute design-system-analytics-dev --file=workers/migrations/0001_init.sql
wrangler d1 execute design-system-analytics-staging --file=workers/migrations/0001_init.sql
wrangler d1 execute design-system-analytics-prod --file=workers/migrations/0001_init.sql
```

### 3. Create R2 Buckets
```bash
# Create buckets for each environment
wrangler r2 bucket create design-system-assets-dev
wrangler r2 bucket create design-system-assets-staging
wrangler r2 bucket create design-system-assets-prod
```

### 4. Set Secrets
```bash
# Set secrets for production (you'll be prompted to enter values)
wrangler secret put FIGMA_TOKEN --env production
wrangler secret put API_KEY --env production
wrangler secret put JWT_SECRET --env production

# Set secrets for staging
wrangler secret put FIGMA_TOKEN --env staging
wrangler secret put API_KEY --env staging
wrangler secret put JWT_SECRET --env staging
```

### 5. Deploy Workers
```bash
# Deploy to staging (test first)
npm run wrangler:deploy:staging

# Deploy to production (after testing)
npm run wrangler:deploy
```

## 🛠️ Available NPM Scripts

I've added convenient npm scripts for Wrangler operations:

```bash
# Development
npm run wrangler:dev              # Start local dev server

# Deployment
npm run wrangler:deploy            # Deploy to production
npm run wrangler:deploy:staging   # Deploy to staging

# Management
npm run wrangler:login            # Login to Cloudflare
npm run wrangler:whoami           # Check current user
npm run wrangler:kv:list         # List KV namespaces
npm run wrangler:d1:list         # List D1 databases
npm run wrangler:r2:list         # List R2 buckets
npm run wrangler:secret:list     # List secrets
npm run wrangler:tail            # Stream live logs

# Full setup automation
npm run wrangler:setup            # Run complete setup script
```

## 📝 Update wrangler.toml

After creating the resources above, update your `wrangler.toml` with the generated IDs:

1. **KV Namespace IDs**: Add the IDs returned from the create commands
2. **D1 Database IDs**: Add the database IDs to the commented sections
3. **Update account_id**: Your account ID is `d2897bdebfa128919bd89b265e6a712e`

Example:
```toml
# In wrangler.toml, update these sections:

# Uncomment and add your KV namespace IDs
[env.production]
kv_namespaces = [
  { binding = "CACHE", id = "YOUR_CACHE_ID_HERE" },
  { binding = "TOKENS", id = "YOUR_TOKENS_ID_HERE" }
]

# Uncomment and add your D1 database ID
[[d1_databases]]
binding = "DB"
database_name = "design-system-analytics-prod"
database_id = "YOUR_DATABASE_ID_HERE"
```

## 🚦 Next Steps

1. **Run automated setup script**:
   ```bash
   npm run wrangler:setup
   ```
   This will walk you through creating all resources.

2. **Test local development**:
   ```bash
   npm run wrangler:dev
   ```

3. **Deploy to staging**:
   ```bash
   npm run wrangler:deploy:staging
   ```

4. **Monitor deployment**:
   ```bash
   npm run wrangler:tail
   ```

## 🔧 Troubleshooting

If you encounter issues:

1. **Authentication issues**: Run `wrangler login` again
2. **Permission errors**: Ensure you have the correct permissions in Cloudflare dashboard
3. **Configuration errors**: Check `wrangler.toml` syntax
4. **Build errors**: Ensure you've run `npm install` and `npm run build` first

## 📚 Resources

- [Wrangler Documentation](https://developers.cloudflare.com/workers/wrangler/)
- [Workers Documentation](https://developers.cloudflare.com/workers/)
- [D1 Documentation](https://developers.cloudflare.com/d1/)
- [KV Documentation](https://developers.cloudflare.com/workers/runtime-apis/kv/)
- [R2 Documentation](https://developers.cloudflare.com/r2/)

## ✅ Status

- ✅ Wrangler installed globally
- ✅ Authentication configured
- ✅ wrangler.toml fixed and ready
- ✅ NPM scripts added
- ✅ Setup scripts created
- ⏳ Awaiting resource creation (KV, D1, R2)
- ⏳ Awaiting deployment

---

Your Wrangler setup is ready! Run the commands above to create your Cloudflare resources and deploy your design system.