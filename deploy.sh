#!/bin/bash
# deploy.sh - Production deployment

echo "🚀 Deploying CoreFlow360 V4 to Cloudflare..."

# Run tests
npm test
if [ $? -ne 0 ]; then
  echo "❌ Tests failed. Aborting deployment."
  exit 1
fi

# Build
npm run build

# Run migrations
wrangler d1 migrations apply DB --env production

# Deploy to staging first
wrangler deploy --env staging
echo "✅ Deployed to staging"

# Run smoke tests
npm run test:staging
if [ $? -ne 0 ]; then
  echo "❌ Staging tests failed. Aborting."
  exit 1
fi

# Deploy to production
wrangler deploy --env production
echo "✅ Deployed to production"

# Verify deployment
curl -s https://api.coreflow360.com/health | grep "ok"
if [ $? -eq 0 ]; then
  echo "✅ Production health check passed"
else
  echo "❌ Health check failed"
  exit 1
fi

echo "🎉 Deployment complete!"