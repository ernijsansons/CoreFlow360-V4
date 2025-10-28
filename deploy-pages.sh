#!/bin/bash

# CoreFlow360 Frontend Deployment Script
# Uses Cloudflare API to deploy Pages project

set -e

API_TOKEN="c49TLrwyAp783j_F24avVZ24wI0ZC9UJnM2AGXFK"
ACCOUNT_ID="d2897bdebfa128919bd89b265e6a712e"
PROJECT_NAME="coreflow360-frontend"
DIST_DIR="frontend/dist"

echo "🚀 CoreFlow360 Frontend Deployment"
echo "===================================="
echo ""

# Step 1: Verify dist folder exists
if [ ! -d "$DIST_DIR" ]; then
    echo "❌ Error: $DIST_DIR not found. Run 'npm run build' first."
    exit 1
fi

echo "✅ Build artifacts found in $DIST_DIR"
echo ""

# Step 2: Create deployment
echo "📦 Creating deployment..."

# Get account details
ACCOUNT_INFO=$(curl -s -X GET "https://api.cloudflare.com/client/v4/accounts/$ACCOUNT_ID" \
  -H "Authorization: Bearer $API_TOKEN" \
  -H "Content-Type: application/json")

echo "Account: $(echo $ACCOUNT_INFO | jq -r '.result.name // "Unknown"')"
echo ""

# Step 3: Get project info
echo "📋 Fetching project information..."
PROJECT_INFO=$(curl -s -X GET "https://api.cloudflare.com/client/v4/accounts/$ACCOUNT_ID/pages/projects/$PROJECT_NAME" \
  -H "Authorization: Bearer $API_TOKEN" \
  -H "Content-Type: application/json")

PROJECT_STATUS=$(echo $PROJECT_INFO | jq -r '.success')

if [ "$PROJECT_STATUS" != "true" ]; then
    echo "❌ Error: Could not access project $PROJECT_NAME"
    echo "Response: $PROJECT_INFO"
    exit 1
fi

echo "✅ Project found: $PROJECT_NAME"
echo ""

# Step 4: Create a tarball of dist folder
echo "📦 Packaging build artifacts..."
cd frontend
tar -czf ../deployment.tar.gz -C dist .
cd ..

TARBALL_SIZE=$(ls -lh deployment.tar.gz | awk '{print $5}')
echo "✅ Created deployment.tar.gz ($TARBALL_SIZE)"
echo ""

# Step 5: Upload using Direct Upload API
echo "☁️  Uploading to Cloudflare Pages..."
UPLOAD_RESPONSE=$(curl -s -X POST "https://api.cloudflare.com/client/v4/accounts/$ACCOUNT_ID/pages/projects/$PROJECT_NAME/deployments" \
  -H "Authorization: Bearer $API_TOKEN" \
  -F "file=@deployment.tar.gz" \
  -F "branch=master")

UPLOAD_SUCCESS=$(echo $UPLOAD_RESPONSE | jq -r '.success')

if [ "$UPLOAD_SUCCESS" != "true" ]; then
    echo "❌ Deployment failed"
    echo "Response: $UPLOAD_RESPONSE"
    rm deployment.tar.gz
    exit 1
fi

DEPLOYMENT_URL=$(echo $UPLOAD_RESPONSE | jq -r '.result.url')
DEPLOYMENT_ID=$(echo $UPLOAD_RESPONSE | jq -r '.result.id')

echo "✅ Deployment created successfully!"
echo ""
echo "📊 Deployment Details:"
echo "   ID: $DEPLOYMENT_ID"
echo "   URL: $DEPLOYMENT_URL"
echo ""

# Cleanup
rm deployment.tar.gz

echo "🎉 Deployment complete!"
echo ""
echo "Next steps:"
echo "1. Visit: $DEPLOYMENT_URL"
echo "2. Run tests: cd frontend && npx playwright test --reporter=line"
echo "3. Check test improvements!"
