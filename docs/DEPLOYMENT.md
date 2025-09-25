# 🚀 Design System Deployment Guide

Complete guide for deploying the Future Enterprise Design System with Docker, GitHub, and Cloudflare integration.

## 📋 Table of Contents

1. [Prerequisites](#prerequisites)
2. [Initial Setup](#initial-setup)
3. [Docker Deployment](#docker-deployment)
4. [GitHub Actions CI/CD](#github-actions-cicd)
5. [Cloudflare Configuration](#cloudflare-configuration)
6. [Deployment Workflow](#deployment-workflow)
7. [Troubleshooting](#troubleshooting)
8. [Architecture](#architecture)

## Prerequisites

### Required Tools
```bash
# Check installations
docker --version          # Docker 20.10+
git --version             # Git 2.30+
node --version           # Node.js 18+
pnpm --version           # pnpm 8.14+
wrangler --version       # Wrangler 3.0+
gh --version             # GitHub CLI
```

### Required Accounts
- GitHub account with Container Registry access
- Cloudflare account with Workers subscription
- NPM account (for publishing)
- Figma account with Dev Mode enabled

## Initial Setup

### 1. Clone and Configure Repository
```bash
# Clone repository
git clone https://github.com/your-org/coreflow360-v4.git
cd coreflow360-v4/design-system

# Install dependencies
pnpm install

# Copy environment template
cp .env.example .env
```

### 2. Configure Environment Variables
Edit `.env` with your credentials:
```env
# Cloudflare
CLOUDFLARE_ACCOUNT_ID=your_account_id
CLOUDFLARE_API_TOKEN=your_api_token
CLOUDFLARE_ZONE_ID=your_zone_id

# GitHub
GITHUB_TOKEN=your_github_token
GITHUB_ACTOR=your_username

# Figma
FIGMA_TOKEN=your_figma_token
FIGMA_FILE_ID=your_file_id

# Security
API_KEY=generate_32_char_string
JWT_SECRET=generate_32_char_string_minimum
```

### 3. Configure GitHub Secrets
```bash
# Set GitHub repository secrets
gh secret set CLOUDFLARE_API_TOKEN
gh secret set CLOUDFLARE_ACCOUNT_ID
gh secret set NPM_TOKEN
gh secret set FIGMA_TOKEN
gh secret set CHROMATIC_PROJECT_TOKEN
```

## Docker Deployment

### Local Development with Docker Compose
```bash
# Start all development services
docker-compose up dev storybook playground

# Start specific service
docker-compose up storybook

# Build production image
docker-compose --profile production up

# Run tests in Docker
docker-compose --profile test up
```

### Building and Pushing Images
```bash
# Login to GitHub Container Registry
echo $GITHUB_TOKEN | docker login ghcr.io -u $GITHUB_ACTOR --password-stdin

# Build multi-platform images
docker buildx create --use --name builder
docker buildx build \
  --platform linux/amd64,linux/arm64 \
  --tag ghcr.io/$GITHUB_ACTOR/design-system:latest \
  --push .

# Pull and run production image
docker pull ghcr.io/$GITHUB_ACTOR/design-system:latest
docker run -p 3000:3000 ghcr.io/$GITHUB_ACTOR/design-system:latest
```

## GitHub Actions CI/CD

### Workflow Triggers
The deployment pipeline triggers on:
- Push to `main`, `develop`, or `comprehensive-testing` branches
- Pull requests to `main`
- Manual dispatch with environment selection

### Manual Deployment
```bash
# Trigger manual deployment via GitHub CLI
gh workflow run design-system-deploy.yml \
  -f environment=production

# Check workflow status
gh run list --workflow=design-system-deploy.yml
```

### Monitoring Deployments
```bash
# Watch workflow in real-time
gh run watch

# View workflow logs
gh run view --log
```

## Cloudflare Configuration

### Initial Cloudflare Setup
```bash
# Login to Cloudflare
wrangler login

# Create KV namespaces
wrangler kv:namespace create CACHE --env production
wrangler kv:namespace create TOKENS --env production

# Create D1 database
wrangler d1 create design-system-analytics

# Create R2 bucket
wrangler r2 bucket create design-system-assets

# Set secrets
wrangler secret put FIGMA_TOKEN --env production
wrangler secret put API_KEY --env production
wrangler secret put JWT_SECRET --env production
```

### Deploy to Cloudflare Workers
```bash
# Deploy to staging
wrangler deploy --env staging

# Deploy to production
wrangler deploy --env production

# Deploy Pages (static assets)
wrangler pages deploy dist --project-name=design-system

# Check deployment status
wrangler deployments list
```

### Custom Domain Setup
1. Navigate to Cloudflare Dashboard > Workers & Pages
2. Select your Worker: `future-enterprise-design-system`
3. Go to Settings > Custom Domains
4. Add domain: `design-system.coreflow360.com`
5. Configure DNS records as instructed

## Deployment Workflow

### Automated Deployment Script
```bash
# Deploy to staging
./scripts/deploy-design-system.sh staging

# Deploy to production
./scripts/deploy-design-system.sh production

# Rollback deployment
./scripts/deploy-design-system.sh production rollback
```

### Step-by-Step Manual Deployment

#### 1. Pre-deployment Checks
```bash
# Run tests
pnpm test

# Check bundle size
pnpm build
ls -lh dist/

# Lint and format
pnpm lint
pnpm format:check
```

#### 2. Build and Push Docker
```bash
# Build Docker image
docker build -t design-system:latest .

# Tag for registry
docker tag design-system:latest ghcr.io/$GITHUB_ACTOR/design-system:latest

# Push to registry
docker push ghcr.io/$GITHUB_ACTOR/design-system:latest
```

#### 3. Deploy to Cloudflare
```bash
# Build for production
pnpm build

# Deploy Workers
wrangler deploy --env production

# Deploy static assets to Pages
wrangler pages deploy dist --project-name=design-system

# Deploy Storybook
pnpm storybook:build
wrangler pages deploy storybook-static --project-name=design-system-storybook
```

#### 4. Verify Deployment
```bash
# Check Workers health
curl https://design-system.coreflow360.workers.dev/health

# Check Pages deployment
curl https://design-system.pages.dev

# Check Docker container
docker ps | grep design-system
```

## Troubleshooting

### Common Issues and Solutions

#### Docker Build Failures
```bash
# Clear Docker cache
docker system prune -a

# Rebuild without cache
docker build --no-cache -t design-system .

# Check Docker logs
docker logs design-system-dev
```

#### Cloudflare Deployment Issues
```bash
# Check Cloudflare status
wrangler tail --env production

# Validate configuration
wrangler whoami
wrangler deployments list

# Reset KV namespace
wrangler kv:namespace delete CACHE --env production
wrangler kv:namespace create CACHE --env production
```

#### GitHub Actions Failures
```bash
# Re-run failed workflow
gh run rerun --failed

# Debug workflow locally with act
act -j quality --secret-file .env

# Check GitHub service status
gh api /rate_limit
```

### Rollback Procedures

#### Cloudflare Rollback
```bash
# List deployments
wrangler deployments list

# Rollback to previous version
wrangler rollback --env production

# Or rollback to specific version
wrangler rollback [deployment-id] --env production
```

#### Docker Rollback
```bash
# List available tags
docker images ghcr.io/$GITHUB_ACTOR/design-system

# Pull previous version
docker pull ghcr.io/$GITHUB_ACTOR/design-system:v1.0.0

# Retag as latest
docker tag ghcr.io/$GITHUB_ACTOR/design-system:v1.0.0 \
           ghcr.io/$GITHUB_ACTOR/design-system:latest

# Push updated tag
docker push ghcr.io/$GITHUB_ACTOR/design-system:latest
```

## Architecture

### Deployment Architecture
```
┌─────────────────┐     ┌─────────────────┐     ┌─────────────────┐
│   GitHub Repo   │────▶│  GitHub Actions │────▶│  Docker Registry│
└─────────────────┘     └─────────────────┘     └─────────────────┘
         │                       │                         │
         │                       │                         │
         ▼                       ▼                         ▼
┌─────────────────┐     ┌─────────────────┐     ┌─────────────────┐
│ Cloudflare Pages│     │Cloudflare Workers│    │   Docker Hosts  │
└─────────────────┘     └─────────────────┘     └─────────────────┘
         │                       │                         │
         └───────────────────────┴─────────────────────────┘
                                 │
                                 ▼
                         ┌─────────────────┐
                         │   Production    │
                         │   Environment   │
                         └─────────────────┘
```

### Service URLs
- **Production Workers**: https://design-system.coreflow360.workers.dev
- **Production Pages**: https://design-system.pages.dev
- **Staging Workers**: https://staging-design-system.coreflow360.workers.dev
- **Storybook**: https://design-system-storybook.pages.dev
- **Docker Registry**: ghcr.io/your-org/design-system
- **NPM Package**: @future-enterprise/design-system

### Environment Configuration

| Environment | Branch | Auto Deploy | Manual Approval | Domain |
|------------|--------|-------------|-----------------|---------|
| Development | develop | No | No | localhost |
| Staging | comprehensive-testing | Yes | No | staging-design-system.coreflow360.com |
| Production | main | Yes | Yes | design-system.coreflow360.com |

## Best Practices

### Security
- Never commit `.env` files
- Rotate API tokens regularly
- Use environment-specific secrets
- Enable 2FA on all accounts
- Implement least-privilege access

### Performance
- Keep bundle size under 100KB
- Use Docker layer caching
- Implement CDN caching
- Enable Cloudflare Auto Minify
- Use R2 for static assets

### Monitoring
- Set up Cloudflare Analytics
- Configure error tracking
- Monitor bundle size trends
- Track deployment frequency
- Review security scans

## Support

For deployment issues:
1. Check [Troubleshooting](#troubleshooting) section
2. Review GitHub Actions logs
3. Check Cloudflare Workers logs
4. Open issue at: https://github.com/your-org/coreflow360-v4/issues

## Next Steps

After successful deployment:
1. ✅ Verify all endpoints are accessible
2. ✅ Test Figma integration
3. ✅ Configure monitoring alerts
4. ✅ Set up backup procedures
5. ✅ Document any custom configurations

---

**Last Updated**: January 2024
**Version**: 1.0.0