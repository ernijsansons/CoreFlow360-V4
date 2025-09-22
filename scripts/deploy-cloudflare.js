#!/usr/bin/env node

/**
 * CLOUDFLARE DEPLOYMENT SCRIPT
 * Production-ready deployment automation for CoreFlow360 V4
 */

import { execSync } from 'child_process';
import fs from 'fs';
import path from 'path';

class CloudflareDeployer {
  constructor() {
    this.env = process.env.NODE_ENV || 'development';
    this.dryRun = process.argv.includes('--dry-run');
    this.force = process.argv.includes('--force');
    this.verbose = process.argv.includes('--verbose');
  }

  async deploy() {
    console.log('🚀 COREFLOW360 V4 - CLOUDFLARE DEPLOYMENT');
    console.log('==========================================');
    console.log(`Environment: ${this.env}`);
    console.log(`Dry Run: ${this.dryRun}`);
    console.log('');

    try {
      // Pre-deployment checks
      await this.preDeploymentChecks();

      // Build and validate
      await this.buildProject();

      // Deploy to Cloudflare
      await this.deployToCloudflare();

      // Post-deployment verification
      await this.postDeploymentVerification();

      console.log('✅ Deployment completed successfully!');

    } catch (error) {
      console.error('❌ Deployment failed:', error.message);
      process.exit(1);
    }
  }

  async preDeploymentChecks() {
    console.log('🔍 Running pre-deployment checks...');

    // Check required environment variables
    const requiredSecrets = [
      'AUTH_SECRET',
      'ENCRYPTION_KEY',
      'JWT_SECRET',
      'API_KEY'
    ];

    for (const secret of requiredSecrets) {
      try {
        const result = this.execCommand(`wrangler secret list`, true);
        if (!result.includes(secret)) {
          throw new Error(`Missing required secret: ${secret}`);
        }
      } catch (error) {
        console.warn(`⚠️ Could not verify secret ${secret}: ${error.message}`);
      }
    }

    // Check wrangler.toml configuration
    if (!fs.existsSync('./wrangler.toml')) {
      throw new Error('wrangler.toml not found');
    }

    // Check TypeScript compilation
    if (!this.force) {
      console.log('  📝 Checking TypeScript...');
      this.execCommand('npm run typecheck');

      // Check tests
      console.log('  🧪 Running tests...');
      this.execCommand('npm run test:run');
    } else {
      console.log('  ⚠️ Skipping TypeScript and test checks (force mode)');
    }

    console.log('✅ Pre-deployment checks passed');
  }

  async buildProject() {
    console.log('🔨 Building project...');

    // Clean previous builds
    this.execCommand('npm run clean');

    // Install dependencies
    console.log('  📦 Installing dependencies...');
    this.execCommand('npm ci');

    // Build TypeScript
    if (!this.force) {
      console.log('  🔧 Compiling TypeScript...');
      this.execCommand('npm run typecheck');
    } else {
      console.log('  ⚠️ Skipping TypeScript compilation (force mode)');
    }

    // Build frontend if exists
    if (fs.existsSync('./frontend')) {
      console.log('  🎨 Building frontend...');
      this.execCommand('npm run frontend:build');
    }

    console.log('✅ Project built successfully');
  }

  async deployToCloudflare() {
    console.log('☁️ Deploying to Cloudflare...');

    const deployCommand = this.env === 'production'
      ? 'wrangler deploy --env production'
      : `wrangler deploy --env ${this.env}`;

    if (this.dryRun) {
      console.log(`Would run: ${deployCommand}`);
      return;
    }

    // Deploy Worker
    console.log('  🔧 Deploying Worker...');
    this.execCommand(deployCommand);

    // Deploy D1 migrations
    console.log('  🗄️ Running D1 migrations...');
    this.execCommand(`wrangler d1 migrations apply coreflow360-main --env ${this.env}`);

    // Deploy Pages if exists
    if (fs.existsSync('./frontend/dist')) {
      console.log('  📄 Deploying Pages...');
      this.execCommand(`wrangler pages deploy frontend/dist --project-name coreflow360-frontend --env ${this.env}`);
    }

    // Deploy KV data if needed
    if (fs.existsSync('./data/kv-seed.json')) {
      console.log('  🔑 Seeding KV data...');
      const kvData = JSON.parse(fs.readFileSync('./data/kv-seed.json', 'utf8'));

      for (const [key, value] of Object.entries(kvData)) {
        this.execCommand(`wrangler kv:key put "${key}" "${JSON.stringify(value)}" --binding KV_CONFIG --env ${this.env}`);
      }
    }

    console.log('✅ Cloudflare deployment completed');
  }

  async postDeploymentVerification() {
    console.log('🔍 Running post-deployment verification...');

    if (this.dryRun) {
      console.log('Skipping verification in dry-run mode');
      return;
    }

    // Get deployment URL
    const workerUrl = this.getWorkerUrl();

    // Health check
    console.log('  ❤️ Health check...');
    await this.verifyEndpoint(`${workerUrl}/health`, { status: 'healthy' });

    // API status check
    console.log('  📊 API status check...');
    await this.verifyEndpoint(`${workerUrl}/api/v4/status`, { status: 'operational' });

    // Test key endpoints
    const testEndpoints = [
      '/api/v4/learning',
      '/api/v4/observability',
      '/api/v4/agents'
    ];

    for (const endpoint of testEndpoints) {
      console.log(`  🔗 Testing ${endpoint}...`);
      await this.verifyEndpoint(`${workerUrl}${endpoint}`, null, false);
    }

    console.log('✅ Post-deployment verification completed');
  }

  async verifyEndpoint(url, expectedData = null, throwOnError = true) {
    try {
      const response = await fetch(url);

      if (!response.ok && throwOnError) {
        throw new Error(`HTTP ${response.status}: ${response.statusText}`);
      }

      if (expectedData) {
        const data = await response.json();

        for (const [key, value] of Object.entries(expectedData)) {
          if (data[key] !== value) {
            throw new Error(`Expected ${key}=${value}, got ${data[key]}`);
          }
        }
      }

      console.log(`    ✅ ${url} - OK`);

    } catch (error) {
      if (throwOnError) {
        throw new Error(`Endpoint verification failed for ${url}: ${error.message}`);
      } else {
        console.log(`    ⚠️ ${url} - ${error.message}`);
      }
    }
  }

  getWorkerUrl() {
    const envMapping = {
      production: 'coreflow360-v4-prod.workers.dev',
      staging: 'coreflow360-v4-staging.workers.dev',
      development: 'coreflow360-v4-dev.workers.dev'
    };

    return `https://${envMapping[this.env] || envMapping.development}`;
  }

  execCommand(command, silent = false) {
    if (this.verbose || !silent) {
      console.log(`    $ ${command}`);
    }

    try {
      const result = execSync(command, {
        encoding: 'utf8',
        stdio: silent ? 'pipe' : 'inherit'
      });

      return result;

    } catch (error) {
      if (silent) {
        return '';
      }
      throw error;
    }
  }
}

// CLI interface
async function main() {
  const deployer = new CloudflareDeployer();

  if (process.argv.includes('--help')) {
    console.log(`
CloudFlare Deployment Script for CoreFlow360 V4

Usage: node scripts/deploy-cloudflare.js [options]

Options:
  --dry-run     Show what would be deployed without actually deploying
  --force       Skip tests and other safety checks
  --verbose     Show detailed output
  --help        Show this help message

Environment Variables:
  NODE_ENV      Target environment (development, staging, production)

Examples:
  # Deploy to development
  npm run deploy

  # Deploy to staging
  NODE_ENV=staging npm run deploy

  # Deploy to production with verification
  NODE_ENV=production npm run deploy

  # Dry run to see what would happen
  npm run deploy -- --dry-run
`);
    process.exit(0);
  }

  await deployer.deploy();
}

// Run main function when script is executed directly
main().catch(error => {
  console.error('Deployment script failed:', error);
  process.exit(1);
});

export { CloudflareDeployer };