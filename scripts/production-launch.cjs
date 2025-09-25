#!/usr/bin/env node

const { execSync } = require('child_process');
const path = require('path');

async function runProductionLaunch() {
  try {
    const command = process.argv[2] || 'help';

    console.log('🚀 Starting Production Launch System...\n');

    // Compile TypeScript with specific config
    console.log('📦 Compiling TypeScript...');
    execSync('npx tsc -p src/production-launch/tsconfig.json', {
      stdio: 'inherit',
      cwd: process.cwd()
    });

    console.log('⚡ Running Production Launch...');
    execSync(`node dist/production-launch/production-launch.js ${command}`, {
      stdio: 'inherit',
      cwd: process.cwd()
    });

  } catch (error) {
    console.error('❌ Production Launch failed:', error.message);
    process.exit(1);
  }
}

// Run if called directly
if (require.main === module) {
  runProductionLaunch();
}

module.exports = { runProductionLaunch };