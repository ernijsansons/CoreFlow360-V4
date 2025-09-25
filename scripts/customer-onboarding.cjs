#!/usr/bin/env node

const { execSync } = require('child_process');
const path = require('path');

async function runCustomerOnboarding() {
  try {
    const command = process.argv[2] || 'help';
    const args = process.argv.slice(3).join(' ');

    console.log('🎯 Starting Customer Onboarding System...\n');

    // Compile TypeScript with specific config
    console.log('📦 Compiling TypeScript...');
    execSync('npx tsc -p src/customer-onboarding/tsconfig.json', {
      stdio: 'inherit',
      cwd: process.cwd()
    });

    console.log('⚡ Running Customer Onboarding...');
    execSync(`node dist/customer-onboarding/customer-onboarding.js ${command} ${args}`, {
      stdio: 'inherit',
      cwd: process.cwd()
    });

  } catch (error) {
    console.error('❌ Customer Onboarding failed:', error.message);
    process.exit(1);
  }
}

// Run if called directly
if (require.main === module) {
  runCustomerOnboarding();
}

module.exports = { runCustomerOnboarding };