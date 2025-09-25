#!/usr/bin/env node

const { execSync } = require('child_process');
const path = require('path');

async function runQuantumAudit() {
  try {
    console.log('🚀 Starting Quantum Audit System...\n');

    // Compile TypeScript with specific config
    console.log('📦 Compiling TypeScript...');
    execSync('npx tsc -p src/quantum-audit/tsconfig.json', {
      stdio: 'inherit',
      cwd: process.cwd()
    });

    console.log('⚡ Running Quantum Audit...');
    execSync('node dist/quantum-audit/quantum-audit.js', {
      stdio: 'inherit',
      cwd: process.cwd()
    });

  } catch (error) {
    console.error('❌ Quantum Audit failed:', error.message);
    process.exit(1);
  }
}

// Run if called directly
if (require.main === module) {
  runQuantumAudit();
}

module.exports = { runQuantumAudit };