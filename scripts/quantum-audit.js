#!/usr/bin/env node

import { execSync } from 'child_process';
import path from 'path';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

async function runQuantumAudit() {
  try {
    console.log('🚀 Starting Quantum Audit System...\n');

    // Run the TypeScript audit
    const auditScript = path.join(__dirname, '..', 'src', 'quantum-audit', 'quantum-audit.ts');

    execSync(`npx ts-node "${auditScript}"`, {
      stdio: 'inherit',
      cwd: process.cwd()
    });

  } catch (error) {
    console.error('❌ Quantum Audit failed:', error.message);
    process.exit(1);
  }
}

// Run if called directly
runQuantumAudit();

export { runQuantumAudit };