#!/usr/bin/env node

/**
 * Cross-Platform Petri Safety Audit Launcher
 * Automatically detects OS and runs appropriate script
 */

const { spawn } = require('child_process');
const path = require('path');
const os = require('os');

const platform = os.platform();
const scriptDir = __dirname;

console.log('🔒 CoreFlow360 V4 - AI Safety Audit Launcher');
console.log('================================================\n');
console.log(`Platform detected: ${platform}\n`);

let command, args, scriptPath;

if (platform === 'win32') {
  // Windows - use PowerShell
  scriptPath = path.join(scriptDir, 'run-petri-safety-audit.ps1');
  command = 'powershell';
  args = ['-ExecutionPolicy', 'Bypass', '-File', scriptPath];
  console.log('Using PowerShell script...\n');
} else {
  // Unix-like (Linux, macOS) - use Bash
  scriptPath = path.join(scriptDir, 'run-petri-safety-audit.sh');
  command = 'bash';
  args = [scriptPath];
  console.log('Using Bash script...\n');
}

// Spawn the appropriate script
const child = spawn(command, args, {
  stdio: 'inherit',
  shell: true,
  env: process.env,
});

child.on('error', (error) => {
  console.error('❌ Failed to start safety audit:', error.message);
  process.exit(1);
});

child.on('close', (code) => {
  if (code === 0) {
    console.log('\n✅ Safety audit completed successfully');
  } else if (code === 2) {
    console.log('\n❌ Critical safety failures detected');
  } else {
    console.log(`\n⚠️ Safety audit exited with code ${code}`);
  }
  process.exit(code);
});
