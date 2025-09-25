import fs from 'fs';
import path from 'path';
import { execSync } from 'child_process';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// ANSI color codes
const colors = {
  reset: '\x1b[0m',
  bright: '\x1b[1m',
  dim: '\x1b[2m',
  red: '\x1b[31m',
  green: '\x1b[32m',
  yellow: '\x1b[33m',
  blue: '\x1b[34m',
  cyan: '\x1b[36m',
  white: '\x1b[37m',
};

function log(message, type = 'info') {
  const prefix = {
    info: `${colors.cyan}ℹ${colors.reset}`,
    success: `${colors.green}✓${colors.reset}`,
    warning: `${colors.yellow}⚠${colors.reset}`,
    error: `${colors.red}✖${colors.reset}`,
    step: `${colors.blue}▶${colors.reset}`,
  }[type] || '';

  console.log(`${prefix} ${message}`);
}

function runCommand(command, description) {
  log(`${description}...`, 'step');
  try {
    const output = execSync(command, {
      encoding: 'utf8',
      stdio: 'pipe'
    });

    // Check if there are any warnings or errors in output
    const lines = output.split('\n').filter(line => line.trim());
    const lastLine = lines[lines.length - 1] || '';

    if (lastLine.includes('✓') || lastLine.includes('passed successfully')) {
      log(`${description} completed successfully`, 'success');
    } else if (lastLine.includes('warnings')) {
      log(`${description} completed with warnings`, 'warning');
    } else {
      log(`${description} completed`, 'success');
    }

    return { success: true, output };
  } catch (error) {
    log(`${description} failed: ${error.message}`, 'error');
    return { success: false, error };
  }
}

function createBackup() {
  const tokenFilePath = path.join(__dirname, '..', 'design-system', 'design-tokens.json');
  const timestamp = new Date().toISOString().replace(/[:.]/g, '-').slice(0, -5);
  const backupPath = tokenFilePath.replace('.json', `.sync-backup-${timestamp}.json`);

  try {
    fs.copyFileSync(tokenFilePath, backupPath);
    log(`Backup created: ${path.basename(backupPath)}`, 'success');
    return { success: true, backupPath };
  } catch (error) {
    log(`Failed to create backup: ${error.message}`, 'error');
    return { success: false, error };
  }
}

function summarizeResults(results) {
  const { validation, diff, tests, backup } = results;

  console.log(`\n${colors.bright}${colors.white}Token Sync Summary${colors.reset}`);
  console.log('━'.repeat(50));

  // Validation Results
  if (validation.success) {
    log('Token validation: PASSED', 'success');
  } else {
    log('Token validation: FAILED', 'error');
  }

  // Diff Results
  if (diff.success) {
    log('Token diff: GENERATED', 'success');
  } else {
    log('Token diff: FAILED', 'error');
  }

  // Test Results
  if (tests.success) {
    const output = tests.output;
    const passMatch = output.match(/(\d+) passed/);
    const failMatch = output.match(/(\d+) failed/);

    if (passMatch && !failMatch) {
      log(`Token tests: ${passMatch[1]} tests PASSED`, 'success');
    } else if (failMatch) {
      log(`Token tests: ${failMatch[1]} tests FAILED`, 'error');
    } else {
      log('Token tests: COMPLETED', 'success');
    }
  } else {
    log('Token tests: FAILED', 'error');
  }

  // Backup Results
  if (backup.success) {
    log('Backup: CREATED', 'success');
  } else {
    log('Backup: FAILED', 'error');
  }

  console.log('━'.repeat(50));

  // Overall Status
  const allPassed = validation.success && diff.success && tests.success && backup.success;
  if (allPassed) {
    log('🎉 All token operations completed successfully!', 'success');
    return 0;
  } else {
    log('❌ Some token operations failed. Check output above.', 'error');
    return 1;
  }
}

function checkPrerequisites() {
  log('Checking prerequisites...', 'step');

  const tokenFile = path.join(__dirname, '..', 'design-system', 'design-tokens.json');
  if (!fs.existsSync(tokenFile)) {
    log('design-tokens.json not found', 'error');
    return false;
  }

  const packageFile = path.join(__dirname, '..', 'package.json');
  if (!fs.existsSync(packageFile)) {
    log('package.json not found', 'error');
    return false;
  }

  // Check if required scripts exist
  const packageContent = JSON.parse(fs.readFileSync(packageFile, 'utf8'));
  const requiredScripts = ['tokens:validate', 'tokens:diff', 'test:tokens'];
  const missingScripts = requiredScripts.filter(script => !packageContent.scripts[script]);

  if (missingScripts.length > 0) {
    log(`Missing npm scripts: ${missingScripts.join(', ')}`, 'error');
    return false;
  }

  log('Prerequisites check passed', 'success');
  return true;
}

async function main() {
  console.log(`${colors.bright}${colors.cyan}🔄 CoreFlow360 V4 Token Sync${colors.reset}\n`);

  // Check prerequisites
  if (!checkPrerequisites()) {
    process.exit(1);
  }

  // Create backup first
  log('Creating backup...', 'step');
  const backupResult = createBackup();

  // Initialize results object
  const results = {
    backup: backupResult,
    validation: { success: false },
    diff: { success: false },
    tests: { success: false }
  };

  // Step 1: Validate tokens
  results.validation = runCommand('npm run tokens:validate', 'Validating token structure');

  // Step 2: Generate diff (don't fail on critical changes for sync)
  results.diff = runCommand('npm run tokens:diff', 'Generating token diff');

  // Step 3: Run tests
  results.tests = runCommand('npm run test:tokens', 'Running token tests');

  // Summarize and exit
  const exitCode = summarizeResults(results);

  if (exitCode === 0) {
    console.log(`\n${colors.green}🚀 Ready for development! Your tokens are validated and synced.${colors.reset}`);

    // Show what files were generated
    const generatedFiles = [
      'design-system/validation-results.json',
      'design-system/token-diff.json'
    ];

    console.log(`\n${colors.dim}Generated files:${colors.reset}`);
    generatedFiles.forEach(file => {
      if (fs.existsSync(file)) {
        console.log(`${colors.dim}  ✓ ${file}${colors.reset}`);
      }
    });

    console.log(`\n${colors.dim}Next steps:${colors.reset}`);
    console.log(`${colors.dim}  • Review validation-results.json for any warnings${colors.reset}`);
    console.log(`${colors.dim}  • Check token-diff.json for changes since last commit${colors.reset}`);
    console.log(`${colors.dim}  • Run individual commands for specific operations${colors.reset}`);
  } else {
    console.log(`\n${colors.red}🔧 Token sync completed with issues. Please review output above.${colors.reset}`);
  }

  process.exit(exitCode);
}

// Handle graceful shutdown
process.on('SIGINT', () => {
  console.log(`\n${colors.yellow}Token sync interrupted by user${colors.reset}`);
  process.exit(1);
});

process.on('uncaughtException', (error) => {
  console.error(`\n${colors.red}Unexpected error: ${error.message}${colors.reset}`);
  process.exit(1);
});

main().catch(error => {
  console.error(`\n${colors.red}Fatal error: ${error.message}${colors.reset}`);
  process.exit(1);
});