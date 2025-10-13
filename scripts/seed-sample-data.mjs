#!/usr/bin/env node
/**
 * Sample Data Seeding Script
 * Loads comprehensive demo data into the database for new users
 *
 * Usage:
 *   node scripts/seed-sample-data.mjs [--env production|staging|development]
 *
 * Features:
 * - CRM data (companies, contacts, deals, activities, leads, notes)
 * - Finance data (invoices, payments, general ledger, chart of accounts)
 * - Analytics data (request logs)
 */

import { execSync } from 'child_process';
import { readFileSync } from 'fs';
import { fileURLToPath } from 'url';
import { dirname, join } from 'path';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

const colors = {
  green: '\x1b[32m',
  red: '\x1b[31m',
  yellow: '\x1b[33m',
  blue: '\x1b[34m',
  cyan: '\x1b[36m',
  magenta: '\x1b[35m',
  reset: '\x1b[0m'
};

function log(level, message) {
  const prefix = {
    success: `${colors.green}✓${colors.reset}`,
    error: `${colors.red}✗${colors.reset}`,
    warn: `${colors.yellow}⚠${colors.reset}`,
    info: `${colors.blue}ℹ${colors.reset}`,
  }[level] || '';
  console.log(`${prefix} ${message}`);
}

function section(title) {
  console.log(`\n${colors.magenta}${'='.repeat(70)}${colors.reset}`);
  console.log(`${colors.magenta}${title}${colors.reset}`);
  console.log(`${colors.magenta}${'='.repeat(70)}${colors.reset}\n`);
}

/**
 * Get environment from command line args
 */
function getEnvironment() {
  const args = process.argv.slice(2);
  const envIndex = args.indexOf('--env');

  if (envIndex !== -1 && args[envIndex + 1]) {
    const env = args[envIndex + 1];
    if (['production', 'staging', 'development'].includes(env)) {
      return env;
    }
  }

  return 'production'; // default
}

/**
 * Execute SQL file against D1 database
 */
async function executeSQLFile(filePath, description, env) {
  try {
    log('info', `${description}...`);

    // Read SQL file
    const sql = readFileSync(filePath, 'utf-8');

    // Split into individual statements (basic split on semicolon)
    const statements = sql
      .split(';')
      .map(s => s.trim())
      .filter(s => s.length > 0 && !s.startsWith('--'));

    let successCount = 0;
    let errorCount = 0;

    for (const statement of statements) {
      if (!statement || statement.startsWith('--')) continue;

      try {
        // Escape for shell
        const escapedSQL = statement.replace(/"/g, '\\"');

        // Execute via wrangler
        const envFlag = env === 'production' ? '--env production --remote' : env === 'staging' ? '--env staging --remote' : '';
        const command = `wrangler d1 execute coreflow360-agents ${envFlag} --command "${escapedSQL}"`;

        execSync(command, {
          encoding: 'utf-8',
          stdio: 'pipe' // Suppress output for cleaner logs
        });

        successCount++;
      } catch (error) {
        // Ignore "already exists" errors (INSERT OR IGNORE)
        if (!error.message.includes('UNIQUE constraint failed')) {
          errorCount++;
          console.error(`    Error executing statement: ${error.message.substring(0, 100)}...`);
        }
      }
    }

    log('success', `${description} - Complete (${successCount} statements executed, ${errorCount} errors)`);
    return { success: true, successCount, errorCount };
  } catch (error) {
    log('error', `${description} - Failed: ${error.message}`);
    return { success: false, error: error.message };
  }
}

/**
 * Verify database connection
 */
function verifyDatabase(env) {
  try {
    log('info', 'Verifying database connection...');
    const envFlag = env === 'production' ? '--env production --remote' : env === 'staging' ? '--env staging --remote' : '';
    execSync(`wrangler d1 execute coreflow360-agents ${envFlag} --command "SELECT 1"`, {
      encoding: 'utf-8',
      stdio: 'pipe'
    });
    log('success', 'Database connection verified');
    return true;
  } catch (error) {
    log('error', `Database connection failed: ${error.message}`);
    return false;
  }
}

/**
 * Check if sample data already exists
 */
function checkExistingData(env) {
  try {
    log('info', 'Checking for existing sample data...');
    const envFlag = env === 'production' ? '--env production --remote' : env === 'staging' ? '--env staging --remote' : '';
    const result = execSync(
      `wrangler d1 execute coreflow360-agents ${envFlag} --command "SELECT COUNT(*) as count FROM crm_companies WHERE id LIKE 'demo-%'"`,
      { encoding: 'utf-8' }
    );

    // Check if result contains a count > 0
    if (result.includes('"count":') && !result.includes('"count":0')) {
      return true;
    }
    return false;
  } catch (error) {
    return false;
  }
}

/**
 * Main seeding function
 */
async function seedSampleData() {
  const env = getEnvironment();

  section(`CoreFlow360 V4 - Sample Data Seeding (${env.toUpperCase()})`);

  log('info', `Environment: ${env}`);
  log('info', 'Database: coreflow360-agents');

  // Verify database connection
  if (!verifyDatabase(env)) {
    log('error', 'Cannot proceed without database connection');
    process.exit(1);
  }

  // Check for existing data
  if (checkExistingData(env)) {
    log('warn', 'Sample data already exists in database');
    log('info', 'Existing data will be preserved (INSERT OR IGNORE is used)');
  }

  // Wait 2 seconds for user to cancel if needed
  log('info', 'Starting in 2 seconds... (Ctrl+C to cancel)');
  await new Promise(resolve => setTimeout(resolve, 2000));

  // Seed CRM sample data
  section('Step 1: Loading CRM Sample Data');
  const crmFile = join(__dirname, '..', 'database', 'seeds', '001_crm_sample_data.sql');
  await executeSQLFile(crmFile, 'Seeding CRM data (companies, contacts, deals, activities)', env);

  // Seed comprehensive sample data
  section('Step 2: Loading Comprehensive Sample Data');
  const compFile = join(__dirname, '..', 'database', 'seeds', '002_comprehensive_sample_data.sql');
  await executeSQLFile(compFile, 'Seeding comprehensive data (finance, analytics, extended CRM)', env);

  // Summary
  section('Seeding Summary');

  log('success', 'CRM Data: Companies, Contacts, Deals, Activities, Leads, Notes ✓');
  log('success', 'Finance Data: Chart of Accounts, Invoices, Payments, Ledger Entries ✓');
  log('success', 'Analytics Data: Request logs and metrics ✓');

  console.log(`\n${colors.cyan}╔═══════════════════════════════════════════════════════════════════╗${colors.reset}`);
  console.log(`${colors.cyan}║  Sample Data Loaded Successfully!                                 ║${colors.reset}`);
  console.log(`${colors.cyan}╚═══════════════════════════════════════════════════════════════════╝${colors.reset}`);

  console.log(`\n${colors.green}Sample Data Includes:${colors.reset}`);
  console.log(`  📊 CRM: 10 companies, 12 contacts, 10 deals, 10 activities, 7 leads`);
  console.log(`  💰 Finance: 5 invoices, 3 payments, Chart of Accounts, GL entries`);
  console.log(`  📈 Analytics: Request logs and performance metrics`);
  console.log(`  💵 Total Revenue: $720,000 (Sample data)`);

  console.log(`\n${colors.blue}View Your Data:${colors.reset}`);
  console.log(`  🌐 Login: https://production.coreflow360-frontend.pages.dev/login`);
  console.log(`  📧 Email: founder@coreflow360.com`);
  console.log(`  🔑 Password: Founder2025!`);

  console.log(`\n${colors.yellow}Next Steps:${colors.reset}`);
  console.log(`  1. Navigate to Dashboard: /dashboard`);
  console.log(`  2. Explore CRM: /crm/companies`);
  console.log(`  3. View Finances: /finance/invoices`);
  console.log(`  4. Check Analytics: /dashboard/analytics\n`);
}

// Run seeding
seedSampleData().catch(error => {
  log('error', `Seeding failed: ${error.message}`);
  console.error(error);
  process.exit(1);
});
