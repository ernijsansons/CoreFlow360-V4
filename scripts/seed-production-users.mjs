#!/usr/bin/env node
/**
 * Production User Seeding Script
 * Creates founder and test accounts in production database
 *
 * Usage:
 *   node scripts/seed-production-users.mjs
 *
 * WARNING: This script creates users in PRODUCTION database
 * Make sure you understand what this does before running
 */

import { execSync } from 'child_process';
import crypto from 'crypto';

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
  console.log(`\n${colors.magenta}${'='.repeat(60)}${colors.reset}`);
  console.log(`${colors.magenta}${title}${colors.reset}`);
  console.log(`${colors.magenta}${'='.repeat(60)}${colors.reset}\n`);
}

/**
 * Generate bcrypt hash for password
 * Note: This uses a simple hash for demonstration
 * In production, use proper bcrypt with salt
 */
function hashPassword(password) {
  // Using SHA-256 for demonstration (bcrypt would be better)
  return crypto.createHash('sha256').update(password).digest('hex');
}

/**
 * Execute D1 SQL command
 */
function executeSQL(sql, description) {
  try {
    log('info', description);

    // Escape single quotes in SQL
    const escapedSQL = sql.replace(/'/g, "''");

    // Execute via wrangler
    const command = `wrangler d1 execute coreflow360-agents --env production --command "${escapedSQL}"`;
    const output = execSync(command, { encoding: 'utf-8' });

    log('success', `${description} - Complete`);
    return { success: true, output };
  } catch (error) {
    log('error', `${description} - Failed: ${error.message}`);
    return { success: false, error: error.message };
  }
}

/**
 * Check if user exists
 */
function checkUserExists(email) {
  try {
    const sql = `SELECT id, email FROM users WHERE email = '${email}' LIMIT 1`;
    const result = executeSQL(sql, `Checking if ${email} exists`);

    // Check if result contains any data (rough check)
    return result.output && result.output.includes(email);
  } catch (error) {
    return false;
  }
}

/**
 * Create a user in the database
 */
function createUser(userData) {
  const { email, password, firstName, lastName, role, businessId } = userData;

  // Check if user already exists
  if (checkUserExists(email)) {
    log('warn', `User ${email} already exists - skipping`);
    return { success: true, existed: true };
  }

  const userId = crypto.randomUUID();
  const passwordHash = hashPassword(password);
  const now = new Date().toISOString();

  const sql = `
    INSERT INTO users (
      id, email, password_hash, first_name, last_name,
      role, business_id, email_verified,
      two_factor_enabled, created_at, updated_at
    ) VALUES (
      '${userId}',
      '${email}',
      '${passwordHash}',
      '${firstName}',
      '${lastName}',
      '${role}',
      '${businessId}',
      1,
      0,
      '${now}',
      '${now}'
    );
  `;

  const result = executeSQL(sql, `Creating user: ${email}`);

  if (result.success) {
    log('success', `User created: ${email} (ID: ${userId})`);
    log('info', `  Password: ${password}`);
  }

  return { ...result, userId };
}

/**
 * Create a business in the database
 */
function createBusiness(businessData) {
  const { name, industry } = businessData;
  const businessId = 'business-founder-001'; // Fixed ID for founder business
  const now = new Date().toISOString();

  // Check if business exists
  const checkSQL = `SELECT id FROM businesses WHERE id = '${businessId}' LIMIT 1`;
  const existingBusiness = executeSQL(checkSQL, `Checking if business ${name} exists`);

  if (existingBusiness.output && existingBusiness.output.includes(businessId)) {
    log('warn', `Business ${name} already exists - skipping`);
    return { success: true, existed: true, businessId };
  }

  const sql = `
    INSERT INTO businesses (
      id, name, industry, employee_count,
      subscription_tier, created_at, updated_at
    ) VALUES (
      '${businessId}',
      '${name}',
      '${industry}',
      '1-10',
      'enterprise',
      '${now}',
      '${now}'
    );
  `;

  const result = executeSQL(sql, `Creating business: ${name}`);

  if (result.success) {
    log('success', `Business created: ${name} (ID: ${businessId})`);
  }

  return { ...result, businessId };
}

/**
 * Main seeding function
 */
async function seedUsers() {
  section('CoreFlow360 V4 - Production User Seeding');

  log('warn', 'WARNING: This will create users in the PRODUCTION database');
  log('info', 'Database: coreflow360-agents (production)');

  // Wait 3 seconds for user to cancel if needed
  log('info', 'Starting in 3 seconds... (Ctrl+C to cancel)');
  await new Promise(resolve => setTimeout(resolve, 3000));

  // Step 1: Create founder business
  section('Step 1: Create Founder Business');

  const business = createBusiness({
    name: 'CoreFlow360 Founder LLC',
    industry: 'Technology'
  });

  if (!business.success && !business.existed) {
    log('error', 'Failed to create business - aborting');
    process.exit(1);
  }

  const businessId = business.businessId;

  // Step 2: Create founder account
  section('Step 2: Create Founder Account');

  const founder = createUser({
    email: 'founder@coreflow360.com',
    password: 'Founder2025!',
    firstName: 'Founder',
    lastName: 'Admin',
    role: 'owner',
    businessId
  });

  if (!founder.success && !founder.existed) {
    log('error', 'Failed to create founder account');
  }

  // Step 3: Create test users
  section('Step 3: Create Test Accounts');

  const testUsers = [
    {
      email: 'test@coreflow360.com',
      password: 'Test2025!',
      firstName: 'Test',
      lastName: 'User',
      role: 'user',
      businessId
    },
    {
      email: 'admin@coreflow360.com',
      password: 'Admin2025!',
      firstName: 'Admin',
      lastName: 'User',
      role: 'admin',
      businessId
    },
    {
      email: 'manager@coreflow360.com',
      password: 'Manager2025!',
      firstName: 'Manager',
      lastName: 'User',
      role: 'manager',
      businessId
    }
  ];

  let successCount = 0;
  let existedCount = 0;

  for (const userData of testUsers) {
    const result = createUser(userData);
    if (result.success) {
      if (result.existed) {
        existedCount++;
      } else {
        successCount++;
      }
    }
  }

  // Summary
  section('Seeding Summary');

  log('success', `Business: ${business.existed ? 'Already existed' : 'Created'}`);
  log('success', `Founder: ${founder.existed ? 'Already existed' : 'Created'}`);
  log('success', `Test Users: ${successCount} created, ${existedCount} already existed`);

  console.log(`\n${colors.cyan}╔═══════════════════════════════════════════════════════════╗${colors.reset}`);
  console.log(`${colors.cyan}║  Seeding Complete!                                        ║${colors.reset}`);
  console.log(`${colors.cyan}╚═══════════════════════════════════════════════════════════╝${colors.reset}`);

  console.log(`\n${colors.green}You can now log in with:${colors.reset}`);
  console.log(`  Email: founder@coreflow360.com`);
  console.log(`  Password: Founder2025!`);
  console.log(`\n${colors.blue}Test accounts:${colors.reset}`);
  console.log(`  test@coreflow360.com (Test2025!)`);
  console.log(`  admin@coreflow360.com (Admin2025!)`);
  console.log(`  manager@coreflow360.com (Manager2025!)`);

  console.log(`\n${colors.yellow}Next steps:${colors.reset}`);
  console.log(`  1. Test login at: https://main.coreflow360-frontend.pages.dev/login`);
  console.log(`  2. Run API tests: node scripts/test-api-comprehensive.mjs`);
  console.log(`  3. Navigate to dashboard: /dashboard\n`);
}

// Run seeding
seedUsers().catch(error => {
  log('error', `Seeding failed: ${error.message}`);
  console.error(error);
  process.exit(1);
});
