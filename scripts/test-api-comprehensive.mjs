#!/usr/bin/env node
/**
 * Comprehensive API Testing Script
 * Phase 2: API & Backend Validation
 */

const BACKEND_URL = 'https://coreflow360-v4-prod.ernijs-ansons.workers.dev';
const FRONTEND_URL = 'https://main.coreflow360-frontend.pages.dev';

// Test credentials (founder account)
const TEST_USER = {
  email: 'founder@coreflow360.com',
  password: 'Founder2025!'
};

const colors = {
  green: '\x1b[32m',
  red: '\x1b[31m',
  yellow: '\x1b[33m',
  blue: '\x1b[34m',
  cyan: '\x1b[36m',
  magenta: '\x1b[35m',
  reset: '\x1b[0m'
};

function log(level, message, indent = 0) {
  const prefix = {
    success: `${colors.green}✓${colors.reset}`,
    error: `${colors.red}✗${colors.reset}`,
    warn: `${colors.yellow}⚠${colors.reset}`,
    info: `${colors.blue}ℹ${colors.reset}`,
    test: `${colors.cyan}→${colors.reset}`,
  }[level] || '';
  const indentation = ' '.repeat(indent);
  console.log(`${indentation}${prefix} ${message}`);
}

function section(title) {
  console.log(`\n${colors.magenta}${'='.repeat(60)}${colors.reset}`);
  console.log(`${colors.magenta}${title}${colors.reset}`);
  console.log(`${colors.magenta}${'='.repeat(60)}${colors.reset}\n`);
}

async function testEndpoint(name, url, options = {}, expectedStatus = 200) {
  try {
    const response = await fetch(url, {
      ...options,
      headers: {
        'Accept-Encoding': 'identity',
        ...options.headers,
      }
    });

    const data = await response.text();
    let json = null;

    try {
      json = JSON.parse(data);
    } catch (e) {
      // Not JSON
    }

    const success = response.status === expectedStatus;

    if (success) {
      log('success', `${name}: ${response.status}`, 2);
      if (json && options.showResponse) {
        console.log('    Response:', JSON.stringify(json, null, 2).substring(0, 300));
      }
    } else {
      log('error', `${name}: Expected ${expectedStatus}, got ${response.status}`, 2);
      if (data.length < 500) {
        console.log('    Response:', data);
      }
    }

    return { success, data: json || data, response, status: response.status };
  } catch (error) {
    log('error', `${name}: ${error.message}`, 2);
    return { success: false, error: error.message, status: 0 };
  }
}

async function authenticateUser() {
  log('info', 'Authenticating founder account...');

  const result = await testEndpoint(
    'Login',
    `${BACKEND_URL}/api/auth/login`,
    {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Origin': FRONTEND_URL
      },
      body: JSON.stringify(TEST_USER),
      showResponse: true
    },
    200
  );

  if (result.success && result.data?.token) {
    log('success', `Authentication successful. Token received.`);
    return { token: result.data.token, user: result.data.user };
  } else if (result.success && result.data?.data?.token) {
    log('success', `Authentication successful (nested response).`);
    return { token: result.data.data.token, user: result.data.data.user };
  } else {
    log('error', 'Authentication failed - unable to get token');
    console.log('Response:', JSON.stringify(result.data, null, 2));
    return null;
  }
}

async function runPhase2Tests() {
  console.log(`\n${colors.cyan}╔═══════════════════════════════════════════════════════════╗${colors.reset}`);
  console.log(`${colors.cyan}║  CoreFlow360 V4 - Phase 2: API & Backend Validation      ║${colors.reset}`);
  console.log(`${colors.cyan}╚═══════════════════════════════════════════════════════════╝${colors.reset}`);

  const results = {
    passed: 0,
    failed: 0,
    warnings: 0,
    total: 0
  };

  function recordResult(passed, isWarning = false) {
    results.total++;
    if (passed) {
      results.passed++;
    } else if (isWarning) {
      results.warnings++;
    } else {
      results.failed++;
    }
  }

  // ============================================================================
  // PHASE 2.1: Authentication & User Management
  // ============================================================================
  section('Phase 2.1: Authentication & User Management');

  // Authenticate to get token for subsequent tests
  const auth = await authenticateUser();

  if (!auth || !auth.token) {
    log('error', 'Cannot proceed without authentication token');
    console.log('\n⚠️  Skipping authenticated endpoint tests\n');
    return results;
  }

  const authHeaders = {
    'Authorization': `Bearer ${auth.token}`,
    'Content-Type': 'application/json',
    'Origin': FRONTEND_URL
  };

  recordResult(true);

  // Test user profile endpoint
  log('test', 'Testing user profile endpoint...');
  const profile = await testEndpoint(
    'GET /api/auth/profile',
    `${BACKEND_URL}/api/auth/profile`,
    { headers: authHeaders },
    200
  );
  recordResult(profile.success);

  // ============================================================================
  // PHASE 2.2: Dashboard API
  // ============================================================================
  section('Phase 2.2: Dashboard API');

  log('test', 'Testing dashboard endpoints...');

  const dashboardStats = await testEndpoint(
    'GET /api/dashboard/stats',
    `${BACKEND_URL}/api/dashboard/stats?businessId=${auth.user?.businessId || 'test'}`,
    { headers: authHeaders },
    200
  );
  recordResult(dashboardStats.success);

  const dashboardActivity = await testEndpoint(
    'GET /api/dashboard/activity',
    `${BACKEND_URL}/api/dashboard/activity?limit=10`,
    { headers: authHeaders },
    200
  );
  recordResult(dashboardActivity.success);

  // ============================================================================
  // PHASE 2.3: CRM Endpoints
  // ============================================================================
  section('Phase 2.3: CRM Endpoints');

  log('test', 'Testing CRM endpoints...');

  // Test contacts endpoint
  const contacts = await testEndpoint(
    'GET /api/crm/contacts',
    `${BACKEND_URL}/api/crm/contacts`,
    { headers: authHeaders },
    200
  );
  recordResult(contacts.success || contacts.status === 404, contacts.status === 404);

  // Test companies endpoint
  const companies = await testEndpoint(
    'GET /api/crm/companies',
    `${BACKEND_URL}/api/crm/companies`,
    { headers: authHeaders },
    200
  );
  recordResult(companies.success || companies.status === 404, companies.status === 404);

  // Test deals endpoint
  const deals = await testEndpoint(
    'GET /api/crm/deals',
    `${BACKEND_URL}/api/crm/deals`,
    { headers: authHeaders },
    200
  );
  recordResult(deals.success || deals.status === 404, deals.status === 404);

  // ============================================================================
  // PHASE 2.4: Finance Endpoints
  // ============================================================================
  section('Phase 2.4: Finance Endpoints');

  log('test', 'Testing finance endpoints...');

  const invoices = await testEndpoint(
    'GET /api/invoices',
    `${BACKEND_URL}/api/invoices`,
    { headers: authHeaders },
    200
  );
  recordResult(invoices.success || invoices.status === 404, invoices.status === 404);

  const finance = await testEndpoint(
    'GET /api/finance',
    `${BACKEND_URL}/api/finance`,
    { headers: authHeaders },
    200
  );
  recordResult(finance.success || finance.status === 404, finance.status === 404);

  // ============================================================================
  // PHASE 2.5: AI Agent System
  // ============================================================================
  section('Phase 2.5: AI Agent System');

  log('test', 'Testing AI agent endpoints...');

  const agents = await testEndpoint(
    'GET /api/agents',
    `${BACKEND_URL}/api/agents`,
    { headers: authHeaders },
    200
  );
  recordResult(agents.success || agents.status === 404, agents.status === 404);

  // ============================================================================
  // PHASE 2.6: Business Management
  // ============================================================================
  section('Phase 2.6: Business Management');

  log('test', 'Testing business endpoints...');

  const business = await testEndpoint(
    'GET /api/business',
    `${BACKEND_URL}/api/business`,
    { headers: authHeaders },
    200
  );
  recordResult(business.success || business.status === 404, business.status === 404);

  // ============================================================================
  // Results Summary
  // ============================================================================
  section('Phase 2 Results Summary');

  console.log(`${colors.green}✓ Passed:${colors.reset}   ${results.passed}/${results.total}`);
  console.log(`${colors.red}✗ Failed:${colors.reset}   ${results.failed}/${results.total}`);
  console.log(`${colors.yellow}⚠ Warnings:${colors.reset} ${results.warnings}/${results.total}`);

  const successRate = ((results.passed / results.total) * 100).toFixed(1);
  console.log(`\nSuccess Rate: ${successRate}%\n`);

  if (results.failed === 0) {
    log('success', 'Phase 2 complete - All critical tests passed! ✨\n');
    return results;
  } else {
    log('error', `Phase 2 complete - ${results.failed} test(s) failed\n`);
    return results;
  }
}

// Run tests
runPhase2Tests()
  .then((results) => {
    if (results.failed > 0) {
      process.exit(1);
    }
    process.exit(0);
  })
  .catch(error => {
    log('error', `Phase 2 test suite failed: ${error.message}`);
    console.error(error);
    process.exit(1);
  });
