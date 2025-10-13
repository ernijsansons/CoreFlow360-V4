#!/usr/bin/env node
/**
 * Deployment Testing Script
 * Tests all critical deployment endpoints
 */

const BACKEND_URL = 'https://coreflow360-v4-prod.ernijs-ansons.workers.dev';
const FRONTEND_URL = 'https://main.coreflow360-frontend.pages.dev';

const colors = {
  green: '\x1b[32m',
  red: '\x1b[31m',
  yellow: '\x1b[33m',
  blue: '\x1b[34m',
  reset: '\x1b[0m'
};

function log(level, message) {
  const prefix = {
    success: `${colors.green}✓${colors.reset}`,
    error: `${colors.red}✗${colors.reset}`,
    warn: `${colors.yellow}⚠${colors.reset}`,
    info: `${colors.blue}ℹ${colors.reset}`
  }[level] || '';
  console.log(`${prefix} ${message}`);
}

async function testEndpoint(name, url, options = {}) {
  try {
    const response = await fetch(url, {
      ...options,
      headers: {
        ...options.headers,
        'Accept-Encoding': 'gzip, deflate, br'
      }
    });

    const data = await response.text();
    let json = null;

    try {
      json = JSON.parse(data);
    } catch (e) {
      // Not JSON, that's okay
    }

    if (response.ok) {
      log('success', `${name}: ${response.status} ${response.statusText}`);
      if (json) {
        console.log('  Response:', JSON.stringify(json, null, 2).substring(0, 200));
      }
      return { success: true, data: json || data, response };
    } else {
      log('error', `${name}: ${response.status} ${response.statusText}`);
      console.log('  Response:', data.substring(0, 200));
      return { success: false, error: data, response };
    }
  } catch (error) {
    log('error', `${name}: ${error.message}`);
    return { success: false, error: error.message };
  }
}

async function runTests() {
  console.log('\n🚀 CoreFlow360 V4 Deployment Testing\n');
  console.log(`Backend:  ${BACKEND_URL}`);
  console.log(`Frontend: ${FRONTEND_URL}\n`);

  const results = {
    passed: 0,
    failed: 0,
    warnings: 0
  };

  // Test 1: Health Endpoint
  console.log('\n📋 Phase 1: Basic Health Checks\n');
  const health = await testEndpoint('Health Check', `${BACKEND_URL}/health`);
  health.success ? results.passed++ : results.failed++;

  // Test 2: API Status
  const status = await testEndpoint('API Status', `${BACKEND_URL}/api/status`);
  status.success ? results.passed++ : results.failed++;

  // Test 3: Root endpoint
  const root = await testEndpoint('Root Endpoint', `${BACKEND_URL}/`);
  root.success ? results.passed++ : results.failed++;

  // Test 4: CORS preflight
  console.log('\n📋 Phase 2: CORS & Security\n');
  const cors = await testEndpoint('CORS Preflight', `${BACKEND_URL}/api/v1/auth/login`, {
    method: 'OPTIONS',
    headers: {
      'Origin': FRONTEND_URL,
      'Access-Control-Request-Method': 'POST',
      'Access-Control-Request-Headers': 'Content-Type'
    }
  });
  cors.success ? results.passed++ : results.failed++;

  // Test 5: Login endpoint (should fail without credentials, but should respond)
  console.log('\n📋 Phase 3: Authentication Endpoints\n');
  const login = await testEndpoint('Login Endpoint (no creds)', `${BACKEND_URL}/api/auth/login`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'Origin': FRONTEND_URL,
      'Accept-Encoding': 'identity'  // Disable compression for test
    },
    body: JSON.stringify({ email: 'test@example.com', password: 'test' })
  });
  // Expecting 400 (invalid credentials) - that's actually good
  if (login.response?.status === 400 || login.response?.status === 401) {
    log('success', 'Login endpoint properly rejects invalid credentials');
    results.passed++;
  } else {
    log('error', `Login endpoint unexpected status: ${login.response?.status}`);
    results.failed++;
  }

  // Test 6: Dashboard API endpoint
  const dashboardEndpoint = await testEndpoint('Dashboard API', `${BACKEND_URL}/api/dashboard`, {
    headers: {
      'Accept-Encoding': 'identity'  // Disable compression for test
    }
  });
  if (dashboardEndpoint.response?.status === 401 || dashboardEndpoint.response?.status === 403) {
    log('success', 'Dashboard endpoint properly requires authentication');
    results.passed++;
  } else {
    log('warn', `Dashboard endpoint status: ${dashboardEndpoint.response?.status} (expected 401/403)`);
    results.warnings++;
  }

  // Test 7: Register endpoint validation
  const register = await testEndpoint('Register Endpoint (invalid data)', `${BACKEND_URL}/api/auth/register`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'Origin': FRONTEND_URL,
      'Accept-Encoding': 'identity'
    },
    body: JSON.stringify({ email: 'invalid' })
  });
  if (register.response?.status === 400) {
    log('success', 'Register endpoint properly validates input');
    results.passed++;
  } else {
    log('warn', `Register endpoint status: ${register.response?.status} (expected 400)`);
    results.warnings++;
  }

  // Test 8: Frontend availability
  console.log('\n📋 Phase 4: Frontend Validation\n');
  const frontend = await testEndpoint('Frontend Root', FRONTEND_URL);
  frontend.success ? results.passed++ : results.failed++;

  // Test 9: Frontend assets
  const frontendAssets = await testEndpoint('Frontend Assets', `${FRONTEND_URL}/assets/index-EEI65xbZ.js`);
  frontendAssets.success ? results.passed++ : results.failed++;

  // Summary
  console.log('\n📊 Test Results Summary\n');
  console.log(`${colors.green}Passed:${colors.reset}   ${results.passed}`);
  console.log(`${colors.red}Failed:${colors.reset}   ${results.failed}`);
  console.log(`${colors.yellow}Warnings:${colors.reset} ${results.warnings}`);

  const total = results.passed + results.failed + results.warnings;
  const successRate = ((results.passed / total) * 100).toFixed(1);
  console.log(`\nSuccess Rate: ${successRate}%\n`);

  if (results.failed === 0) {
    log('success', 'All critical tests passed! ✨');
    process.exit(0);
  } else {
    log('error', `${results.failed} critical test(s) failed`);
    process.exit(1);
  }
}

runTests().catch(error => {
  log('error', `Test suite failed: ${error.message}`);
  process.exit(1);
});
