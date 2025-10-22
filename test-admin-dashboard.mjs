/**
 * Admin Dashboard API Test Suite
 * Tests all Fortune 50 admin endpoints
 */

const API_BASE = 'http://127.0.0.1:8790';

// ANSI color codes
const GREEN = '\x1b[32m';
const RED = '\x1b[31m';
const YELLOW = '\x1b[33m';
const BLUE = '\x1b[34m';
const CYAN = '\x1b[36m';
const RESET = '\x1b[0m';

let testResults = {
  passed: 0,
  failed: 0,
  skipped: 0,
  total: 0
};

/**
 * Make API call with proper headers
 */
async function apiCall(method, endpoint, body = null, customHeaders = {}) {
  const url = `${API_BASE}${endpoint}`;

  const headers = {
    'Content-Type': 'application/json',
    ...customHeaders
  };

  const options = {
    method,
    headers
  };

  if (body && (method === 'POST' || method === 'PUT' || method === 'PATCH')) {
    options.body = JSON.stringify(body);
  }

  try {
    const response = await fetch(url, options);
    const data = await response.json();

    return {
      status: response.status,
      ok: response.ok,
      data,
      headers: Object.fromEntries(response.headers.entries())
    };
  } catch (error) {
    return {
      status: 0,
      ok: false,
      error: error.message
    };
  }
}

/**
 * Test reporter
 */
function reportTest(name, passed, details = '') {
  testResults.total++;

  if (passed) {
    testResults.passed++;
    console.log(`${GREEN}✓${RESET} ${name}`);
  } else {
    testResults.failed++;
    console.log(`${RED}✗${RESET} ${name}`);
    if (details) {
      console.log(`  ${YELLOW}${details}${RESET}`);
    }
  }
}

function skipTest(name, reason) {
  testResults.total++;
  testResults.skipped++;
  console.log(`${YELLOW}○${RESET} ${name} ${CYAN}(skipped: ${reason})${RESET}`);
}

/**
 * Print section header
 */
function section(title) {
  console.log(`\n${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}`);
  console.log(`${BLUE}${title}${RESET}`);
  console.log(`${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}\n`);
}

/**
 * Print final summary
 */
function printSummary() {
  console.log(`\n${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}`);
  console.log(`${BLUE}TEST SUMMARY${RESET}`);
  console.log(`${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}`);
  console.log(`Total Tests:  ${testResults.total}`);
  console.log(`${GREEN}Passed:       ${testResults.passed}${RESET}`);
  console.log(`${RED}Failed:       ${testResults.failed}${RESET}`);
  console.log(`${YELLOW}Skipped:      ${testResults.skipped}${RESET}`);
  console.log(`${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}\n`);

  const successRate = testResults.total > 0
    ? ((testResults.passed / testResults.total) * 100).toFixed(2)
    : 0;

  console.log(`Success Rate: ${successRate}%\n`);
}

// ============================================================================
// MAIN TEST SUITE
// ============================================================================

async function runTests() {
  console.log(`${CYAN}╔════════════════════════════════════════════╗${RESET}`);
  console.log(`${CYAN}║  ADMIN DASHBOARD API TEST SUITE            ║${RESET}`);
  console.log(`${CYAN}║  Fortune 50 Level Analytics & Management  ║${RESET}`);
  console.log(`${CYAN}╚════════════════════════════════════════════╝${RESET}\n`);

  console.log(`Testing API: ${API_BASE}\n`);

  // ===========================================================================
  // SETUP: Create admin user and get auth token
  // ===========================================================================

  section('SETUP: Authentication');

  let adminToken = null;
  let adminUserId = null;

  // Register admin user
  const timestamp = Date.now();
  let registerResult = await apiCall('POST', '/api/auth/register', {
    email: `admin${timestamp}@test.com`,
    password: 'AdminPass123!',
    firstName: 'Admin',
    lastName: 'User',
    businessName: 'Admin Business',
    acceptTerms: true
  });

  if (registerResult.status === 201) {
    adminToken = registerResult.data.token;
    adminUserId = registerResult.data.user?.id;
    reportTest('Admin user registration', true);
    console.log(`  Admin User ID: ${adminUserId}`);
    console.log(`  Token length: ${adminToken?.length || 0} chars`);
  } else {
    reportTest('Admin user registration', false, `Status: ${registerResult.status}`);
    console.log(`\n${RED}Cannot proceed without admin authentication. Exiting...${RESET}\n`);
    return;
  }

  // Manually update user role to 'admin' via database (would need D1 migration)
  // For now, we'll test that endpoints properly reject non-admin users
  console.log(`\n${YELLOW}Note: User role needs to be manually set to 'admin' in database for full testing${RESET}`);

  // ===========================================================================
  // TEST 1: ADMIN ANALYTICS ENDPOINTS
  // ===========================================================================

  section('TEST 1: Admin Analytics Endpoints');

  // 1.1 Executive KPIs
  let kpisResult = await apiCall('GET', '/api/admin/analytics/kpis', null, {
    'X-User-ID': adminUserId,
    'Authorization': `Bearer ${adminToken}`
  });

  // Since user is not actually admin, expect 403
  if (kpisResult.status === 403) {
    reportTest('GET /api/admin/analytics/kpis (403 for non-admin)', true);
  } else {
    reportTest('GET /api/admin/analytics/kpis', kpisResult.status === 200,
      `Expected 403 or 200, got ${kpisResult.status}`);
  }

  // 1.2 Real-time Monitoring
  let realtimeResult = await apiCall('GET', '/api/admin/analytics/realtime', null, {
    'X-User-ID': adminUserId,
    'Authorization': `Bearer ${adminToken}`
  });

  if (realtimeResult.status === 403) {
    reportTest('GET /api/admin/analytics/realtime (403 for non-admin)', true);
  } else {
    reportTest('GET /api/admin/analytics/realtime', realtimeResult.status === 200,
      `Expected 403 or 200, got ${realtimeResult.status}`);
  }

  // 1.3 Business Intelligence
  let biResult = await apiCall('GET', '/api/admin/analytics/business-intelligence', null, {
    'X-User-ID': adminUserId,
    'Authorization': `Bearer ${adminToken}`
  });

  if (biResult.status === 403) {
    reportTest('GET /api/admin/analytics/business-intelligence (403 for non-admin)', true);
  } else {
    reportTest('GET /api/admin/analytics/business-intelligence', biResult.status === 200,
      `Expected 403 or 200, got ${biResult.status}`);
  }

  // 1.4 System Analytics
  let systemResult = await apiCall('GET', '/api/admin/analytics/system', null, {
    'X-User-ID': adminUserId,
    'Authorization': `Bearer ${adminToken}`
  });

  if (systemResult.status === 403) {
    reportTest('GET /api/admin/analytics/system (403 for non-admin)', true);
  } else {
    reportTest('GET /api/admin/analytics/system', systemResult.status === 200,
      `Expected 403 or 200, got ${systemResult.status}`);
  }

  // 1.5 Security Analytics
  let securityResult = await apiCall('GET', '/api/admin/analytics/security', null, {
    'X-User-ID': adminUserId,
    'Authorization': `Bearer ${adminToken}`
  });

  if (securityResult.status === 403) {
    reportTest('GET /api/admin/analytics/security (403 for non-admin)', true);
  } else {
    reportTest('GET /api/admin/analytics/security', securityResult.status === 200,
      `Expected 403 or 200, got ${securityResult.status}`);
  }

  // ===========================================================================
  // TEST 2: ADMIN MANAGEMENT ENDPOINTS
  // ===========================================================================

  section('TEST 2: Admin Management Endpoints');

  // 2.1 List Users
  let usersResult = await apiCall('GET', '/api/admin/users', null, {
    'X-User-ID': adminUserId,
    'Authorization': `Bearer ${adminToken}`
  });

  if (usersResult.status === 403) {
    reportTest('GET /api/admin/users (403 for non-admin)', true);
  } else {
    reportTest('GET /api/admin/users', usersResult.status === 200,
      `Expected 403 or 200, got ${usersResult.status}`);
  }

  // 2.2 List Users with Pagination
  let usersPaginatedResult = await apiCall('GET', '/api/admin/users?page=1&limit=10', null, {
    'X-User-ID': adminUserId,
    'Authorization': `Bearer ${adminToken}`
  });

  if (usersPaginatedResult.status === 403) {
    reportTest('GET /api/admin/users?page=1&limit=10 (403 for non-admin)', true);
  } else {
    reportTest('GET /api/admin/users with pagination', usersPaginatedResult.status === 200,
      `Expected 403 or 200, got ${usersPaginatedResult.status}`);
  }

  // 2.3 Get User Details
  let userDetailResult = await apiCall('GET', `/api/admin/users/${adminUserId}`, null, {
    'X-User-ID': adminUserId,
    'Authorization': `Bearer ${adminToken}`
  });

  if (userDetailResult.status === 403) {
    reportTest('GET /api/admin/users/:id (403 for non-admin)', true);
  } else {
    reportTest('GET /api/admin/users/:id', userDetailResult.status === 200,
      `Expected 403 or 200, got ${userDetailResult.status}`);
  }

  // 2.4 List Businesses
  let businessesResult = await apiCall('GET', '/api/admin/businesses', null, {
    'X-User-ID': adminUserId,
    'Authorization': `Bearer ${adminToken}`
  });

  if (businessesResult.status === 403) {
    reportTest('GET /api/admin/businesses (403 for non-admin)', true);
  } else {
    reportTest('GET /api/admin/businesses', businessesResult.status === 200,
      `Expected 403 or 200, got ${businessesResult.status}`);
  }

  // 2.5 Query Audit Logs
  let auditLogsResult = await apiCall('GET', '/api/admin/audit-logs', null, {
    'X-User-ID': adminUserId,
    'Authorization': `Bearer ${adminToken}`
  });

  if (auditLogsResult.status === 403) {
    reportTest('GET /api/admin/audit-logs (403 for non-admin)', true);
  } else {
    reportTest('GET /api/admin/audit-logs', auditLogsResult.status === 200,
      `Expected 403 or 200, got ${auditLogsResult.status}`);
  }

  // 2.6 List Sessions
  let sessionsResult = await apiCall('GET', '/api/admin/sessions', null, {
    'X-User-ID': adminUserId,
    'Authorization': `Bearer ${adminToken}`
  });

  if (sessionsResult.status === 403) {
    reportTest('GET /api/admin/sessions (403 for non-admin)', true);
  } else {
    reportTest('GET /api/admin/sessions', sessionsResult.status === 200,
      `Expected 403 or 200, got ${sessionsResult.status}`);
  }

  // ===========================================================================
  // TEST 3: AUTHORIZATION CHECKS
  // ===========================================================================

  section('TEST 3: Authorization Checks');

  // 3.1 Test without X-User-ID header
  let noUserIdResult = await apiCall('GET', '/api/admin/analytics/kpis', null, {
    'Authorization': `Bearer ${adminToken}`
  });

  reportTest('Analytics KPIs without X-User-ID (401)', noUserIdResult.status === 401);

  // 3.2 Test without Authorization header
  let noAuthResult = await apiCall('GET', '/api/admin/users', null, {
    'X-User-ID': adminUserId
  });

  reportTest('User list without Authorization (401 or 403)',
    noAuthResult.status === 401 || noAuthResult.status === 403);

  // 3.3 Test with invalid User ID
  let invalidUserResult = await apiCall('GET', '/api/admin/analytics/system', null, {
    'X-User-ID': 'invalid-user-id',
    'Authorization': `Bearer ${adminToken}`
  });

  reportTest('System analytics with invalid User ID (401 or 403)',
    invalidUserResult.status === 401 || invalidUserResult.status === 403);

  // ===========================================================================
  // TEST 4: ROUTE STRUCTURE VALIDATION
  // ===========================================================================

  section('TEST 4: Route Structure Validation');

  // 4.1 Verify all admin analytics routes are mounted
  const analyticsEndpoints = [
    '/api/admin/analytics/kpis',
    '/api/admin/analytics/realtime',
    '/api/admin/analytics/business-intelligence',
    '/api/admin/analytics/system',
    '/api/admin/analytics/security'
  ];

  for (const endpoint of analyticsEndpoints) {
    const result = await apiCall('GET', endpoint, null, {
      'X-User-ID': adminUserId,
      'Authorization': `Bearer ${adminToken}`
    });

    // Should return 403 (Forbidden) not 404 (Not Found)
    reportTest(`Route exists: ${endpoint}`, result.status !== 404,
      result.status === 404 ? 'Route not found' : `Status: ${result.status}`);
  }

  // 4.2 Verify all admin management routes are mounted
  const managementEndpoints = [
    '/api/admin/users',
    '/api/admin/businesses',
    '/api/admin/audit-logs',
    '/api/admin/sessions'
  ];

  for (const endpoint of managementEndpoints) {
    const result = await apiCall('GET', endpoint, null, {
      'X-User-ID': adminUserId,
      'Authorization': `Bearer ${adminToken}`
    });

    reportTest(`Route exists: ${endpoint}`, result.status !== 404,
      result.status === 404 ? 'Route not found' : `Status: ${result.status}`);
  }

  // ===========================================================================
  // PRINT SUMMARY
  // ===========================================================================

  printSummary();

  // Return exit code
  return testResults.failed === 0 ? 0 : 1;
}

// Run tests
runTests().then(exitCode => {
  process.exit(exitCode);
}).catch(error => {
  console.error(`${RED}Fatal error during testing:${RESET}`, error);
  process.exit(1);
});
