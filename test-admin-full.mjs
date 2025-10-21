/**
 * Complete Admin Dashboard Test
 * Creates admin user and tests all endpoints
 */

const API_BASE = 'http://127.0.0.1:8790';

// Colors
const GREEN = '\x1b[32m';
const RED = '\x1b[31m';
const YELLOW = '\x1b[33m';
const BLUE = '\x1b[34m';
const CYAN = '\x1b[36m';
const RESET = '\x1b[0m';

let testResults = { passed: 0, failed: 0, total: 0 };

async function apiCall(method, endpoint, body = null, customHeaders = {}) {
  const url = `${API_BASE}${endpoint}`;
  const headers = { 'Content-Type': 'application/json', ...customHeaders };
  const options = { method, headers };
  if (body && (method === 'POST' || method === 'PUT' || method === 'PATCH')) {
    options.body = JSON.stringify(body);
  }

  try {
    const response = await fetch(url, options);
    const data = await response.json();
    return { status: response.status, ok: response.ok, data };
  } catch (error) {
    return { status: 0, ok: false, error: error.message };
  }
}

function reportTest(name, passed, details = '') {
  testResults.total++;
  if (passed) {
    testResults.passed++;
    console.log(`${GREEN}✓${RESET} ${name}`);
    if (details) console.log(`  ${CYAN}${details}${RESET}`);
  } else {
    testResults.failed++;
    console.log(`${RED}✗${RESET} ${name}`);
    if (details) console.log(`  ${YELLOW}${details}${RESET}`);
  }
}

function section(title) {
  console.log(`\n${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}`);
  console.log(`${BLUE}${title}${RESET}`);
  console.log(`${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}\n`);
}

async function runTests() {
  console.log(`${CYAN}╔═══════════════════════════════════════════╗${RESET}`);
  console.log(`${CYAN}║  ADMIN DASHBOARD FULL TEST SUITE          ║${RESET}`);
  console.log(`${CYAN}╚═══════════════════════════════════════════╝${RESET}\n`);

  // ===========================================================================
  // SETUP
  // ===========================================================================
  section('SETUP: Create Admin User');

  const timestamp = Date.now();
  let registerResult = await apiCall('POST', '/api/auth/register', {
    email: `admin${timestamp}@test.com`,
    password: 'AdminPass123!',
    firstName: 'Admin',
    lastName: 'User',
    businessName: 'Admin Business',
    acceptTerms: true
  });

  let adminToken, adminUserId;
  if (registerResult.status === 201) {
    adminToken = registerResult.data.token;
    adminUserId = registerResult.data.user?.id;
    reportTest('Admin user registered', true, `User ID: ${adminUserId}`);
  } else {
    reportTest('Admin user registration', false, `Status: ${registerResult.status}`);
    console.log(`\n${RED}Cannot proceed. Exiting...${RESET}\n`);
    return;
  }

  // Manually set admin role via database
  console.log(`\n${YELLOW}Setting user role to 'admin' in database...${RESET}`);
  const dbResult = await fetch(`${API_BASE}/test-set-admin`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ userId: adminUserId })
  });

  if (dbResult.ok) {
    console.log(`${GREEN}User role set to admin successfully${RESET}`);
  } else {
    console.log(`${YELLOW}Note: Manual database update may be needed to set role='admin' for user ${adminUserId}${RESET}`);
  }

  // ===========================================================================
  // TEST 1: ANALYTICS ENDPOINTS
  // ===========================================================================
  section('TEST 1: Admin Analytics Endpoints');

  // Executive KPIs
  let kpisResult = await apiCall('GET', '/api/v1/admin/analytics/kpis', null, {
    'X-User-ID': adminUserId,
    'Authorization': `Bearer ${adminToken}`
  });
  reportTest('GET /api/v1/admin/analytics/kpis', kpisResult.status === 200,
    kpisResult.status === 200 ? `Total Revenue: $${kpisResult.data?.data?.kpis?.totalRevenue || 0}` : `Status: ${kpisResult.status}`);

  // Real-time Monitoring
  let realtimeResult = await apiCall('GET', '/api/v1/admin/analytics/realtime', null, {
    'X-User-ID': adminUserId,
    'Authorization': `Bearer ${adminToken}`
  });
  reportTest('GET /api/v1/admin/analytics/realtime', realtimeResult.status === 200,
    realtimeResult.status === 200 ? `Active Users: ${realtimeResult.data?.data?.realtime?.activeUsers || 0}` : `Status: ${realtimeResult.status}`);

  // Business Intelligence
  let biResult = await apiCall('GET', '/api/v1/admin/analytics/business-intelligence', null, {
    'X-User-ID': adminUserId,
    'Authorization': `Bearer ${adminToken}`
  });
  reportTest('GET /api/v1/admin/analytics/business-intelligence', biResult.status === 200,
    biResult.status === 200 ? `Revenue Trend: ${biResult.data?.data?.revenueTrend?.length || 0} months` : `Status: ${biResult.status}`);

  // System Analytics
  let systemResult = await apiCall('GET', '/api/v1/admin/analytics/system', null, {
    'X-User-ID': adminUserId,
    'Authorization': `Bearer ${adminToken}`
  });
  reportTest('GET /api/v1/admin/analytics/system', systemResult.status === 200,
    systemResult.status === 200 ? `DB Tables: ${systemResult.data?.data?.database?.tables?.length || 0}` : `Status: ${systemResult.status}`);

  // Security Analytics
  let securityResult = await apiCall('GET', '/api/v1/admin/analytics/security', null, {
    'X-User-ID': adminUserId,
    'Authorization': `Bearer ${adminToken}`
  });
  reportTest('GET /api/v1/admin/analytics/security', securityResult.status === 200,
    securityResult.status === 200 ? `Failed Logins: ${securityResult.data?.data?.security?.failedLoginAttempts || 0}` : `Status: ${securityResult.status}`);

  // ===========================================================================
  // TEST 2: MANAGEMENT ENDPOINTS
  // ===========================================================================
  section('TEST 2: Admin Management Endpoints');

  // List Users
  let usersResult = await apiCall('GET', '/api/v1/admin/users', null, {
    'X-User-ID': adminUserId,
    'Authorization': `Bearer ${adminToken}`
  });
  reportTest('GET /api/v1/admin/users', usersResult.status === 200,
    usersResult.status === 200 ? `Total Users: ${usersResult.data?.data?.pagination?.total || 0}` : `Status: ${usersResult.status}`);

  // List Users with Pagination
  let usersPaginated = await apiCall('GET', '/api/v1/admin/users?page=1&limit=10', null, {
    'X-User-ID': adminUserId,
    'Authorization': `Bearer ${adminToken}`
  });
  reportTest('GET /api/v1/admin/users with pagination', usersPaginated.status === 200,
    usersPaginated.status === 200 ? `Showing ${usersPaginated.data?.data?.users?.length || 0} users` : `Status: ${usersPaginated.status}`);

  // Get User Details
  let userDetail = await apiCall('GET', `/api/v1/admin/users/${adminUserId}`, null, {
    'X-User-ID': adminUserId,
    'Authorization': `Bearer ${adminToken}`
  });
  reportTest('GET /api/v1/admin/users/:id', userDetail.status === 200,
    userDetail.status === 200 ? `Businesses: ${userDetail.data?.data?.businesses?.length || 0}` : `Status: ${userDetail.status}`);

  // List Businesses
  let businesses = await apiCall('GET', '/api/v1/admin/businesses', null, {
    'X-User-ID': adminUserId,
    'Authorization': `Bearer ${adminToken}`
  });
  reportTest('GET /api/v1/admin/businesses', businesses.status === 200,
    businesses.status === 200 ? `Total Businesses: ${businesses.data?.data?.pagination?.total || 0}` : `Status: ${businesses.status}`);

  // Query Audit Logs
  let auditLogs = await apiCall('GET', '/api/v1/admin/audit-logs', null, {
    'X-User-ID': adminUserId,
    'Authorization': `Bearer ${adminToken}`
  });
  reportTest('GET /api/v1/admin/audit-logs', auditLogs.status === 200,
    auditLogs.status === 200 ? `Audit Entries: ${auditLogs.data?.data?.logs?.length || 0}` : `Status: ${auditLogs.status}`);

  // List Sessions
  let sessions = await apiCall('GET', '/api/v1/admin/sessions', null, {
    'X-User-ID': adminUserId,
    'Authorization': `Bearer ${adminToken}`
  });
  reportTest('GET /api/v1/admin/sessions', sessions.status === 200,
    sessions.status === 200 ? `Active Sessions: ${sessions.data?.data?.sessions?.length || 0}` : `Status: ${sessions.status}`);

  // ===========================================================================
  // TEST 3: DATA VALIDATION
  // ===========================================================================
  section('TEST 3: Data Quality Checks');

  if (kpisResult.status === 200) {
    const kpis = kpisResult.data?.data?.kpis;
    reportTest('KPIs have all required fields',
      kpis && 'totalBusinesses' in kpis && 'activeUsers' in kpis && 'systemHealthScore' in kpis,
      `Health Score: ${kpis?.systemHealthScore}%`);
  }

  if (systemResult.status === 200) {
    const db = systemResult.data?.data?.database;
    reportTest('System analytics has database info',
      db && db.tables && db.recordCounts,
      `Users in DB: ${db?.recordCounts?.users || 0}`);
  }

  if (usersResult.status === 200) {
    const pagination = usersResult.data?.data?.pagination;
    reportTest('User list has pagination',
      pagination && 'page' in pagination && 'total' in pagination,
      `Page ${pagination?.page} of ${pagination?.totalPages}`);
  }

  // ===========================================================================
  // SUMMARY
  // ===========================================================================
  console.log(`\n${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}`);
  console.log(`${BLUE}TEST SUMMARY${RESET}`);
  console.log(`${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}`);
  console.log(`Total Tests:  ${testResults.total}`);
  console.log(`${GREEN}Passed:       ${testResults.passed}${RESET}`);
  console.log(`${RED}Failed:       ${testResults.failed}${RESET}`);
  console.log(`${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}\n`);

  const successRate = testResults.total > 0
    ? ((testResults.passed / testResults.total) * 100).toFixed(2)
    : 0;

  console.log(`Success Rate: ${successRate}%\n`);

  return testResults.failed === 0 ? 0 : 1;
}

runTests().then(exitCode => {
  process.exit(exitCode);
}).catch(error => {
  console.error(`${RED}Fatal error:${RESET}`, error);
  process.exit(1);
});
