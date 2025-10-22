#!/usr/bin/env node
/**
 * CoreFlow360 V4 - COMPREHENSIVE API ENDPOINT AUDIT
 * Tests ALL API endpoints with real business logic
 */

const BACKEND_URL = 'http://127.0.0.1:8790';
const TEST_USER = {
  email: 'test@coreflow360.dev',
  password: 'TestPass123!'
};

let authToken = null;

// Helper function to make authenticated requests
async function apiCall(method, endpoint, body = null) {
  const headers = {
    'Content-Type': 'application/json',
  };

  if (authToken) {
    headers['Authorization'] = `Bearer ${authToken}`;
  }

  const options = {
    method,
    headers
  };

  if (body) {
    options.body = JSON.stringify(body);
  }

  try {
    const response = await fetch(`${BACKEND_URL}${endpoint}`, options);
    const data = await response.json().catch(() => null);

    return {
      status: response.status,
      ok: response.ok,
      data,
      endpoint,
      method
    };
  } catch (error) {
    return {
      status: 0,
      ok: false,
      error: error.message,
      endpoint,
      method
    };
  }
}

const results = {
  total: 0,
  passed: 0,
  failed: 0,
  endpoints: []
};

function logResult(endpoint, method, status, expected, details = '') {
  results.total++;
  const passed = status === expected;

  if (passed) {
    results.passed++;
    console.log(`✅ ${method.padEnd(7)} ${endpoint.padEnd(50)} → ${status}`);
  } else {
    results.failed++;
    console.log(`❌ ${method.padEnd(7)} ${endpoint.padEnd(50)} → ${status} (expected ${expected})`);
  }

  if (details) {
    console.log(`   ${details}`);
  }

  results.endpoints.push({ endpoint, method, status, expected, passed, details });
}

async function testAllEndpoints() {
  console.log('🔍 COMPREHENSIVE API ENDPOINT AUDIT');
  console.log('='.repeat(100));
  console.log();

  // ==================== AUTHENTICATION ====================
  console.log('📋 AUTHENTICATION ENDPOINTS');
  console.log('-'.repeat(100));

  let loginResult = await apiCall('POST', '/api/auth/login', TEST_USER);
  logResult('/api/auth/login', 'POST', loginResult.status, 200,
    loginResult.data?.success ? 'Login successful' : 'Login failed');

  if (loginResult.data?.data?.token) {
    authToken = loginResult.data.data.token;
  }

  // Use timestamp to make email unique
  const timestamp = Date.now();
  let registerResult = await apiCall('POST', '/api/auth/register', {
    email: `newuser${timestamp}@test.com`,
    password: 'TestPass123!',
    firstName: 'Test',
    lastName: 'User',
    businessName: 'Test Business',
    acceptTerms: true
  });
  logResult('/api/auth/register', 'POST', registerResult.status, 201,
    registerResult.data?.success ? 'Registration successful' : 'Registration endpoint exists');

  let logoutResult = await apiCall('POST', '/api/auth/logout');
  logResult('/api/auth/logout', 'POST', logoutResult.status, 200);

  let refreshResult = await apiCall('POST', '/api/auth/refresh', {
    refreshToken: loginResult.data?.data?.refreshToken || 'test'
  });
  logResult('/api/auth/refresh', 'POST', refreshResult.status, 200);

  console.log();

  // ==================== DASHBOARD ====================
  console.log('📋 DASHBOARD ENDPOINTS');
  console.log('-'.repeat(100));

  let statsResult = await apiCall('GET', '/api/dashboard/stats?dateRange=30d');
  logResult('/api/dashboard/stats', 'GET', statsResult.status, 200);

  let metricsResult = await apiCall('GET', '/api/dashboard/metrics');
  logResult('/api/dashboard/metrics', 'GET', metricsResult.status, 200);

  let activityResult = await apiCall('GET', '/api/dashboard/activity');
  logResult('/api/dashboard/activity', 'GET', activityResult.status, 200);

  console.log();

  // ==================== CRM ====================
  console.log('📋 CRM ENDPOINTS');
  console.log('-'.repeat(100));

  let contactsResult = await apiCall('GET', '/api/crm/contacts');
  logResult('/api/crm/contacts', 'GET', contactsResult.status, 200);

  let createContactResult = await apiCall('POST', '/api/crm/contacts', {
    firstName: 'John',
    lastName: 'Doe',
    email: 'john@example.com'
  });
  logResult('/api/crm/contacts', 'POST', createContactResult.status, 201);

  let leadsResult = await apiCall('GET', '/api/crm/leads');
  logResult('/api/crm/leads', 'GET', leadsResult.status, 200);

  let dealsResult = await apiCall('GET', '/api/crm/deals');
  logResult('/api/crm/deals', 'GET', dealsResult.status, 200);

  let pipelineResult = await apiCall('GET', '/api/crm/pipeline');
  logResult('/api/crm/pipeline', 'GET', pipelineResult.status, 200);

  console.log();

  // ==================== FINANCE ====================
  console.log('📋 FINANCE ENDPOINTS');
  console.log('-'.repeat(100));

  let invoicesResult = await apiCall('GET', '/api/finance/invoices');
  logResult('/api/finance/invoices', 'GET', invoicesResult.status, 200);

  let expensesResult = await apiCall('GET', '/api/finance/expenses');
  logResult('/api/finance/expenses', 'GET', expensesResult.status, 200);

  let transactionsResult = await apiCall('GET', '/api/finance/transactions');
  logResult('/api/finance/transactions', 'GET', transactionsResult.status, 200);

  let ledgerResult = await apiCall('GET', '/api/finance/ledger');
  logResult('/api/finance/ledger', 'GET', ledgerResult.status, 200);

  let reportsResult = await apiCall('GET', '/api/finance/reports');
  logResult('/api/finance/reports', 'GET', reportsResult.status, 200);

  console.log();

  // ==================== ENTITIES ====================
  console.log('📋 ENTITY ENDPOINTS');
  console.log('-'.repeat(100));

  let entitiesResult = await apiCall('GET', '/api/entities');
  logResult('/api/entities', 'GET', entitiesResult.status, 200);

  console.log();

  // ==================== DOCUMENTS ====================
  console.log('📋 DOCUMENT ENDPOINTS');
  console.log('-'.repeat(100));

  let documentsResult = await apiCall('GET', '/api/documents');
  logResult('/api/documents', 'GET', documentsResult.status, 200);

  let uploadResult = await apiCall('POST', '/api/documents/upload');
  logResult('/api/documents/upload', 'POST', uploadResult.status, 201);

  console.log();

  // ==================== AI AGENTS ====================
  console.log('📋 AI AGENT ENDPOINTS');
  console.log('-'.repeat(100));

  let agentsResult = await apiCall('GET', '/api/agents');
  logResult('/api/agents', 'GET', agentsResult.status, 200);

  let agentStatusResult = await apiCall('GET', '/api/agents/status');
  logResult('/api/agents/status', 'GET', agentStatusResult.status, 200);

  console.log();

  // ==================== CHAT ====================
  console.log('📋 CHAT ENDPOINTS');
  console.log('-'.repeat(100));

  let chatMessagesResult = await apiCall('GET', '/api/chat/messages');
  logResult('/api/chat/messages', 'GET', chatMessagesResult.status, 200);

  let sendMessageResult = await apiCall('POST', '/api/chat/send', {
    message: 'Test message'
  });
  logResult('/api/chat/send', 'POST', sendMessageResult.status, 201);

  console.log();

  // ==================== BANKING ====================
  console.log('📋 BANKING ENDPOINTS');
  console.log('-'.repeat(100));

  let accountsResult = await apiCall('GET', '/api/banking/accounts');
  logResult('/api/banking/accounts', 'GET', accountsResult.status, 200);

  let bankTransactionsResult = await apiCall('GET', '/api/banking/transactions');
  logResult('/api/banking/transactions', 'GET', bankTransactionsResult.status, 200);

  console.log();

  // ==================== RECONCILIATION ====================
  console.log('📋 RECONCILIATION ENDPOINTS');
  console.log('-'.repeat(100));

  let reconciliationResult = await apiCall('GET', '/api/reconciliation');
  logResult('/api/reconciliation', 'GET', reconciliationResult.status, 200);

  console.log();

  // ==================== ANOMALIES ====================
  console.log('📋 ANOMALY DETECTION ENDPOINTS');
  console.log('-'.repeat(100));

  let anomaliesResult = await apiCall('GET', '/api/anomalies');
  logResult('/api/anomalies', 'GET', anomaliesResult.status, 200);

  console.log();

  // ==================== DATA QUALITY ====================
  console.log('📋 DATA QUALITY ENDPOINTS');
  console.log('-'.repeat(100));

  let dataQualityResult = await apiCall('GET', '/api/data-quality');
  logResult('/api/data-quality', 'GET', dataQualityResult.status, 200);

  console.log();

  // ==================== EXPORT ====================
  console.log('📋 EXPORT ENDPOINTS');
  console.log('-'.repeat(100));

  let exportsResult = await apiCall('GET', '/api/export');
  logResult('/api/export', 'GET', exportsResult.status, 200);

  console.log();

  // ==================== MIGRATION ====================
  console.log('📋 MIGRATION ENDPOINTS');
  console.log('-'.repeat(100));

  let migrationResult = await apiCall('GET', '/api/migration/status');
  logResult('/api/migration/status', 'GET', migrationResult.status, 200);

  console.log();

  // ==================== AI MONITORING ====================
  console.log('📋 AI MONITORING ENDPOINTS');
  console.log('-'.repeat(100));

  let aiMonitoringResult = await apiCall('GET', '/api/ai-monitoring/metrics');
  logResult('/api/ai-monitoring/metrics', 'GET', aiMonitoringResult.status, 200);

  console.log();

  // ==================== SUMMARY ====================
  console.log('='.repeat(100));
  console.log('📊 AUDIT SUMMARY');
  console.log('='.repeat(100));
  console.log(`Total Endpoints Tested: ${results.total}`);
  console.log(`✅ Passing: ${results.passed}`);
  console.log(`❌ Failing: ${results.failed}`);
  console.log(`🎯 Success Rate: ${((results.passed / results.total) * 100).toFixed(1)}%`);
  console.log();

  if (results.failed > 0) {
    console.log('❌ FAILING ENDPOINTS:');
    console.log('-'.repeat(100));
    results.endpoints.filter(e => !e.passed).forEach(e => {
      console.log(`   ${e.method.padEnd(7)} ${e.endpoint.padEnd(50)} → ${e.status} (expected ${e.expected})`);
    });
    console.log();
  }

  console.log('💡 All missing endpoints need to be implemented with full business logic.');
}

testAllEndpoints().catch(console.error);
