/**
 * Quick Admin Endpoint Test
 */

const API_BASE = 'http://127.0.0.1:8790';

async function testAdminEndpoints() {
  console.log('Testing Admin Dashboard Endpoints\n');

  // First, login to get a token
  const loginResponse = await fetch(`${API_BASE}/api/v1/auth/login`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      email: 'admin1760751803974@test.com',  // Use an existing user
      password: 'AdminPass123!'
    })
  });

  if (!loginResponse.ok) {
    console.log('❌ Login failed, need to create user first');
    console.log('Status:', loginResponse.status);
    return;
  }

  const loginData = await loginResponse.json();
  const token = loginData.token;
  const userId = loginData.user?.id;

  console.log('✓ Login successful');
  console.log('User ID:', userId);
  console.log();

  // Manually set user to admin
  const setAdminResponse = await fetch(`${API_BASE}/test-set-admin`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ userId })
  });

  if (setAdminResponse.ok) {
    const data = await setAdminResponse.json();
    console.log('✓', data.message);
    console.log();
  }

  // Test admin endpoints
  const endpoints = [
    '/api/v1/admin/analytics/kpis',
    '/api/v1/admin/analytics/realtime',
    '/api/v1/admin/analytics/business-intelligence',
    '/api/v1/admin/analytics/system',
    '/api/v1/admin/analytics/security',
    '/api/v1/admin/users',
    '/api/v1/admin/businesses',
    '/api/v1/admin/audit-logs',
    '/api/v1/admin/sessions'
  ];

  for (const endpoint of endpoints) {
    const response = await fetch(`${API_BASE}${endpoint}`, {
      headers: {
        'Authorization': `Bearer ${token}`,
        'X-User-ID': userId
      }
    });

    const status = response.status;
    const statusText = response.ok ? '✓' : '✗';
    const color = response.ok ? '\x1b[32m' : '\x1b[31m';
    const reset = '\x1b[0m';

    console.log(`${color}${statusText} ${endpoint} - ${status}${reset}`);

    if (response.ok) {
      const data = await response.json();
      // Show first key from data
      const firstKey = Object.keys(data.data || {})[0];
      if (firstKey) {
        console.log(`  → ${firstKey}:`, JSON.stringify(data.data[firstKey]).substring(0, 80));
      }
    }
  }
}

testAdminEndpoints().catch(console.error);
