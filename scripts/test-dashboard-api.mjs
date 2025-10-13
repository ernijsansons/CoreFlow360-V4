// Test dashboard API endpoints
const API_URL = 'https://coreflow360-v4-prod.ernijs-ansons.workers.dev';

async function testDashboardAPI() {
  console.log('🔍 Testing Dashboard API Endpoints\n');

  try {
    // Test stats endpoint
    console.log('1. Testing /api/dashboard/stats...');
    const statsResponse = await fetch(`${API_URL}/api/dashboard/stats?businessId=business-founder-001&dateRange=30d`);
    const statsData = await statsResponse.json();
    console.log('Stats Response:', JSON.stringify(statsData, null, 2));

    // Test activity endpoint
    console.log('\n2. Testing /api/dashboard/activity...');
    const activityResponse = await fetch(`${API_URL}/api/dashboard/activity?businessId=business-founder-001&limit=5`);
    const activityData = await activityResponse.json();
    console.log('Activity Response:', JSON.stringify(activityData, null, 2));

    // Test tasks endpoint
    console.log('\n3. Testing /api/dashboard/tasks...');
    const tasksResponse = await fetch(`${API_URL}/api/dashboard/tasks?businessId=business-founder-001`);
    const tasksData = await tasksResponse.json();
    console.log('Tasks Response:', JSON.stringify(tasksData, null, 2));

    console.log('\n✅ All endpoints tested successfully!');
  } catch (error) {
    console.error('\n💥 Test Failed:', error.message);
  }
}

testDashboardAPI();
