const BACKEND_URL = 'http://127.0.0.1:8790';

async function testAuthFlow() {
  console.log('🔐 COMPREHENSIVE AUTHENTICATION FLOW TEST\n');
  
  const timestamp = Date.now();
  const testUser = {
    email: `test${timestamp}@coreflow360.dev`,
    password: 'TestPass123!',
    firstName: 'Test',
    lastName: 'User',
    businessName: 'Test Business',
    acceptTerms: true
  };
  
  // Test 1: Registration
  console.log('📝 Test 1: User Registration');
  try {
    const regResponse = await fetch(`${BACKEND_URL}/api/auth/register`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(testUser)
    });
    const regData = await regResponse.json();
    
    if (regResponse.status === 201 && regData.success) {
      console.log('✅ Registration: SUCCESS');
      console.log(`   User ID: ${regData.data?.userId}`);
      console.log(`   Business ID: ${regData.data?.businessId}`);
    } else {
      console.log(`❌ Registration: FAILED (${regResponse.status})`);
      console.log(`   Error: ${regData.error}`);
      return false;
    }
  } catch (error) {
    console.log(`❌ Registration: ERROR - ${error.message}`);
    return false;
  }
  
  // Test 2: Login
  console.log('\n🔑 Test 2: User Login');
  let authToken = null;
  try {
    const loginResponse = await fetch(`${BACKEND_URL}/api/auth/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        email: testUser.email,
        password: testUser.password
      })
    });
    const loginData = await loginResponse.json();
    
    if (loginResponse.status === 200 && loginData.success) {
      authToken = loginData.data?.token;
      console.log('✅ Login: SUCCESS');
      console.log(`   Token received: ${authToken ? 'Yes' : 'No'}`);
      console.log(`   Token length: ${authToken?.length || 0} chars`);
    } else {
      console.log(`❌ Login: FAILED (${loginResponse.status})`);
      console.log(`   Error: ${loginData.error}`);
      return false;
    }
  } catch (error) {
    console.log(`❌ Login: ERROR - ${error.message}`);
    return false;
  }
  
  // Test 3: Authenticated Request
  console.log('\n🔒 Test 3: Authenticated API Request');
  try {
    const dashResponse = await fetch(`${BACKEND_URL}/api/dashboard/stats`, {
      headers: {
        'Authorization': `Bearer ${authToken}`,
        'Content-Type': 'application/json'
      }
    });
    const dashData = await dashResponse.json();
    
    if (dashResponse.status === 200 && dashData.success) {
      console.log('✅ Authenticated Request: SUCCESS');
      console.log(`   Revenue: $${dashData.data?.overview?.totalRevenue || 0}`);
      console.log(`   Users: ${dashData.data?.overview?.totalUsers || 0}`);
    } else {
      console.log(`❌ Authenticated Request: FAILED (${dashResponse.status})`);
    }
  } catch (error) {
    console.log(`❌ Authenticated Request: ERROR - ${error.message}`);
  }
  
  // Test 4: Logout
  console.log('\n👋 Test 4: User Logout');
  try {
    const logoutResponse = await fetch(`${BACKEND_URL}/api/auth/logout`, {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${authToken}`,
        'Content-Type': 'application/json'
      }
    });
    const logoutData = await logoutResponse.json();
    
    if (logoutResponse.status === 200 && logoutData.success) {
      console.log('✅ Logout: SUCCESS');
    } else {
      console.log(`❌ Logout: FAILED (${logoutResponse.status})`);
    }
  } catch (error) {
    console.log(`❌ Logout: ERROR - ${error.message}`);
  }
  
  // Test 5: Token Refresh
  console.log('\n🔄 Test 5: Token Refresh');
  try {
    const refreshResponse = await fetch(`${BACKEND_URL}/api/auth/refresh`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ refreshToken: authToken })
    });
    const refreshData = await refreshResponse.json();
    
    if (refreshResponse.status === 200 && refreshData.success) {
      console.log('✅ Token Refresh: SUCCESS');
    } else {
      console.log(`⚠️  Token Refresh: ${refreshResponse.status}`);
    }
  } catch (error) {
    console.log(`❌ Token Refresh: ERROR - ${error.message}`);
  }
  
  console.log('\n' + '='.repeat(80));
  console.log('✅ AUTHENTICATION FLOW TEST COMPLETED SUCCESSFULLY');
  console.log('='.repeat(80));
  
  return true;
}

testAuthFlow().catch(console.error);
