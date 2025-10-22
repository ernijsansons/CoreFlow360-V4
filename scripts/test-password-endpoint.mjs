// Test password verification endpoint
const API_URL = 'https://coreflow360-v4-prod.ernijs-ansons.workers.dev';

async function testPasswordEndpoint() {
  console.log('🔐 Testing Password Verification Endpoint\n');

  try {
    const response = await fetch(`${API_URL}/api/test-password/verify-founder`, {
      method: 'GET',
      headers: {
        'Accept': 'application/json',
        'Accept-Encoding': 'gzip, deflate'
      }
    });

    console.log('Response Status:', response.status);
    console.log('');

    const data = await response.json();
    console.log('Response Data:');
    console.log(JSON.stringify(data, null, 2));

    if (data.isValid) {
      console.log('\n✅ PASSWORD VERIFICATION PASSED!');
    } else {
      console.log('\n❌ PASSWORD VERIFICATION FAILED');
    }
  } catch (error) {
    console.error('\n💥 REQUEST FAILED:', error.message);
  }
}

testPasswordEndpoint();
