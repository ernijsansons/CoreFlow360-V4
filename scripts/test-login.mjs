// Test Login with Detailed Error Info
const API_URL = 'https://coreflow360-v4-prod.ernijs-ansons.workers.dev';

async function testLogin() {
  console.log('🔐 Testing login...\n');

  try {
    const response = await fetch(`${API_URL}/api/auth/login`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        email: 'founder@coreflow360.com',
        password: 'REDACTED',
      }),
    });

    console.log('Response Status:', response.status);
    console.log('Response Headers:', {
      'content-type': response.headers.get('content-type'),
      'set-cookie': response.headers.get('set-cookie'),
    });

    const text = await response.text();
    console.log('\nRaw Response:', text);

    let data;
    try {
      data = JSON.parse(text);
      console.log('\nParsed Response:', JSON.stringify(data, null, 2));
    } catch (e) {
      console.error('Failed to parse JSON');
      return;
    }

    if (data.success) {
      console.log('\n✅ LOGIN SUCCESSFUL!');
      console.log('Token:', data.token?.substring(0, 30) + '...');
      console.log('User:', data.user);
    } else {
      console.log('\n❌ LOGIN FAILED');
      console.log('Error:', data.error);
    }
  } catch (error) {
    console.error('\n❌ REQUEST FAILED:', error.message);
  }
}

testLogin();
