// Debug Login - Full Request/Response Details
const API_URL = 'https://coreflow360-v4-prod.ernijs-ansons.workers.dev';

async function debugLogin() {
  console.log('🔐 Debug Login Test\n');
  console.log('Testing credentials:');
  console.log('Email: founder@coreflow360.com');
  console.log('Password: REDACTED');
  console.log('');

  const requestBody = {
    email: 'founder@coreflow360.com',
    password: 'REDACTED',
  };

  console.log('📤 Request Body:', JSON.stringify(requestBody, null, 2));
  console.log('');

  try {
    const response = await fetch(`${API_URL}/api/auth/login`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'User-Agent': 'CoreFlow360-Debug/1.0',
        'Accept': 'application/json',
      },
      body: JSON.stringify(requestBody),
    });

    console.log('📥 Response Status:', response.status, response.statusText);
    console.log('');

    console.log('📋 Response Headers:');
    for (const [key, value] of response.headers.entries()) {
      console.log(`  ${key}: ${value}`);
    }
    console.log('');

    const text = await response.text();
    console.log('📄 Raw Response Body:');
    console.log(text);
    console.log('');

    try {
      const data = JSON.parse(text);
      console.log('🔍 Parsed JSON:');
      console.log(JSON.stringify(data, null, 2));

      if (data.success) {
        console.log('\n✅ LOGIN SUCCESSFUL!');
        if (data.token) {
          console.log('Token preview:', data.token.substring(0, 50) + '...');
        }
        if (data.user) {
          console.log('User:', data.user);
        }
      } else {
        console.log('\n❌ LOGIN FAILED');
        console.log('Error message:', data.error);
      }
    } catch (parseError) {
      console.error('⚠️  Failed to parse response as JSON');
      console.error('Parse error:', parseError.message);
    }
  } catch (error) {
    console.error('\n💥 REQUEST FAILED');
    console.error('Error:', error.message);
    console.error('Stack:', error.stack);
  }
}

debugLogin();
