#!/usr/bin/env node

const API_URL = 'https://coreflow360-v4-prod.ernijs-ansons.workers.dev';

async function testDebugPassword() {
  console.log('🔐 Testing debug password endpoint...\n');

  try {
    const response = await fetch(`${API_URL}/api/auth/debug-password`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        email: 'founder@coreflow360.com',
        password: 'REDACTED'
      }),
    });

    console.log('Response Status:', response.status);
    console.log('Response Headers:', Object.fromEntries(response.headers.entries()));

    const data = await response.json();
    console.log('\n📊 Debug Data:');
    console.log(JSON.stringify(data, null, 2));

    if (data.success && data.debug) {
      console.log('\n✅ Debug endpoint working');
      console.log('\nKey findings:');
      console.log('- Password verification result:', data.debug.passwordVerificationResult);
      console.log('- Hashes match:', data.debug.hashesMatch);
      console.log('- DB hash length:', data.debug.dbHashLength);
      console.log('- DB salt length:', data.debug.dbSaltLength);
    }
  } catch (error) {
    console.error('❌ Error:', error.message);
  }
}

testDebugPassword();
