// Create Founder Account Script
const API_URL = 'https://coreflow360-v4-prod.ernijs-ansons.workers.dev';

async function createFounder() {
  try {
    const response = await fetch(`${API_URL}/api/auth/register`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        email: 'founder@coreflow360.com',
        password: 'CoreFlow360!2025Strong',
        name: 'Ernijs Ansons',
        companyName: 'CoreFlow360',
        acceptTerms: true,
      }),
    });

    console.log('Response status:', response.status);
    console.log('Response headers:', Object.fromEntries(response.headers.entries()));

    const text = await response.text();
    console.log('Response body:', text);

    let data;
    try {
      data = JSON.parse(text);
    } catch (e) {
      console.error('Failed to parse response as JSON');
      return null;
    }

    if (data.success) {
      console.log('✅ Founder account created successfully!');
      console.log('📧 Email:', 'founder@coreflow360.com');
      console.log('🔑 Password:', 'CoreFlow360!2025Strong');
      console.log('👤 User ID:', data.user?.id);
      console.log('🎫 Token:', data.token?.substring(0, 20) + '...');
    } else {
      console.error('❌ Failed to create founder account');
      console.error('Error:', data.error);
      console.error('Full response:', JSON.stringify(data, null, 2));
    }

    return data;
  } catch (error) {
    console.error('❌ Request failed:', error.message);
    throw error;
  }
}

createFounder();
