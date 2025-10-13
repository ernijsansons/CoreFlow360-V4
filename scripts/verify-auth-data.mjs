// Verify authentication data structure in production
const API_URL = 'https://coreflow360-v4-prod.ernijs-ansons.workers.dev';

async function verifyAuthData() {
  console.log('🔍 Verifying Production Authentication Data\n');

  try {
    // Test 1: Check if user exists
    console.log('Test 1: Checking user exists in database...');
    const checkUserSQL = `
      SELECT
        id, email, first_name, last_name, status,
        LENGTH(password_hash) as hash_len,
        LENGTH(password_salt) as salt_len,
        SUBSTR(password_hash, 1, 20) as hash_preview,
        SUBSTR(password_salt, 1, 20) as salt_preview
      FROM users
      WHERE email = 'founder@coreflow360.com'
    `;

    const response1 = await fetch(`${API_URL}/api/migration/execute-sql`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ sql: checkUserSQL })
    });

    const result1 = await response1.json();
    console.log('User Query Result:', JSON.stringify(result1, null, 2));

    // Test 2: Try the exact login query
    console.log('\nTest 2: Testing exact login SQL query...');
    const loginSQL = `
      SELECT u.*, b.name as business_name, b.domain as business_domain
      FROM users u
      LEFT JOIN businesses b ON u.business_id = b.id
      WHERE u.email = 'founder@coreflow360.com'
    `;

    const response2 = await fetch(`${API_URL}/api/migration/execute-sql`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ sql: loginSQL })
    });

    const result2 = await response2.json();
    console.log('Login Query Result:', JSON.stringify(result2, null, 2));

    if (result2.results && result2.results.length > 0) {
      const user = result2.results[0];
      console.log('\n✅ User Found:');
      console.log('  - Email:', user.email);
      console.log('  - Has password_hash:', !!user.password_hash);
      console.log('  - Has password_salt:', !!user.password_salt);
      console.log('  - Hash length:', user.password_hash?.length);
      console.log('  - Salt length:', user.password_salt?.length);
      console.log('  - Business:', user.business_name);
    } else {
      console.log('\n❌ User Not Found!');
    }

  } catch (error) {
    console.error('\n💥 Verification Failed:', error.message);
  }
}

verifyAuthData();
