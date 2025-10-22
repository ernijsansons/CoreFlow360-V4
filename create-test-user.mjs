// Create test user in database
import Database from 'better-sqlite3';

const db = new Database('.wrangler/state/v3/d1/miniflare-D1DatabaseObject/c56bb204-78bc-4357-a704-419aa9f11e6f.sqlite');

// Using a pre-hashed password for "Test123!@#"
// This is a bcrypt hash that can be verified
const passwordHash = '$2a$10$N9qo8uLOickgx2ZMRZoMyeIjZAgcfl7p92ldGxad68LJZdL17lhWy'; // "password"

const userId = 'test-user-001';
const businessId = 'test-business-001';

// Insert user
try {
  db.exec(`
    INSERT OR REPLACE INTO users (
      id, email, password_hash, first_name, last_name, business_id, email_verified, status
    ) VALUES (
      '${userId}',
      'test@example.com',
      '${passwordHash}',
      'Test',
      'User',
      '${businessId}',
      1,
      'active'
    );
  `);

  console.log('✅ Test user created successfully!');
  console.log('   Email: test@example.com');
  console.log('   Password: password');
  console.log('   (Simple password for testing)');
} catch (error) {
  console.error('❌ Error creating user:', error.message);
}

db.close();
