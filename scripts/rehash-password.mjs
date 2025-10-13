// Rehash password using PasswordSecurity format from security-utilities.ts
const PASSWORD = 'REDACTED';
const ITERATIONS = 100000;

async function hashPassword(password) {
  const encoder = new TextEncoder();
  const data = encoder.encode(password);

  // Generate random salt
  const salt = crypto.getRandomValues(new Uint8Array(16));

  // Import key for PBKDF2
  const keyMaterial = await crypto.subtle.importKey(
    'raw',
    data,
    'PBKDF2',
    false,
    ['deriveBits']
  );

  // Derive key using PBKDF2
  const derivedBits = await crypto.subtle.deriveBits(
    {
      name: 'PBKDF2',
      salt: salt,
      iterations: ITERATIONS,
      hash: 'SHA-256'
    },
    keyMaterial,
    256
  );

  const hashArray = new Uint8Array(derivedBits);

  // Convert to base64
  const saltBase64 = btoa(String.fromCharCode(...salt));
  const hashBase64 = btoa(String.fromCharCode(...hashArray));

  // Return salt$iterations$hash format
  return `${saltBase64}$${ITERATIONS}$${hashBase64}`;
}

// Hash the password
const hash = await hashPassword(PASSWORD);
console.log('\n📝 New Password Hash (PasswordSecurity format):');
console.log(hash);

console.log('\n🔧 SQL Update Command:');
console.log(`wrangler d1 execute coreflow360-agents --env production --command "UPDATE users SET password_hash = '${hash}' WHERE email = 'founder@coreflow360.com'"`);
