// Generate separate hash and salt using crypto.ts format
const PASSWORD = 'REDACTED';
const PBKDF2_ITERATIONS = 100000;
const SALT_LENGTH = 32;
const HASH_LENGTH = 32;

async function hashPassword(password) {
  const encoder = new TextEncoder();
  const passwordBuffer = encoder.encode(password);

  // Generate salt
  const saltBuffer = crypto.getRandomValues(new Uint8Array(SALT_LENGTH));

  // Import password as CryptoKey
  const passwordKey = await crypto.subtle.importKey(
    'raw',
    passwordBuffer,
    'PBKDF2',
    false,
    ['deriveBits']
  );

  // Derive hash using PBKDF2
  const hashBuffer = await crypto.subtle.deriveBits(
    {
      name: 'PBKDF2',
      salt: saltBuffer,
      iterations: PBKDF2_ITERATIONS,
      hash: 'SHA-256'
    },
    passwordKey,
    HASH_LENGTH * 8 // bits
  );

  // Convert to base64
  const bufferToBase64 = (buffer) => {
    const binString = Array.from(buffer, (x) => String.fromCodePoint(x)).join('');
    return btoa(binString);
  };

  const hashString = bufferToBase64(new Uint8Array(hashBuffer));
  const saltString = bufferToBase64(saltBuffer);

  return {
    hash: hashString,
    salt: saltString
  };
}

// Hash the password
const { hash, salt } = await hashPassword(PASSWORD);

console.log('\n📝 Password Hash and Salt (Separate):');
console.log('');
console.log('Salt:', salt);
console.log('Hash:', hash);
console.log('');

console.log('🔧 SQL Update Command:');
console.log(`wrangler d1 execute coreflow360-agents --env production --remote --command "UPDATE users SET password_hash = '${hash}', password_salt = '${salt}' WHERE email = 'founder@coreflow360.com'"`);
