// Test password verification logic locally
const PASSWORD = 'REDACTED';
const STORED_HASH = '7ReLeGm2ttjp+z3DBaD4yvfP4MjDaZSL3tjJeAF8azM=';
const STORED_SALT = 'dBpVkci53M5Ahco3SLvySoStq+2Ktt2YLbDCx4nAHQU=';

const PBKDF2_ITERATIONS = 100000;
const HASH_LENGTH = 32;

// Helper functions
function base64ToBuffer(base64) {
  const binString = atob(base64);
  const buffer = new Uint8Array(binString.length);
  for (let i = 0; i < binString.length; i++) {
    buffer[i] = binString.charCodeAt(i);
  }
  return buffer;
}

function bufferToBase64(buffer) {
  const binString = Array.from(buffer, (x) => String.fromCodePoint(x)).join('');
  return btoa(binString);
}

async function hashPassword(password, salt) {
  const encoder = new TextEncoder();
  const passwordBuffer = encoder.encode(password);

  // Decode salt
  const saltBuffer = base64ToBuffer(salt);

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

  const hashString = bufferToBase64(new Uint8Array(hashBuffer));

  return hashString;
}

async function verifyPassword(password, storedHash, storedSalt) {
  const newHash = await hashPassword(password, storedSalt);

  console.log('\n🔍 Password Verification Test:');
  console.log('Password:', password);
  console.log('Stored Salt:', storedSalt);
  console.log('Stored Hash:', storedHash);
  console.log('Computed Hash:', newHash);
  console.log('Hashes Match:', newHash === storedHash);

  // Constant-time comparison
  if (newHash.length !== storedHash.length) {
    console.log('❌ Hash length mismatch');
    return false;
  }

  let result = 0;
  for (let i = 0; i < newHash.length; i++) {
    result |= newHash.charCodeAt(i) ^ storedHash.charCodeAt(i);
  }

  const isValid = result === 0;
  console.log('\n' + (isValid ? '✅ VERIFICATION PASSED' : '❌ VERIFICATION FAILED'));

  return isValid;
}

// Test
await verifyPassword(PASSWORD, STORED_HASH, STORED_SALT);
