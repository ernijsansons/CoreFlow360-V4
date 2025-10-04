// Debug script to test security functions
const { detectSuspiciousActivity, sanitizeInput, validateFileUpload } = require('./src/middleware/security.ts');

// Test path traversal detection
console.log('=== Path Traversal Test ===');
const url = 'https://example.com/api/../../../etc/passwd';
const headers = new Headers();
headers.set('User-Agent', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36');

const request = new Request(url, { headers });
const result = detectSuspiciousActivity(request);
console.log('URL:', url);
console.log('Result:', result);

// Test sanitization
console.log('\n=== Sanitization Test ===');
const input = '<script>alert(1)</script>';
const sanitized = sanitizeInput(input, { allowHtml: false, normalizeWhitespace: true });
console.log('Input:', input);
console.log('Sanitized:', sanitized);

// Test file validation
console.log('\n=== File Validation Test ===');
const filename = '../../../etc/passwd';
const fileResult = validateFileUpload(filename);
console.log('Filename:', filename);
console.log('Result:', fileResult);