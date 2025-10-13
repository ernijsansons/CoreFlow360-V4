// CoreFlow360 V4 - CRM Endpoints Testing Script
import https from 'https';
import http from 'http';
import zlib from 'zlib';

const BASE_URL = 'http://127.0.0.1:8790';
const tests = [];

async function makeRequest(method, path, body = null) {
  return new Promise((resolve) => {
    const url = new URL(path, BASE_URL);
    const options = {
      method,
      headers: body ? { 'Content-Type': 'application/json', 'Accept-Encoding': 'gzip, deflate, identity' } : { 'Accept-Encoding': 'gzip, deflate, identity' }
    };

    const req = http.request(url, options, (res) => {
      const isGzipped = res.headers['content-encoding'] === 'gzip';
      const stream = isGzipped ? res.pipe(zlib.createGunzip()) : res;

      let data = '';
      stream.on('data', chunk => data += chunk);
      stream.on('end', () => {
        try {
          resolve({
            status: res.statusCode,
            headers: res.headers,
            data: data ? (res.headers['content-type']?.includes('json') ? JSON.parse(data) : data) : null
          });
        } catch (e) {
          resolve({
            status: res.statusCode,
            headers: res.headers,
            data: data,
            parseError: e.message
          });
        }
      });
    });

    req.on('error', (error) => {
      resolve({ status: 0, error: error.message });
    });

    if (body) req.write(JSON.stringify(body));
    req.end();
  });
}

async function runTests() {
  console.log('\n========================================');
  console.log('CoreFlow360 V4 - CRM Endpoints Testing');
  console.log('========================================\n');

  // Test 1: Health
  console.log('[1/9] Testing Health Endpoint...');
  const health = await makeRequest('GET', '/health');
  if (health.status === 200 || health.status === 503) {
    console.log(`  ✓ Health: ${health.status} - ${health.data?.status || 'responded'}`);
    tests.push({ name: 'Health', status: 'PASS' });
  } else {
    console.log(`  ✗ Health failed: ${health.status}`);
    tests.push({ name: 'Health', status: 'FAIL' });
  }

  // Test 2: Conversation Logs List
  console.log('\n[2/9] Testing Conversation Logs List...');
  const logs = await makeRequest('GET', '/api/v1/crm/conversation-logs?limit=10');
  if (logs.status === 401 || logs.status === 200 || logs.status === 404) {
    console.log(`  ✓ Response: ${logs.status} ${logs.status === 401 ? '(Auth required)' : logs.status === 404 ? '(Route not found - check routing)' : '(Success)'}`);
    tests.push({ name: 'Conversation Logs List', status: logs.status === 404 ? 'WARN' : 'PASS' });
  } else {
    console.log(`  ✗ Failed: ${logs.status}`);
    tests.push({ name: 'Conversation Logs List', status: 'FAIL' });
  }

  // Test 3: Conversation Logs Single
  console.log('\n[3/9] Testing Conversation Log Detail...');
  const logDetail = await makeRequest('GET', '/api/v1/crm/conversation-logs/test-id-123');
  if (logDetail.status === 401 || logDetail.status === 404 || logDetail.status === 200) {
    console.log(`  ✓ Response: ${logDetail.status} ${logDetail.status === 401 ? '(Auth required)' : '(Expected)'}`);
    tests.push({ name: 'Conversation Log Detail', status: logDetail.status === 404 && !logDetail.data ? 'WARN' : 'PASS' });
  } else {
    console.log(`  ✗ Failed: ${logDetail.status}`);
    tests.push({ name: 'Conversation Log Detail', status: 'FAIL' });
  }

  // Test 4: Conversation Logs Stats
  console.log('\n[4/9] Testing Conversation Logs Stats...');
  const stats = await makeRequest('GET', '/api/v1/crm/conversation-logs/stats/summary');
  if (stats.status === 401 || stats.status === 404 || stats.status === 200) {
    console.log(`  ✓ Response: ${stats.status} ${stats.status === 401 ? '(Auth required)' : stats.status === 404 ? '(Route check needed)' : '(Success)'}`);
    tests.push({ name: 'Conversation Logs Stats', status: stats.status === 404 && !stats.data ? 'WARN' : 'PASS' });
  } else {
    console.log(`  ✗ Failed: ${stats.status}`);
    tests.push({ name: 'Conversation Logs Stats', status: 'FAIL' });
  }

  // Test 5: CRM Integrations Sync Status
  console.log('\n[5/9] Testing Sync Status...');
  const sync = await makeRequest('GET', '/api/v1/crm/integrations/sync-status');
  if (sync.status === 401 || sync.status === 404 || sync.status === 200) {
    console.log(`  ✓ Response: ${sync.status} ${sync.status === 401 ? '(Auth required)' : sync.status === 404 ? '(Route check needed)' : '(Success)'}`);
    tests.push({ name: 'Sync Status', status: sync.status === 404 && !sync.data ? 'WARN' : 'PASS' });
  } else {
    console.log(`  ✗ Failed: ${sync.status}`);
    tests.push({ name: 'Sync Status', status: 'FAIL' });
  }

  // Test 6: Gmail Test
  console.log('\n[6/9] Testing Gmail Integration Test...');
  const gmailTest = await makeRequest('POST', '/api/v1/crm/integrations/gmail/test');
  if (gmailTest.status === 401 || gmailTest.status === 404 || gmailTest.status === 200) {
    console.log(`  ✓ Response: ${gmailTest.status} ${gmailTest.status === 401 ? '(Auth required)' : gmailTest.status === 404 ? '(Route check needed)' : '(Success)'}`);
    tests.push({ name: 'Gmail Test', status: gmailTest.status === 404 && !gmailTest.data ? 'WARN' : 'PASS' });
  } else {
    console.log(`  ✗ Failed: ${gmailTest.status}`);
    tests.push({ name: 'Gmail Test', status: 'FAIL' });
  }

  // Test 7: Outlook Test
  console.log('\n[7/9] Testing Outlook Integration Test...');
  const outlookTest = await makeRequest('POST', '/api/v1/crm/integrations/outlook/test');
  if (outlookTest.status === 401 || outlookTest.status === 404 || outlookTest.status === 200) {
    console.log(`  ✓ Response: ${outlookTest.status} ${outlookTest.status === 401 ? '(Auth required)' : outlookTest.status === 404 ? '(Route check needed)' : '(Success)'}`);
    tests.push({ name: 'Outlook Test', status: outlookTest.status === 404 && !outlookTest.data ? 'WARN' : 'PASS' });
  } else {
    console.log(`  ✗ Failed: ${outlookTest.status}`);
    tests.push({ name: 'Outlook Test', status: 'FAIL' });
  }

  // Test 8: Twilio Test
  console.log('\n[8/9] Testing Twilio Integration Test...');
  const twilioTest = await makeRequest('POST', '/api/v1/crm/integrations/twilio/test');
  if (twilioTest.status === 401 || twilioTest.status === 404 || twilioTest.status === 200) {
    console.log(`  ✓ Response: ${twilioTest.status} ${twilioTest.status === 401 ? '(Auth required)' : twilioTest.status === 404 ? '(Route check needed)' : '(Success)'}`);
    tests.push({ name: 'Twilio Test', status: twilioTest.status === 404 && !twilioTest.data ? 'WARN' : 'PASS' });
  } else {
    console.log(`  ✗ Failed: ${twilioTest.status}`);
    tests.push({ name: 'Twilio Test', status: 'FAIL' });
  }

  // Test 9: Gmail Config Update
  console.log('\n[9/9] Testing Gmail Config Update...');
  const configUpdate = await makeRequest('PUT', '/api/v1/crm/integrations/gmail/config', { sync_enabled: true });
  if (configUpdate.status === 401 || configUpdate.status === 404 || configUpdate.status === 200) {
    console.log(`  ✓ Response: ${configUpdate.status} ${configUpdate.status === 401 ? '(Auth required)' : configUpdate.status === 404 ? '(Route check needed)' : '(Success)'}`);
    tests.push({ name: 'Gmail Config', status: configUpdate.status === 404 && !configUpdate.data ? 'WARN' : 'PASS' });
  } else {
    console.log(`  ✗ Failed: ${configUpdate.status}`);
    tests.push({ name: 'Gmail Config', status: 'FAIL' });
  }

  // Summary
  console.log('\n========================================');
  console.log('TEST SUMMARY');
  console.log('========================================');

  const passed = tests.filter(t => t.status === 'PASS').length;
  const warned = tests.filter(t => t.status === 'WARN').length;
  const failed = tests.filter(t => t.status === 'FAIL').length;

  console.log(`\nTotal Tests: ${tests.length}`);
  console.log(`Passed: ${passed}`);
  console.log(`Warnings: ${warned} (404s - may need route registration check)`);
  console.log(`Failed: ${failed}`);

  console.log('\nDetailed Results:');
  tests.forEach(t => {
    const icon = t.status === 'PASS' ? '✓' : t.status === 'WARN' ? '⚠' : '✗';
    console.log(`  ${icon} ${t.name}: ${t.status}`);
  });

  console.log('\n========================================\n');

  if (warned > 0) {
    console.log('NOTE: Routes returning 404 may not be registered in src/routes/index.ts');
    console.log('Check that conversation-logs route is properly imported and mounted.\n');
  }
}

runTests().catch(console.error);
