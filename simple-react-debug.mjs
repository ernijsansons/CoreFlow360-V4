import WebSocket from 'ws';

const res = await fetch('http://127.0.0.1:9222/json/list');
const tabs = await res.json();
const tab = tabs.find(t => t.url && t.url.includes('coreflow360'));

if (!tab) {
  console.log('ERROR: No CoreFlow360 tab found');
  process.exit(1);
}

console.log('Connected to:', tab.url);
console.log('\nReloading and monitoring for 10 seconds...\n');

const ws = new WebSocket(tab.webSocketDebuggerUrl);
let id = 1;

ws.on('open', () => {
  ws.send(JSON.stringify({ id: id++, method: 'Runtime.enable' }));
  ws.send(JSON.stringify({ id: id++, method: 'Console.enable' }));
  
  setTimeout(() => {
    ws.send(JSON.stringify({ id: id++, method: 'Page.reload', params: { ignoreCache: true } }));
  }, 500);

  ws.on('message', (data) => {
    const msg = JSON.parse(data);
    
    if (msg.method === 'Runtime.exceptionThrown') {
      const ex = msg.params.exceptionDetails;
      console.log('\n!!! EXCEPTION THROWN !!!');
      console.log('Type:', ex.exception?.className);
      console.log('Message:', ex.exception?.description || ex.text);
      console.log('File:', ex.url);
      console.log('Line:', ex.lineNumber, 'Col:', ex.columnNumber);
      if (ex.exception?.preview?.properties) {
        console.log('\nException properties:');
        ex.exception.preview.properties.forEach(prop => {
          console.log(`  ${prop.name}:`, prop.value);
        });
      }
      console.log('\n');
    }
    
    if (msg.method === 'Runtime.consoleAPICalled') {
      const type = msg.params.type;
      const args = msg.params.args.map(a => a.value || a.description);
      const text = args.join(' ');
      
      if (text.includes('[CoreFlow360]')) {
        console.log(`[${type.toUpperCase()}]`, text);
      }
    }
  });

  setTimeout(() => {
    const evalId = id++;
    ws.send(JSON.stringify({
      id: evalId,
      method: 'Runtime.evaluate',
      params: {
        expression: `({
          bundleName: document.querySelector('script[src*="index-"]')?.src?.match(/index-([^.]+)\.js/)?.[0],
          reactExists: typeof React !== 'undefined',
          errorText: document.body.innerText.substring(0, 150)
        })`,
        returnByValue: true
      }
    }));

    ws.on('message', (data) => {
      const msg = JSON.parse(data);
      if (msg.id === evalId && msg.result?.result?.value) {
        console.log('\n=== FINAL STATE ===');
        const state = msg.result.result.value;
        console.log('Bundle:', state.bundleName);
        console.log('React loaded:', state.reactExists);
        console.log('Error text:', state.errorText);
        ws.close();
        process.exit(0);
      }
    });
  }, 9000);
});

setTimeout(() => {
  console.log('\nTimeout - closing');
  ws.close();
  process.exit(1);
}, 11000);
