import WebSocket from 'ws';

const response = await fetch('http://127.0.0.1:9222/json/list');
const tabs = await response.json();

const tab = tabs.find(t => t.url && t.url.includes('coreflow360-frontend.pages.dev'));

if (!tab) {
  console.log('ERROR: Tab not found. Open the production site in Chrome.');
  process.exit(1);
}

console.log('Connected to:', tab.url);
console.log('Reloading page and capturing ALL errors...\n');

const ws = new WebSocket(tab.webSocketDebuggerUrl);
let id = 1;
const allErrors = [];

ws.on('open', () => {
  ws.send(JSON.stringify({ id: id++, method: 'Runtime.enable' }));
  ws.send(JSON.stringify({ id: id++, method: 'Console.enable' }));
  ws.send(JSON.stringify({ id: id++, method: 'Log.enable' }));
  ws.send(JSON.stringify({ id: id++, method: 'Network.enable' }));
  
  setTimeout(() => {
    ws.send(JSON.stringify({ 
      id: id++, 
      method: 'Page.reload',
      params: { ignoreCache: true }
    }));
  }, 500);

  ws.on('message', (data) => {
    const msg = JSON.parse(data);
    
    if (msg.method === 'Runtime.exceptionThrown') {
      const ex = msg.params.exceptionDetails;
      console.log('========================================');
      console.log('EXCEPTION THROWN');
      console.log('========================================');
      console.log('Type:', ex.exception?.className);
      console.log('Message:', ex.exception?.description || ex.text);
      console.log('File:', ex.url);
      console.log('Line:', ex.lineNumber, 'Col:', ex.columnNumber);
      
      if (ex.stackTrace?.callFrames) {
        console.log('\nStack:');
        ex.stackTrace.callFrames.slice(0, 5).forEach((frame, i) => {
          console.log(`  ${i+1}. ${frame.functionName || 'anonymous'}`);
          console.log(`     ${frame.url}:${frame.lineNumber}`);
        });
      }
      console.log('========================================\n');
      allErrors.push(ex);
    }
    
    if (msg.method === 'Runtime.consoleAPICalled' && msg.params.type === 'error') {
      const args = msg.params.args.map(a => a.value || a.description);
      const text = args.join(' ');
      if (!text.includes('[CoreFlow360]')) {
        console.log('CONSOLE ERROR:', text);
        allErrors.push({ type: 'console', message: text });
      }
    }
  });

  setTimeout(() => {
    console.log(`\n\nTotal errors captured: ${allErrors.length}`);
    if (allErrors.length === 0) {
      console.log('\nNO ERRORS CAPTURED. Checking if React mounted...\n');
    }
    
    const evalId = id++;
    ws.send(JSON.stringify({
      id: evalId,
      method: 'Runtime.evaluate',
      params: {
        expression: `({
          reactExists: typeof React !== 'undefined',
          hasRoot: !!document.getElementById('root'),
          bodyText: document.body.innerText.substring(0, 300)
        })`,
        returnByValue: true
      }
    }));

    ws.on('message', (data) => {
      const msg = JSON.parse(data);
      if (msg.id === evalId && msg.result?.result?.value) {
        const state = msg.result.result.value;
        console.log('React loaded:', state.reactExists);
        console.log('Root exists:', state.hasRoot);
        console.log('Body text:', state.bodyText);
        ws.close();
        process.exit(0);
      }
    });
  }, 8000);
});

setTimeout(() => {
  console.log('\nTimeout reached');
  ws.close();
  process.exit(1);
}, 10000);
