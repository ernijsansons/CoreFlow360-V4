import WebSocket from 'ws';

const response = await fetch('http://127.0.0.1:9222/json/list');
const tabs = await response.json();
const tab = tabs.find(t => t.url && t.url.includes('coreflow360'));

const ws = new WebSocket(tab.webSocketDebuggerUrl);
let id = 1;

ws.on('open', () => {
  ws.send(JSON.stringify({ id: id++, method: 'Runtime.enable' }));
  ws.send(JSON.stringify({ id: id++, method: 'Console.enable' }));
  
  setTimeout(() => {
    ws.send(JSON.stringify({ id: id++, method: 'Page.reload', params: { ignoreCache: true } }));
  }, 500);

  let foundError = false;

  ws.on('message', (data) => {
    const msg = JSON.parse(data);
    
    if (msg.method === 'Runtime.exceptionThrown') {
      foundError = true;
      const ex = msg.params.exceptionDetails;
      console.log('\n=== REAL EXCEPTION ===');
      console.log('Message:', ex.exception?.description || ex.text);
      console.log('Location:', ex.url + ':' + ex.lineNumber);
      console.log('Stack:', JSON.stringify(ex.stackTrace, null, 2));
    }
    
    if (msg.method === 'Runtime.consoleAPICalled') {
      const args = msg.params.args;
      const firstArg = args[0]?.value || args[0]?.description || '';
      
      if (firstArg.includes('Router Error') || firstArg.includes('caught error')) {
        console.log('\n=== ERROR BOUNDARY LOG ===');
        args.forEach(arg => {
          console.log(arg.value || arg.description);
        });
      }
    }
  });

  setTimeout(() => {
    if (!foundError) {
      console.log('\nNo exception found. Checking error boundary state...\n');
      
      const evalId = id++;
      ws.send(JSON.stringify({
        id: evalId,
        method: 'Runtime.evaluate',
        params: {
          expression: `
            Array.from(document.querySelectorAll('pre')).map(pre => pre.textContent).join('\n---\n')
          `,
          returnByValue: true
        }
      }));

      ws.on('message', (data) => {
        const msg = JSON.parse(data);
        if (msg.id === evalId && msg.result?.result?.value) {
          console.log('Error details on page:');
          console.log(msg.result.result.value);
          ws.close();
        }
      });
    } else {
      ws.close();
    }
  }, 7000);
});
