import WebSocket from 'ws';

fetch('http://127.0.0.1:9222/json/list')
  .then(res => res.json())
  .then(tabs => {
    const tab = tabs.find(t => t.url && t.url.includes('production.coreflow360'));
    if (!tab) { console.log('Tab not found'); return; }
    
    const ws = new WebSocket(tab.webSocketDebuggerUrl);
    let id = 1;

    ws.on('open', () => {
      ws.send(JSON.stringify({ id: id++, method: 'Runtime.enable' }));
      ws.send(JSON.stringify({ id: id++, method: 'Console.enable' }));
      ws.send(JSON.stringify({ id: id++, method: 'Network.enable' }));
      
      setTimeout(() => {
        ws.send(JSON.stringify({ id: id++, method: 'Page.reload', params: { ignoreCache: true } }));
      }, 500);

      const errors = [];

      ws.on('message', (data) => {
        const msg = JSON.parse(data);
        
        if (msg.method === 'Runtime.exceptionThrown') {
          const ex = msg.params.exceptionDetails;
          errors.push({
            type: 'EXCEPTION',
            message: ex.exception?.description || ex.text,
            location: `${ex.url}:${ex.lineNumber}:${ex.columnNumber}`
          });
        }
        
        if (msg.method === 'Runtime.consoleAPICalled') {
          const args = msg.params.args.map(a => a.value || a.description).join(' ');
          if (args.includes('CoreFlow360') && !args.includes('Loading timeout')) {
            console.log('[LOG]', args);
          }
        }
      });

      setTimeout(() => {
        const evalId = id++;
        ws.send(JSON.stringify({
          id: evalId,
          method: 'Runtime.evaluate',
          params: {
            expression: `JSON.stringify({
              url: window.location.href,
              bundleLoaded: document.querySelector('script[src*="index-"]')?.src,
              apiUrl: window.__API_URL__ || 'not found',
              hasRoot: !!document.getElementById('root'),
              rootContent: document.getElementById('root')?.innerHTML.substring(0, 200),
              reactMounted: typeof React !== 'undefined',
              errorMessage: document.body.innerText.includes('Loading Failed') ? 'LOADING FAILED SCREEN' : 'other'
            })`,
            returnByValue: true
          }
        }));

        ws.on('message', (data) => {
          const msg = JSON.parse(data);
          if (msg.id === evalId && msg.result) {
            console.log('\n=== PAGE STATE ===');
            const state = JSON.parse(msg.result.result.value);
            console.log('URL:', state.url);
            console.log('Bundle:', state.bundleLoaded);
            console.log('React Mounted:', state.reactMounted);
            console.log('Error Screen:', state.errorMessage);
            console.log('\n=== ERRORS CAPTURED ===');
            if (errors.length === 0) {
              console.log('No JavaScript errors captured');
            } else {
              errors.forEach(e => console.log(e));
            }
            ws.close();
          }
        });
      }, 7000);

      setTimeout(() => ws.close(), 9000);
    });
  });
