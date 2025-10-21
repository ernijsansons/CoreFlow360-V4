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
      
      setTimeout(() => {
        ws.send(JSON.stringify({ id: id++, method: 'Page.reload', params: { ignoreCache: true } }));
      }, 500);

      ws.on('message', (data) => {
        const msg = JSON.parse(data);
        if (msg.method === 'Runtime.exceptionThrown') {
          const ex = msg.params.exceptionDetails;
          console.log('\nEXCEPTION:', ex.exception?.description || ex.text);
          console.log('At:', ex.url + ':' + ex.lineNumber);
        }
      });

      setTimeout(() => ws.close(), 8000);
    });
  });
