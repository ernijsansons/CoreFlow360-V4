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
        const evalId = id++;
        ws.send(JSON.stringify({
          id: evalId,
          method: 'Runtime.evaluate',
          params: {
            expression: 'document.body.innerText',
            returnByValue: true
          }
        }));

        ws.on('message', (data) => {
          const msg = JSON.parse(data);
          if (msg.id === evalId && msg.result) {
            console.log('Page content:');
            console.log(msg.result.result.value);
            ws.close();
          }
        });
      }, 1000);

      setTimeout(() => ws.close(), 3000);
    });
  });
