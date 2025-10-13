#!/usr/bin/env node

import WebSocket from 'ws';

const CDP_URL = 'http://127.0.0.1:9222';

async function inspectPage() {
  try {
    // Get list of tabs
    const response = await fetch(`${CDP_URL}/json/list`);
    const tabs = await response.json();

    // Find the production page
    const productionTab = tabs.find(tab =>
      tab.url && tab.url.includes('production.coreflow360-frontend.pages.dev')
    );

    if (!productionTab) {
      console.error('❌ Production page not found in open tabs');
      console.log('Open tabs:', tabs.map(t => t.url));
      process.exit(1);
    }

    console.log('✅ Found production page:', productionTab.url);
    console.log('📄 Page title:', productionTab.title);
    console.log('\n🔗 Connecting to DevTools...\n');

    // Connect to WebSocket
    const ws = new WebSocket(productionTab.webSocketDebuggerUrl);

    let messageId = 1;
    const pendingRequests = new Map();

    ws.on('open', async () => {
      console.log('✅ Connected to Chrome DevTools Protocol\n');

      // Enable domains
      await sendCommand(ws, pendingRequests, 'Runtime.enable');
      await sendCommand(ws, pendingRequests, 'Log.enable');
      await sendCommand(ws, pendingRequests, 'Page.enable');
      await sendCommand(ws, pendingRequests, 'Network.enable');

      // Get console messages
      console.log('📋 === CONSOLE LOGS ===\n');

      // Evaluate: Get all console history
      const consoleResult = await sendCommand(ws, pendingRequests, 'Runtime.evaluate', {
        expression: `
          (function() {
            const logs = [];
            const originalConsole = {
              log: console.log,
              warn: console.warn,
              error: console.error
            };

            // Try to get any stored console messages
            if (window.__consoleHistory) {
              return window.__consoleHistory;
            }

            return { message: 'Console history not available - will capture new logs' };
          })()
        `,
        returnByValue: true
      });

      console.log('Console evaluation result:', JSON.stringify(consoleResult, null, 2));

      // Check if CSS variables are loaded
      console.log('\n🎨 === CSS VARIABLES CHECK ===\n');
      const cssCheck = await sendCommand(ws, pendingRequests, 'Runtime.evaluate', {
        expression: `
          (function() {
            const rootStyles = getComputedStyle(document.documentElement);
            const criticalVars = {
              '--brand-primary-600': rootStyles.getPropertyValue('--brand-primary-600'),
              '--brand-accent-600': rootStyles.getPropertyValue('--brand-accent-600'),
              '--brand-teal-600': rootStyles.getPropertyValue('--brand-teal-600'),
              '--semantic-success-500': rootStyles.getPropertyValue('--semantic-success-500')
            };
            return criticalVars;
          })()
        `,
        returnByValue: true
      });

      if (cssCheck.result?.result?.value) {
        console.log('CSS Variables:');
        console.log(JSON.stringify(cssCheck.result.result.value, null, 2));
      }

      // Check DOM structure
      console.log('\n🌳 === DOM STRUCTURE ===\n');
      const domCheck = await sendCommand(ws, pendingRequests, 'Runtime.evaluate', {
        expression: `
          (function() {
            const root = document.getElementById('root');
            const loadingScreen = document.getElementById('loading-screen');

            return {
              hasRoot: !!root,
              rootHTML: root ? root.innerHTML.substring(0, 200) : null,
              hasLoadingScreen: !!loadingScreen,
              loadingScreenVisible: loadingScreen ?
                window.getComputedStyle(loadingScreen).display !== 'none' : null,
              bodyClasses: document.body.className,
              documentTitle: document.title
            };
          })()
        `,
        returnByValue: true
      });

      if (domCheck.result?.result?.value) {
        console.log('DOM State:');
        console.log(JSON.stringify(domCheck.result.result.value, null, 2));
      }

      // Check for React errors
      console.log('\n⚛️  === REACT & JAVASCRIPT ERRORS ===\n');
      const errorCheck = await sendCommand(ws, pendingRequests, 'Runtime.evaluate', {
        expression: `
          (function() {
            const errors = [];

            // Check for React error boundary
            const errorElements = document.querySelectorAll('[class*="error"], [class*="Error"]');
            if (errorElements.length > 0) {
              errors.push({
                type: 'Error UI detected',
                count: errorElements.length,
                text: Array.from(errorElements).map(el => el.textContent.substring(0, 100))
              });
            }

            // Check if "Something went wrong" message exists
            if (document.body.textContent.includes('Something went wrong')) {
              errors.push({
                type: 'Error message found',
                message: 'Something went wrong'
              });
            }

            return errors.length > 0 ? errors : { status: 'No error messages in DOM' };
          })()
        `,
        returnByValue: true
      });

      if (errorCheck.result?.result?.value) {
        console.log('Error Check:');
        console.log(JSON.stringify(errorCheck.result.result.value, null, 2));
      }

      // Get page screenshot info
      console.log('\n📸 === PAGE VISUAL STATE ===\n');
      const visualCheck = await sendCommand(ws, pendingRequests, 'Runtime.evaluate', {
        expression: `
          (function() {
            return {
              viewport: {
                width: window.innerWidth,
                height: window.innerHeight
              },
              scroll: {
                x: window.scrollX,
                y: window.scrollY
              },
              visibleText: document.body.innerText.substring(0, 500),
              hasLoginForm: !!document.querySelector('input[type="email"]'),
              hasPasswordField: !!document.querySelector('input[type="password"]'),
              hasButtons: document.querySelectorAll('button').length
            };
          })()
        `,
        returnByValue: true
      });

      if (visualCheck.result?.result?.value) {
        console.log('Visual State:');
        console.log(JSON.stringify(visualCheck.result.result.value, null, 2));
      }

      console.log('\n✅ === INSPECTION COMPLETE ===\n');

      ws.close();
      process.exit(0);
    });

    ws.on('error', (error) => {
      console.error('❌ WebSocket error:', error);
      process.exit(1);
    });

    ws.on('message', (data) => {
      const message = JSON.parse(data);

      // Handle responses to our commands
      if (message.id && pendingRequests.has(message.id)) {
        const { resolve } = pendingRequests.get(message.id);
        pendingRequests.delete(message.id);
        resolve(message);
      }

      // Handle console messages
      if (message.method === 'Runtime.consoleAPICalled') {
        const { type, args } = message.params;
        console.log(`[Console ${type}]:`, args.map(arg => arg.value || arg.description).join(' '));
      }

      // Handle exceptions
      if (message.method === 'Runtime.exceptionThrown') {
        console.error('[Exception]:', message.params.exceptionDetails);
      }
    });

    function sendCommand(ws, pendingRequests, method, params = {}) {
      return new Promise((resolve) => {
        const id = messageId++;
        pendingRequests.set(id, { resolve });

        ws.send(JSON.stringify({
          id,
          method,
          params
        }));
      });
    }

  } catch (error) {
    console.error('❌ Failed to inspect page:', error);
    process.exit(1);
  }
}

inspectPage();
