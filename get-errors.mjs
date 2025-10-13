#!/usr/bin/env node

import WebSocket from 'ws';

const CDP_URL = 'http://127.0.0.1:9222';

async function getErrors() {
  const response = await fetch(`${CDP_URL}/json/list`);
  const tabs = await response.json();

  const productionTab = tabs.find(tab =>
    tab.url && tab.url.includes('production.coreflow360-frontend.pages.dev')
  );

  if (!productionTab) {
    console.error('Production page not found');
    process.exit(1);
  }

  const ws = new WebSocket(productionTab.webSocketDebuggerUrl);
  let messageId = 1;
  const pendingRequests = new Map();

  ws.on('open', async () => {
    console.log('Connected to Chrome\n');

    await sendCommand(ws, pendingRequests, 'Runtime.enable');
    await sendCommand(ws, pendingRequests, 'Log.enable');

    console.log('=== CHECKING FOR JAVASCRIPT ERRORS ===\n');

    // Get exceptions thrown
    const exceptionsResult = await sendCommand(ws, pendingRequests, 'Runtime.evaluate', {
      expression: `
        (function() {
          // Check if there are any error messages stored
          const errorDivs = Array.from(document.querySelectorAll('[class*="error"]'));
          const errorText = errorDivs.map(div => div.textContent).join('\\n');

          // Try to access React DevTools error info
          let reactError = null;
          try {
            const root = document.getElementById('root');
            if (root && root._reactRootContainer) {
              reactError = 'React root exists';
            }
          } catch (e) {
            reactError = e.message;
          }

          return {
            hasErrorInDOM: document.body.textContent.includes('Something went wrong'),
            errorElements: errorDivs.length,
            errorText: errorText.substring(0, 500),
            reactError,
            windowErrorEvent: window.__lastError || 'No error captured'
          };
        })()
      `,
      returnByValue: true
    });

    console.log('Error DOM Check:');
    console.log(JSON.stringify(exceptionsResult.result?.result?.value, null, 2));

    // Try to trigger the actual error by calling window.onerror
    console.log('\n=== CHECKING ERROR HANDLERS ===\n');

    const errorHandlerCheck = await sendCommand(ws, pendingRequests, 'Runtime.evaluate', {
      expression: `
        (function() {
          return {
            hasWindowError: typeof window.onerror === 'function',
            hasUnhandledRejection: typeof window.onunhandledrejection === 'function',
            errorListeners: window.addEventListener ? 'addEventListener exists' : 'no addEventListener'
          };
        })()
      `,
      returnByValue: true
    });

    console.log('Error Handlers:');
    console.log(JSON.stringify(errorHandlerCheck.result?.result?.value, null, 2));

    // Check the actual error from error boundary
    console.log('\n=== EXTRACTING ERROR BOUNDARY STATE ===\n');

    const errorBoundaryCheck = await sendCommand(ws, pendingRequests, 'Runtime.evaluate', {
      expression: `
        (function() {
          // Try to find error boundary component state
          const errorAlert = document.querySelector('[role="alert"]');
          if (!errorAlert) return { status: 'No error alert found' };

          const errorDetails = {
            alertText: errorAlert.textContent,
            alertHTML: errorAlert.innerHTML.substring(0, 300),
            parentClasses: errorAlert.parentElement?.className,
            hasDetails: errorAlert.textContent.includes('details')
          };

          // Check if there's a collapsed error details section
          const detailsElements = document.querySelectorAll('details, [class*="detail"]');
          if (detailsElements.length > 0) {
            errorDetails.detailsCount = detailsElements.length;
            errorDetails.detailsText = Array.from(detailsElements).map(el => el.textContent.substring(0, 200));
          }

          return errorDetails;
        })()
      `,
      returnByValue: true
    });

    console.log('Error Boundary State:');
    console.log(JSON.stringify(errorBoundaryCheck.result?.result?.value, null, 2));

    // Reload the page and capture errors as they happen
    console.log('\n=== RELOADING PAGE TO CAPTURE ERRORS ===\n');
    console.log('Listening for errors...\n');

    // Set up listeners for new errors
    let errorsDetected = [];

    ws.on('message', (data) => {
      const message = JSON.parse(data);

      if (message.method === 'Runtime.consoleAPICalled') {
        const { type, args } = message.params;
        if (type === 'error') {
          const errorMsg = args.map(arg => arg.value || arg.description).join(' ');
          console.log(`[Console Error]: ${errorMsg}`);
          errorsDetected.push({ type: 'console', message: errorMsg });
        }
      }

      if (message.method === 'Runtime.exceptionThrown') {
        const { exceptionDetails } = message.params;
        console.log(`[Exception]: ${exceptionDetails.exception?.description || exceptionDetails.text}`);
        errorsDetected.push({
          type: 'exception',
          message: exceptionDetails.exception?.description || exceptionDetails.text,
          stack: exceptionDetails.exception?.stack
        });
      }

      if (message.method === 'Log.entryAdded') {
        const { entry } = message.params;
        if (entry.level === 'error') {
          console.log(`[Log Error]: ${entry.text}`);
          errorsDetected.push({ type: 'log', message: entry.text });
        }
      }
    });

    // Wait a bit for errors to come in
    setTimeout(() => {
      console.log('\n=== ERRORS DETECTED ===\n');
      if (errorsDetected.length > 0) {
        console.log(JSON.stringify(errorsDetected, null, 2));
      } else {
        console.log('No errors detected during page load');
      }

      console.log('\n=== DONE ===\n');
      ws.close();
      process.exit(0);
    }, 3000);

    // Reload the page
    await sendCommand(ws, pendingRequests, 'Page.reload', {
      ignoreCache: false
    });
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
}

getErrors();
