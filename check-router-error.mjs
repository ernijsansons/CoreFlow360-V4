#!/usr/bin/env node

import WebSocket from 'ws';

const CDP_URL = 'http://127.0.0.1:9222';

async function checkRouterError() {
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
    console.log('✅ Connected to Chrome\n');

    await sendCommand(ws, pendingRequests, 'Runtime.enable');

    console.log('🔍 Checking for <details> element with error stack...\n');

    // Check if there's a details element with error stack
    const detailsCheck = await sendCommand(ws, pendingRequests, 'Runtime.evaluate', {
      expression: `
        (function() {
          const detailsElement = document.querySelector('details');
          if (!detailsElement) {
            return { found: false, message: 'No <details> element found - wrong error boundary!' };
          }

          const summary = detailsElement.querySelector('summary');
          const code = detailsElement.querySelector('code');

          return {
            found: true,
            summaryText: summary ? summary.textContent : null,
            codeText: code ? code.textContent : null,
            fullHTML: detailsElement.innerHTML.substring(0, 1000)
          };
        })()
      `,
      returnByValue: true
    });

    console.log('Details Element Check:');
    console.log(JSON.stringify(detailsCheck.result?.result?.value, null, 2));

    // Check which error boundary is rendering
    console.log('\n🎯 Checking which error boundary component is rendering...\n');

    const errorBoundaryCheck = await sendCommand(ws, pendingRequests, 'Runtime.evaluate', {
      expression: `
        (function() {
          const alert = document.querySelector('[role="alert"]');
          if (!alert) return { status: 'No alert found' };

          const alertText = alert.textContent;
          const hasDetails = !!document.querySelector('details');
          const hasTryAgainButton = !!document.querySelector('button:has-text("Try again"), button:has-text("Try Again")');
          const hasGoHomeLink = !!document.querySelector('a[href="/landing"], a:has-text("Go Home")');

          // Check if it's the router error boundary (has details + link to /landing)
          // vs generic error boundary (no details + buttons only)

          return {
            alertText: alertText.substring(0, 200),
            hasDetailsElement: hasDetails,
            hasTryAgainButton,
            hasGoHomeLink,
            likelySource: hasDetails && hasGoHomeLink ? 'TanStack Router Error Boundary (__root.tsx)' : 'Generic Error Boundary (error-boundary.tsx)'
          };
        })()
      `,
      returnByValue: true
    });

    console.log('Error Boundary Source:');
    console.log(JSON.stringify(errorBoundaryCheck.result?.result?.value, null, 2));

    // Get ALL console logs that happened
    console.log('\n📋 Getting all console.error messages...\n');

    const consoleCheck = await sendCommand(ws, pendingRequests, 'Runtime.evaluate', {
      expression: `
        (function() {
          // Access the console history if available
          const errors = [];

          // Try to get stored errors from window
          if (window.__errors) {
            return window.__errors;
          }

          return { message: 'No stored console errors - need to capture on page load' };
        })()
      `,
      returnByValue: true
    });

    console.log('Console Check:');
    console.log(JSON.stringify(consoleCheck.result?.result?.value, null, 2));

    console.log('\n✅ Analysis complete\n');

    ws.close();
    process.exit(0);
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

checkRouterError();
