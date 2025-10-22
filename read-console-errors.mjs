#!/usr/bin/env node

import WebSocket from 'ws';

const CDP_URL = 'http://127.0.0.1:9222';

async function readErrors() {
  const response = await fetch(`${CDP_URL}/json/list`);
  const tabs = await response.json();

  const productionTab = tabs.find(tab =>
    tab.url && tab.url.includes('production.coreflow360-frontend.pages.dev')
  );

  if (!productionTab) {
    console.error('Production page not found');
    process.exit(1);
  }

  console.log('Connecting to:', productionTab.url, '\n');

  const ws = new WebSocket(productionTab.webSocketDebuggerUrl);
  let messageId = 1;
  const errors = [];

  ws.on('open', async () => {
    console.log('✅ Connected\n');

    // Enable Runtime domain
    ws.send(JSON.stringify({
      id: messageId++,
      method: 'Runtime.enable'
    }));

    // Enable Log domain
    ws.send(JSON.stringify({
      id: messageId++,
      method: 'Log.enable'
    }));

    // Enable Console domain
    ws.send(JSON.stringify({
      id: messageId++,
      method: 'Console.enable'
    }));

    // Wait a bit for setup
    await new Promise(resolve => setTimeout(resolve, 500));

    // Execute JavaScript to get console errors
    ws.send(JSON.stringify({
      id: messageId++,
      method: 'Runtime.evaluate',
      params: {
        expression: `
          (function() {
            // Get all text from the page that might contain errors
            const pageText = document.body.innerText;

            // Look for error messages
            const hasLoadingFailed = pageText.includes('Application Loading Failed');
            const hasTroubleshooting = pageText.includes('Troubleshooting Steps');

            // Try to find any error details
            const errorElements = document.querySelectorAll('[class*="error"]');
            const errorTexts = Array.from(errorElements).map(el => el.textContent);

            return {
              hasLoadingFailed,
              hasTroubleshooting,
              pageSnippet: pageText.substring(0, 500),
              errorElements: errorTexts.length,
              errorTexts: errorTexts.slice(0, 5)
            };
          })()
        `,
        returnByValue: true
      }
    }));

    console.log('📋 Waiting for console messages...\n');
  });

  ws.on('message', (data) => {
    const message = JSON.parse(data);

    // Capture console API calls (console.log, console.error, etc.)
    if (message.method === 'Runtime.consoleAPICalled') {
      const { type, args, stackTrace } = message.params;

      if (type === 'error') {
        const errorMsg = args.map(arg => {
          if (arg.value) return arg.value;
          if (arg.description) return arg.description;
          if (arg.preview) return JSON.stringify(arg.preview);
          return String(arg);
        }).join(' ');

        console.log('🔴 [Console Error]:', errorMsg);
        errors.push({ type: 'console', message: errorMsg, stack: stackTrace });
      }
    }

    // Capture exceptions
    if (message.method === 'Runtime.exceptionThrown') {
      const { exceptionDetails } = message.params;
      const error = exceptionDetails.exception;

      console.log('💥 [Exception]:', error?.description || exceptionDetails.text);
      if (exceptionDetails.stackTrace) {
        console.log('   Stack:', JSON.stringify(exceptionDetails.stackTrace, null, 2));
      }
      errors.push({
        type: 'exception',
        message: error?.description || exceptionDetails.text,
        stack: exceptionDetails.stackTrace
      });
    }

    // Capture Log entries
    if (message.method === 'Log.entryAdded') {
      const { entry } = message.params;
      if (entry.level === 'error') {
        console.log('📕 [Log Error]:', entry.text);
        errors.push({ type: 'log', message: entry.text });
      }
    }

    // Handle responses to our evaluate command
    if (message.id && message.result?.result?.value) {
      const result = message.result.result.value;
      console.log('\n📄 Page Analysis:');
      console.log(JSON.stringify(result, null, 2));
    }
  });

  // Close after 5 seconds
  setTimeout(() => {
    console.log('\n\n✅ Summary of Errors:\n');
    if (errors.length === 0) {
      console.log('No JavaScript errors detected in console');
    } else {
      errors.forEach((error, i) => {
        console.log(`${i + 1}. [${error.type}] ${error.message}`);
      });
    }

    ws.close();
    process.exit(0);
  }, 5000);
}

readErrors();
